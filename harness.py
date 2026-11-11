#!/usr/bin/env python3
"""
Watchtower Harness — Human-in-the-Loop Detection Core
=====================================================

Observes. Scores. Explains. Queues. A human decides.

This tool deliberately refuses to act autonomously.
It is not an EDR, not a blocker, and not a phone-home agent.
It produces findings with transparent scores and an append-only,
hash-chained audit log so that every decision is reviewable
and every review is attributable.

Design constraints enforced by construction:
  - No network calls / telemetry
  - No screen capture / keystroke logging
  - No writing-style or "AI-ness" scoring
  - No automatic block / delete / report
  - No contacting anyone
  - Advisory tiers only — never triggers

See docs/ for the full remediation surface this harness supports.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sqlite3
import stat
import sys
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

# ---------------------------------------------------------------------------
# Constants & configuration
# ---------------------------------------------------------------------------

VERSION = "1.0.3"
DEFAULT_DB = Path.home() / ".watchtower" / "harness.db"
DEFAULT_BASELINE = Path.home() / ".watchtower" / "baseline.json"
CONFIG_PATH = Path.home() / ".watchtower" / "config.json"

# Response tiers — advisory only. The harness prints them; it never executes them.
RESPONSE_TIERS = [
    (0.85, "critical", "Review immediately. Consider isolating the path by hand."),
    (0.65, "high",     "Review today. Corroborate before acting."),
    (0.45, "medium",   "Review this week. Low urgency alone."),
    (0.00, "low",      "Record only."),
]

# Weights used by the additive scorer. Public by design.
# An attacker who reads the docs knows these. That is acceptable:
# the weights prioritize human attention; they are not the defense.
WEIGHTS = {
    "input_injection_pattern": 0.55,
    "input_encoded_payload":   0.50,
    "input_control_characters": 0.40,
    "file_added":              0.35,
    "file_modified":           0.40,
    "file_permission_change":  0.45,
    "auth_failure_burst":      0.60,
    "auth_new_source":         0.50,
    "auth_privilege_change":   0.70,
}

# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class Signal:
    """A single typed observation produced by an adapter."""
    kind: str
    path_or_source: str
    detail: str
    weight: float
    raw: Dict[str, Any] = field(default_factory=dict)

@dataclass
class Finding:
    """A scored, human-reviewable unit of work."""
    id: Optional[int]
    score: float
    tier: str
    guidance: str
    signals: List[Signal]
    status: str = "open"          # open | reviewed | dismissed
    created_at: str = ""
    reviewed_at: Optional[str] = None
    reviewer: Optional[str] = None
    rationale: Optional[str] = None
    surface: str = "general"
    tool: Optional[str] = None
    rule_id: Optional[str] = None
    mcp_session_id: Optional[str] = None
    review_session_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["signals"] = [asdict(s) for s in self.signals]
        return d

# ---------------------------------------------------------------------------
# Audit log — append-only, hash-chained
# ---------------------------------------------------------------------------

class AuditLog:
    """
    Append-only, hash-chained audit trail.
    Written *before* scoring so a compromise of the scorer still leaves a trail.
    """

    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn
        self._ensure_schema()

    def _ensure_schema(self) -> None:
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL,
                event TEXT NOT NULL,
                payload TEXT NOT NULL,
                prev_hash TEXT NOT NULL,
                entry_hash TEXT NOT NULL
            )
        """)
        self.conn.commit()

    def _latest_hash(self) -> str:
        row = self.conn.execute(
            "SELECT entry_hash FROM audit_log ORDER BY id DESC LIMIT 1"
        ).fetchone()
        return row[0] if row else "0" * 64

    def append(self, event: str, payload: Dict[str, Any]) -> str:
        ts = datetime.now(timezone.utc).isoformat()
        prev = self._latest_hash()
        body = json.dumps({"ts": ts, "event": event, "payload": payload, "prev": prev},
                          sort_keys=True, separators=(",", ":"))
        entry_hash = hashlib.sha256(body.encode("utf-8")).hexdigest()
        self.conn.execute(
            "INSERT INTO audit_log (ts, event, payload, prev_hash, entry_hash) VALUES (?, ?, ?, ?, ?)",
            (ts, event, json.dumps(payload, sort_keys=True), prev, entry_hash),
        )
        self.conn.commit()
        return entry_hash

    def verify(self) -> Tuple[bool, str]:
        rows = self.conn.execute(
            "SELECT id, ts, event, payload, prev_hash, entry_hash FROM audit_log ORDER BY id"
        ).fetchall()
        if not rows:
            return True, "empty log (ok)"
        expected_prev = "0" * 64
        for row in rows:
            id_, ts, event, payload, prev_hash, entry_hash = row
            if prev_hash != expected_prev:
                return False, f"chain break at id={id_}: expected prev {expected_prev[:12]}… got {prev_hash[:12]}…"
            body = json.dumps(
                {"ts": ts, "event": event, "payload": json.loads(payload), "prev": prev_hash},
                sort_keys=True, separators=(",", ":"),
            )
            computed = hashlib.sha256(body.encode("utf-8")).hexdigest()
            if computed != entry_hash:
                return False, f"hash mismatch at id={id_}"
            expected_prev = entry_hash
        return True, f"ok ({len(rows)} entries)"

# ---------------------------------------------------------------------------
# SQLite store for findings
# ---------------------------------------------------------------------------

class Store:
    def __init__(self, db_path: Path):
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(db_path))
        self.conn.row_factory = sqlite3.Row
        self._ensure_schema()
        self.audit = AuditLog(self.conn)

    def _ensure_schema(self) -> None:
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                score REAL NOT NULL,
                tier TEXT NOT NULL,
                guidance TEXT NOT NULL,
                signals TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'open',
                created_at TEXT NOT NULL,
                reviewed_at TEXT,
                reviewer TEXT,
                rationale TEXT,
                surface TEXT NOT NULL DEFAULT 'general',
                tool TEXT,
                rule_id TEXT,
                mcp_session_id TEXT,
                review_session_id TEXT
            )
        """)
        existing = {row["name"] for row in self.conn.execute("PRAGMA table_info(findings)")}
        migrations = {
            "surface": "ALTER TABLE findings ADD COLUMN surface TEXT NOT NULL DEFAULT 'general'",
            "tool": "ALTER TABLE findings ADD COLUMN tool TEXT",
            "rule_id": "ALTER TABLE findings ADD COLUMN rule_id TEXT",
            "mcp_session_id": "ALTER TABLE findings ADD COLUMN mcp_session_id TEXT",
            "review_session_id": "ALTER TABLE findings ADD COLUMN review_session_id TEXT",
        }
        for column, statement in migrations.items():
            if column not in existing: self.conn.execute(statement)
        self.conn.commit()

    def insert_finding(self, f: Finding) -> int:
        cur = self.conn.execute(
            """INSERT INTO findings
               (score, tier, guidance, signals, status, created_at, reviewed_at, reviewer, rationale,
                surface, tool, rule_id, mcp_session_id, review_session_id)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                f.score, f.tier, f.guidance, json.dumps([asdict(s) for s in f.signals]),
                f.status, f.created_at, f.reviewed_at, f.reviewer, f.rationale,
                f.surface, f.tool, f.rule_id, f.mcp_session_id, f.review_session_id,
            ),
        )
        self.conn.commit()
        return int(cur.lastrowid)

    def list_open(self, limit: int = 20) -> List[Finding]:
        rows = self.conn.execute(
            "SELECT * FROM findings WHERE status = 'open' ORDER BY score DESC, id ASC LIMIT ?",
            (limit,),
        ).fetchall()
        return [self._row_to_finding(r) for r in rows]

    def get(self, fid: int) -> Optional[Finding]:
        row = self.conn.execute("SELECT * FROM findings WHERE id = ?", (fid,)).fetchone()
        return self._row_to_finding(row) if row else None

    def update_review(self, fid: int, status: str, reviewer: str, rationale: str,
                      review_session_id: Optional[str] = None) -> None:
        now = datetime.now(timezone.utc).isoformat()
        self.conn.execute(
            """UPDATE findings
               SET status = ?, reviewed_at = ?, reviewer = ?, rationale = ?, review_session_id = ?
               WHERE id = ?""",
            (status, now, reviewer, rationale, review_session_id, fid),
        )
        self.conn.commit()

    def stats(self) -> Dict[str, int]:
        rows = self.conn.execute(
            "SELECT status, COUNT(*) AS c FROM findings GROUP BY status"
        ).fetchall()
        return {r["status"]: r["c"] for r in rows}

    def purge_closed(self, days: int) -> int:
        cutoff = time.time() - (days * 86400)
        # ISO timestamps are lexicographically ordered; convert cutoff to ISO for safety
        cutoff_iso = datetime.fromtimestamp(cutoff, tz=timezone.utc).isoformat()
        cur = self.conn.execute(
            "DELETE FROM findings WHERE status IN ('reviewed', 'dismissed') AND reviewed_at < ?",
            (cutoff_iso,),
        )
        self.conn.commit()
        return cur.rowcount

    def _row_to_finding(self, row: sqlite3.Row) -> Finding:
        signals = [Signal(**s) for s in json.loads(row["signals"])]
        return Finding(
            id=row["id"],
            score=row["score"],
            tier=row["tier"],
            guidance=row["guidance"],
            signals=signals,
            status=row["status"],
            created_at=row["created_at"],
            reviewed_at=row["reviewed_at"],
            reviewer=row["reviewer"],
            rationale=row["rationale"],
            surface=row["surface"] if "surface" in row.keys() else "general",
            tool=row["tool"] if "tool" in row.keys() else None,
            rule_id=row["rule_id"] if "rule_id" in row.keys() else None,
            mcp_session_id=row["mcp_session_id"] if "mcp_session_id" in row.keys() else None,
            review_session_id=row["review_session_id"] if "review_session_id" in row.keys() else None,
        )

# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------

def score_signals(signals: Sequence[Signal]) -> Tuple[float, str, str]:
    """Additive scorer. Transparent by design."""
    total = 0.0
    for s in signals:
        total += s.weight
    # Cap at 1.0 for readability; real weight sum can exceed it
    score = min(1.0, total)
    for threshold, tier, guidance in RESPONSE_TIERS:
        if score >= threshold:
            return score, tier, guidance
    return score, "low", "Record only."

# ---------------------------------------------------------------------------
# Adapters
# ---------------------------------------------------------------------------

class InputAnomalyAdapter:
    """
    Pattern-based detection of common injection / smuggling idioms.
    Novel phrasing will pass — that is why tool-call allowlists and
    human confirmation gates exist. Detection is one layer, not the layer.
    """

    INJECTION_PATTERNS = [
        re.compile(r"(?i)\bignore\s+(all\s+)?(previous|prior|above)\s+instructions?\b"),
        re.compile(r"(?i)\bdisregard\s+(all\s+)?(previous|prior|above)\b"),
        re.compile(r"(?i)\byou\s+are\s+now\s+(in\s+)?(a\s+)?(new\s+)?mode\b"),
        re.compile(r"(?i)\bsystem\s*:\s*"),
        re.compile(r"(?i)\b(do\s+not|never)\s+(follow|obey|listen)\b"),
        re.compile(r"(?i)\bjailbreak\b"),
        re.compile(r"(?i)\bprompt\s+injection\b"),
    ]

    ENCODED_PATTERNS = [
        re.compile(r"(?i)\b(base64|b64)\s*[:=]\s*[A-Za-z0-9+/=]{20,}"),
        re.compile(r"(?i)\b(hex|hexadecimal)\s*[:=]\s*[0-9a-fA-F]{20,}"),
        re.compile(r"data:[^;]+;base64,[A-Za-z0-9+/=]{20,}"),
        re.compile(r"(?:%[0-9a-fA-F]{2}){8,}"),  # heavy URL-encoding
    ]

    CONTROL_CHAR_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]|[\u200b-\u200f\u202a-\u202e\u2060\ufeff]")

    def scan_text(self, text: str, source: str = "stdin") -> List[Signal]:
        signals: List[Signal] = []
        if not text:
            return signals

        for pat in self.INJECTION_PATTERNS:
            if pat.search(text):
                signals.append(Signal(
                    kind="input_injection_pattern",
                    path_or_source=source,
                    detail=f"Matched injection idiom: {pat.pattern[:60]}…",
                    weight=WEIGHTS["input_injection_pattern"],
                    raw={"pattern": pat.pattern},
                ))
                break  # one is enough for this category

        for pat in self.ENCODED_PATTERNS:
            if pat.search(text):
                signals.append(Signal(
                    kind="input_encoded_payload",
                    path_or_source=source,
                    detail="Possible encoded payload (base64/hex/data-URI/URL-encoding)",
                    weight=WEIGHTS["input_encoded_payload"],
                    raw={},
                ))
                break

        if self.CONTROL_CHAR_RE.search(text):
            signals.append(Signal(
                kind="input_control_characters",
                path_or_source=source,
                detail="Control / bidi / zero-width characters detected",
                weight=WEIGHTS["input_control_characters"],
                raw={},
            ))

        return signals


class FileIntegrityAdapter:
    """
    Baseline + diff. The baseline is the contract; the diff is the alarm.
    Permission-change detection is not optional.
    """

    def __init__(self, baseline_path: Path = DEFAULT_BASELINE):
        self.baseline_path = baseline_path

    def _hash_file(self, path: Path) -> Optional[str]:
        try:
            h = hashlib.sha256()
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(1 << 20), b""):
                    h.update(chunk)
            return h.hexdigest()
        except (OSError, IOError):
            return None

    def _stat_info(self, path: Path) -> Optional[Dict[str, Any]]:
        try:
            st = path.lstat()
            return {
                "mode": st.st_mode,
                "uid": st.st_uid,
                "gid": st.st_gid,
                "size": st.st_size,
                "mtime": int(st.st_mtime),
            }
        except (OSError, IOError):
            return None

    def build_baseline(self, roots: Sequence[Path]) -> Dict[str, Any]:
        baseline: Dict[str, Any] = {"version": 1, "created": datetime.now(timezone.utc).isoformat(), "files": {}}
        for root in roots:
            root = root.resolve()
            if not root.exists():
                continue
            if root.is_file():
                candidates = [root]
            else:
                candidates = [p for p in root.rglob("*") if p.is_file()]
            for p in candidates:
                rel = str(p)
                info = self._stat_info(p)
                digest = self._hash_file(p)
                if info and digest:
                    baseline["files"][rel] = {"sha256": digest, **info}
        self.baseline_path.parent.mkdir(parents=True, exist_ok=True)
        self.baseline_path.write_text(json.dumps(baseline, indent=2, sort_keys=True))
        return baseline

    def load_baseline(self) -> Dict[str, Any]:
        if not self.baseline_path.exists():
            return {"files": {}}
        return json.loads(self.baseline_path.read_text())

    def scan(self, roots: Sequence[Path]) -> List[Signal]:
        baseline = self.load_baseline()
        known = baseline.get("files", {})
        signals: List[Signal] = []
        seen = set()

        for root in roots:
            root = root.resolve()
            if not root.exists():
                continue
            candidates = [root] if root.is_file() else [p for p in root.rglob("*") if p.is_file()]
            for p in candidates:
                rel = str(p)
                seen.add(rel)
                info = self._stat_info(p)
                digest = self._hash_file(p)
                if not info or not digest:
                    continue

                if rel not in known:
                    signals.append(Signal(
                        kind="file_added",
                        path_or_source=rel,
                        detail=f"New file (mode={oct(info['mode'])}, size={info['size']})",
                        weight=WEIGHTS["file_added"],
                        raw={"sha256": digest, **info},
                    ))
                    continue

                prev = known[rel]
                if prev.get("sha256") != digest:
                    signals.append(Signal(
                        kind="file_modified",
                        path_or_source=rel,
                        detail="Content hash changed",
                        weight=WEIGHTS["file_modified"],
                        raw={"old": prev.get("sha256"), "new": digest},
                    ))
                if prev.get("mode") != info["mode"]:
                    signals.append(Signal(
                        kind="file_permission_change",
                        path_or_source=rel,
                        detail=f"Mode changed {oct(prev.get('mode', 0))} → {oct(info['mode'])}",
                        weight=WEIGHTS["file_permission_change"],
                        raw={"old_mode": prev.get("mode"), "new_mode": info["mode"]},
                    ))

        # We do not currently emit "file_removed" to keep the surface small;
        # operators can extend if needed.
        return signals


class AuthLogAdapter:
    """
    sshd-shaped parser. Other log formats need their own adapter.
    AUTH_FAIL_RE family is a template, not a universal parser.
    """

    AUTH_FAIL_RE = re.compile(
        r"(?i)(Failed password|authentication failure|Invalid user|Failed publickey).*?(?:for|user)\s+(\S+).*?(?:from\s+(\S+))?"
    )
    PRIV_RE = re.compile(
        r"(?i)(sudo|pkexec|su\[|setuid).*?(session opened|COMMAND=|user\s+\S+\s+as\s+\S+)"
    )
    NEW_SOURCE_RE = re.compile(
        r"(?i)Accepted\s+(password|publickey).*?for\s+(\S+)\s+from\s+(\S+)"
    )

    def scan_lines(self, lines: Sequence[str], source: str = "auth.log") -> List[Signal]:
        signals: List[Signal] = []
        fail_count = 0
        sources: Dict[str, int] = {}

        for line in lines:
            m = self.AUTH_FAIL_RE.search(line)
            if m:
                fail_count += 1
                src = m.group(3) or "unknown"
                sources[src] = sources.get(src, 0) + 1
                continue

            if self.PRIV_RE.search(line):
                signals.append(Signal(
                    kind="auth_privilege_change",
                    path_or_source=source,
                    detail=line.strip()[:200],
                    weight=WEIGHTS["auth_privilege_change"],
                    raw={"line": line.strip()[:500]},
                ))

            m2 = self.NEW_SOURCE_RE.search(line)
            if m2:
                src = m2.group(3)
                # In a real deployment you would compare against a known-good set.
                # Here we surface every accepted source as a candidate for review.
                signals.append(Signal(
                    kind="auth_new_source",
                    path_or_source=src,
                    detail=f"Accepted {m2.group(1)} for {m2.group(2)} from {src}",
                    weight=WEIGHTS["auth_new_source"],
                    raw={"user": m2.group(2), "method": m2.group(1)},
                ))

        if fail_count >= 5:
            top = sorted(sources.items(), key=lambda x: -x[1])[:3]
            signals.append(Signal(
                kind="auth_failure_burst",
                path_or_source=source,
                detail=f"{fail_count} failures; top sources: {top}",
                weight=WEIGHTS["auth_failure_burst"],
                raw={"count": fail_count, "sources": dict(top)},
            ))

        return signals

# ---------------------------------------------------------------------------
# Config permission check
# ---------------------------------------------------------------------------

def check_config_permissions(path: Path = CONFIG_PATH) -> List[str]:
    """Warn if CONFIG_PATH (or any watched config) is group/world-readable."""
    warnings = []
    if not path.exists():
        return warnings
    try:
        mode = path.stat().st_mode
        if mode & stat.S_IRGRP:
            warnings.append(f"{path} is group-readable (mode {oct(mode & 0o777)})")
        if mode & stat.S_IROTH:
            warnings.append(f"{path} is world-readable (mode {oct(mode & 0o777)})")
        if mode & (stat.S_IWGRP | stat.S_IWOTH):
            warnings.append(f"{path} is group/world-writable (mode {oct(mode & 0o777)})")
    except OSError as e:
        warnings.append(f"cannot stat {path}: {e}")
    return warnings

# ---------------------------------------------------------------------------
# CLI commands
# ---------------------------------------------------------------------------

def cmd_baseline(args: argparse.Namespace, store: Store) -> int:
    roots = [Path(p) for p in (args.paths or ["."])]
    adapter = FileIntegrityAdapter(Path(args.baseline) if args.baseline else DEFAULT_BASELINE)
    baseline = adapter.build_baseline(roots)
    store.audit.append("baseline", {"roots": [str(r) for r in roots], "file_count": len(baseline["files"])})
    print(f"Baseline written → {adapter.baseline_path} ({len(baseline['files'])} files)")
    return 0


def cmd_scan(args: argparse.Namespace, store: Store) -> int:
    all_signals: List[Signal] = []

    # File integrity
    if args.paths or not (args.input or args.auth_log):
        roots = [Path(p) for p in (args.paths or ["."])]
        fi = FileIntegrityAdapter(Path(args.baseline) if args.baseline else DEFAULT_BASELINE)
        all_signals.extend(fi.scan(roots))

    # Input anomaly
    if args.input:
        text = Path(args.input).read_text(errors="replace") if args.input != "-" else sys.stdin.read()
        ia = InputAnomalyAdapter()
        all_signals.extend(ia.scan_text(text, source=args.input))

    # Auth log
    if args.auth_log:
        lines = Path(args.auth_log).read_text(errors="replace").splitlines()
        aa = AuthLogAdapter()
        all_signals.extend(aa.scan_lines(lines, source=args.auth_log))

    # Read-only AI music / DAW MCP log and static source inspection.
    mcp_findings: List[Dict[str, Any]] = []
    if args.mcp_log or args.music_scan_dir:
        from ai_music_mcp_scanner import load_profile, scan_mcp_log, scan_static_tree
        profile = load_profile(args.daw_profile)
        if args.mcp_log:
            mcp_text = Path(args.mcp_log).read_text(errors="replace") if args.mcp_log != "-" else sys.stdin.read()
            mcp_findings.extend(scan_mcp_log(mcp_text, profile))
        if args.music_scan_dir:
            mcp_findings.extend(scan_static_tree(Path(args.music_scan_dir)))
    for item in mcp_findings:
        signal = Signal(
            kind="ai_music_mcp_" + str(item["rule_id"]).lower(),
            path_or_source=str(item.get("tool") or "static-scan"),
            detail=str(item["explanation"]), weight=float(item["score"]),
            raw={"rule_id":item["rule_id"],"evidence":item.get("evidence",{}),
                 "suggested_action":item.get("suggested_action",""),"session_id":item.get("session_id")},
        )
        finding = Finding(
            id=None, score=float(item["score"]), tier=str(item["tier"]),
            guidance=str(item["suggested_action"]), signals=[signal],
            created_at=datetime.now(timezone.utc).isoformat(), surface="ai_music_mcp",
            tool=str(item.get("tool") or "static-scan"), rule_id=str(item["rule_id"]),
            mcp_session_id=item.get("session_id"),
        )
        fid=store.insert_finding(finding)
        store.audit.append("ai_music_mcp_finding",{"finding_id":fid,"surface":"ai_music_mcp",
            "tool":finding.tool,"rule_id":finding.rule_id,"score":finding.score,"session_id":finding.mcp_session_id})
        print(f"Finding #{fid}  score={finding.score:.2f}  tier={finding.tier}  surface=ai_music_mcp  rule={finding.rule_id}")
        print(f"  {finding.guidance}")

    if not all_signals:
        if not mcp_findings:
            print("No signals.")
            store.audit.append("scan", {"signals": 0, "findings": 0})
        return 0

    # Group into a single finding for simplicity; real deployments may split by source
    score, tier, guidance = score_signals(all_signals)
    finding = Finding(
        id=None,
        score=score,
        tier=tier,
        guidance=guidance,
        signals=all_signals,
        created_at=datetime.now(timezone.utc).isoformat(),
    )
    fid = store.insert_finding(finding)
    store.audit.append("scan", {
        "finding_id": fid,
        "score": score,
        "tier": tier,
        "signal_count": len(all_signals),
        "kinds": sorted({s.kind for s in all_signals}),
    })

    print(f"Finding #{fid}  score={score:.2f}  tier={tier}")
    print(f"  {guidance}")
    for s in all_signals:
        print(f"  • [{s.kind}] {s.path_or_source}: {s.detail}")
    return 0


def cmd_review(args: argparse.Namespace, store: Store) -> int:
    if args.id:
        findings = [store.get(args.id)]
        if findings[0] is None:
            print(f"No finding with id={args.id}", file=sys.stderr)
            return 1
    else:
        findings = store.list_open(limit=args.limit)

    if not findings:
        print("No open findings.")
        return 0

    for f in findings:
        assert f is not None
        print("=" * 60)
        print(f"Finding #{f.id}  score={f.score:.2f}  tier={f.tier}  status={f.status}")
        print(f"Created: {f.created_at}")
        print(f"Guidance: {f.guidance}")
        print("Signals:")
        for s in f.signals:
            print(f"  • [{s.kind}] {s.path_or_source}")
            print(f"      {s.detail}")
        print()

        if args.dry_run:
            continue

        # Force rationale — this is what turns a log into an audit trail
        status = input("Status [reviewed/dismissed/skip]: ").strip().lower()
        if status not in ("reviewed", "dismissed"):
            print("Skipped.")
            continue
        reviewer = input("Reviewer name/id: ").strip() or os.environ.get("USER", "unknown")
        rationale = input("Rationale (required): ").strip()
        while not rationale:
            rationale = input("Rationale (required): ").strip()
        review_session_id = None
        if f.surface == "ai_music_mcp":
            captured = f.mcp_session_id or "not recorded in source event"
            review_session_id = input(f"MCP session ID (captured: {captured}; enter to confirm/re-enter): ").strip()
            while not review_session_id:
                review_session_id = input("MCP session ID (required): ").strip()

        store.update_review(f.id, status, reviewer, rationale, review_session_id)
        store.audit.append("review", {"finding_id":f.id,"status":status,"reviewer":reviewer,
            "rationale":rationale,"mcp_session_id":review_session_id})
        print(f"Recorded: {status} by {reviewer}")
    return 0


def cmd_report(args: argparse.Namespace, store: Store) -> int:
    stats = store.stats()
    total = sum(stats.values())
    open_c = stats.get("open", 0)
    reviewed = stats.get("reviewed", 0)
    dismissed = stats.get("dismissed", 0)
    closed = reviewed + dismissed
    fp_rate = (dismissed / closed * 100) if closed else 0.0

    print(f"Watchtower Harness report  (db={args.db})")
    print(f"  Total findings : {total}")
    print(f"  Open           : {open_c}")
    print(f"  Reviewed       : {reviewed}")
    print(f"  Dismissed      : {dismissed}")
    if closed:
        print(f"  Dismissed rate : {fp_rate:.1f}%  (of closed)")
        if fp_rate > 30:
            print("  ⚠  Dismissed rate > 30% — thresholds or adapters may need tuning.")
    mcp_rows = store.conn.execute(
        """SELECT surface, tool, rule_id, score, status, guidance, signals
           FROM findings WHERE surface='ai_music_mcp' ORDER BY id"""
    ).fetchall()
    print("AI Music / DAW MCP")
    print("  surface | tool | rule_id | score | explanation | queued_for_review")
    for row in mcp_rows:
        stored_signals = json.loads(row["signals"])
        explanation = stored_signals[0].get("detail", "") if stored_signals else ""
        print(f"  {row['surface']} | {row['tool'] or ''} | {row['rule_id'] or ''} | "
              f"{row['score']:.2f} | {explanation} | {'true' if row['status']=='open' else 'false'}")
        print(f"    Suggested action: {row['guidance']}")
    if not mcp_rows: print("  No AI music / DAW MCP findings.")
    print()
    print("Response tiers (advisory only):")
    for thresh, tier, guidance in RESPONSE_TIERS:
        print(f"  ≥ {thresh:.2f}  {tier:8s}  {guidance}")
    return 0


def cmd_verify(args: argparse.Namespace, store: Store) -> int:
    ok, msg = store.audit.verify()
    print(f"Audit chain: {'OK' if ok else 'BROKEN'} — {msg}")
    store.audit.append("verify", {"ok": ok, "detail": msg})
    return 0 if ok else 2


def cmd_purge(args: argparse.Namespace, store: Store) -> int:
    n = store.purge_closed(args.days)
    store.audit.append("purge", {"days": args.days, "removed": n})
    print(f"Purged {n} closed findings older than {args.days} days.")
    return 0


def cmd_check_perms(args: argparse.Namespace, store: Store) -> int:
    warnings = check_config_permissions(Path(args.config) if args.config else CONFIG_PATH)
    if not warnings:
        print("Config permissions look good.")
        return 0
    for w in warnings:
        print(f"WARNING: {w}")
    return 1

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="harness",
        description="Watchtower Harness — observe, score, explain, queue. A human decides.",
    )
    p.add_argument("--db", default=str(DEFAULT_DB), help="SQLite database path")
    p.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # baseline
    b = sub.add_parser("baseline", help="Record a known-good file baseline")
    b.add_argument("paths", nargs="*", help="Files or directories to baseline")
    b.add_argument("--baseline", help="Baseline JSON path")

    # scan
    s = sub.add_parser("scan", help="Run adapters and create findings")
    s.add_argument("paths", nargs="*", help="Paths for FileIntegrityAdapter")
    s.add_argument("--input", help="File (or - for stdin) for InputAnomalyAdapter")
    s.add_argument("--auth-log", help="Auth log file for AuthLogAdapter")
    s.add_argument("--mcp-log", help="JSON-RPC MCP tool-call log (or - for stdin)")
    s.add_argument("--music-scan-dir", help="Read-only static scan of a skill / DAW harness directory")
    s.add_argument("--daw-profile", help="Optional daw_profile.json")
    s.add_argument("--baseline", help="Baseline JSON path")

    # review
    r = sub.add_parser("review", help="Review open findings (forces rationale)")
    r.add_argument("--id", type=int, help="Review a specific finding")
    r.add_argument("--limit", type=int, default=20, help="Max open findings to show")
    r.add_argument("--dry-run", action="store_true", help="Show only, do not update")

    # report
    sub.add_parser("report", help="Print summary statistics")

    # verify
    sub.add_parser("verify", help="Verify audit-log hash chain")

    # purge
    pu = sub.add_parser("purge", help="Purge closed findings older than N days")
    pu.add_argument("--days", type=int, default=90, help="Retention window (default 90)")

    # check-perms
    cp = sub.add_parser("check-perms", help="Check config file permissions")
    cp.add_argument("--config", help="Config path to check")

    return p


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    # Startup permission check (non-fatal)
    for w in check_config_permissions():
        print(f"WARNING: {w}", file=sys.stderr)

    store = Store(Path(args.db))

    dispatch = {
        "baseline": cmd_baseline,
        "scan": cmd_scan,
        "review": cmd_review,
        "report": cmd_report,
        "verify": cmd_verify,
        "purge": cmd_purge,
        "check-perms": cmd_check_perms,
    }
    return dispatch[args.cmd](args, store)


if __name__ == "__main__":
    sys.exit(main())
