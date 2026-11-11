#!/usr/bin/env python3
"""Read-only CLAP bundle and WAV/audio-call risk indicators; stdlib only."""
from __future__ import annotations
import hashlib, json, os, re, struct, time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

CLAP_SUFFIX = ".clap"
AUDIO_SUFFIXES = {".wav", ".wave"}
MAX_HEADER = 1024 * 1024
MAX_BINARY_HASH = 512 * 1024 * 1024
MAX_EVENTS = 200000

def _tier(score: float) -> str:
    return "critical" if score >= .85 else "high" if score >= .65 else "medium" if score >= .45 else "low"

def _finding(rule: str, score: float, subject: str, explanation: str, action: str, evidence: Dict[str, Any]) -> Dict[str, Any]:
    return {"surface":"clap_audio","tool":subject,"rule_id":rule,"score":score,"tier":_tier(score),
            "explanation":explanation,"suggested_action":action,"queued_for_review":True,
            "session_id":None,"evidence":evidence}

def _sha256(path: Path) -> Optional[str]:
    try:
        size=path.stat().st_size
        if size > MAX_BINARY_HASH: return None
        h=hashlib.sha256()
        with path.open("rb") as f:
            for block in iter(lambda:f.read(1024*1024),b""): h.update(block)
        return h.hexdigest()
    except OSError: return None

def _strings(path: Path, limit: int = MAX_HEADER) -> List[str]:
    try:
        with path.open("rb") as f: data=f.read(limit)
    except OSError: return []
    raw=re.findall(rb"[\x20-\x7e]{6,160}",data)
    return [x.decode("ascii","replace") for x in raw[:5000]]

def _clap_bundles(root: Path) -> Iterable[Path]:
    if root.is_file() and root.suffix.lower()==CLAP_SUFFIX:
        yield root; return
    if not root.exists(): return
    for current, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = [d for d in dirs if not (Path(current)/d).is_symlink()]
        p=Path(current)
        if p.suffix.lower()==CLAP_SUFFIX:
            yield p
            dirs[:] = []

def scan_clap_tree(root: Path) -> List[Dict[str, Any]]:
    """Inventory CLAP bundle metadata and hashes without dlopen/load/execute."""
    findings=[]
    for bundle in _clap_bundles(root):
        try:
            entries=list(bundle.rglob("*")) if bundle.is_dir() else [bundle]
        except OSError: entries=[]
        binaries=[p for p in entries if p.is_file() and (p.suffix.lower() in {".dll",".so",".dylib"} or p.name.lower() in {"clap","plugin"})]
        if bundle.is_file(): binaries=[bundle]
        total=0; symlinks=[]; hashes=[]; strings=[]
        for p in entries:
            try:
                if p.is_symlink(): symlinks.append(str(p.relative_to(bundle))); continue
                if p.is_file():
                    total += p.stat().st_size
                    if p in binaries:
                        digest=_sha256(p)
                        if digest: hashes.append({"file":str(p.relative_to(bundle)),"sha256":digest,"size":p.stat().st_size})
                        strings.extend(_strings(p,MAX_HEADER))
            except OSError: continue
        identifiers=[]
        for s in strings:
            if re.search(r"(?i)(clap|plugin|vendor|version|https?://)",s):
                identifiers.append(s[:160])
        evidence={"bundle":str(bundle),"bundle_size_bytes":total,"binary_count":len(binaries),
                  "binary_hashes":hashes,"symlink_entries":symlinks[:50],"embedded_metadata_strings":list(dict.fromkeys(identifiers))[:50]}
        if not binaries:
            findings.append(_finding("CLAP_BUNDLE_NO_BINARY",.45,str(bundle),
                "A .clap bundle was found but no conventional plugin binary was identified. This may be a nonstandard layout or an incomplete installation.",
                "Inspect the bundle layout and compare it with the vendor's published package; do not load the plugin to identify it.",evidence))
        if symlinks:
            findings.append(_finding("CLAP_BUNDLE_SYMLINK",.65,str(bundle),
                "The CLAP bundle contains symlink entries. Symlinks can redirect bundle resources outside the expected plugin directory.",
                "Resolve each link target manually and verify it remains within an approved plugin root.",evidence))
        if total > 1024*1024*1024:
            findings.append(_finding("CLAP_BUNDLE_SIZE",.50,str(bundle),
                "The CLAP bundle exceeds 1 GiB; this is an unusual footprint and may create scan or load-time resource pressure.",
                "Verify vendor package size and inspect large embedded assets before loading in a production DAW.",evidence))
        if binaries and not hashes:
            findings.append(_finding("CLAP_BINARY_UNHASHED",.45,str(bundle),
                "A CLAP binary was found but could not be hashed within the scanner's bounded-read policy.",
                "Check file size and permissions, then hash with an approved offline integrity tool.",evidence))
    return findings

def inspect_wav_header(path: Path) -> Dict[str, Any]:
    """Parse bounded RIFF/WAVE chunk headers only; never decode PCM."""
    result={"path":str(path),"valid":False}
    try:
        size=path.stat().st_size
        with path.open("rb") as f:
            head=f.read(MAX_HEADER)
    except OSError as exc:
        result["error"]=str(exc); return result
    if len(head)<12 or head[:4] not in (b"RIFF",b"RF64") or head[8:12]!=b"WAVE":
        result["error"]="not a recognized RIFF/RF64 WAVE header"; return result
    riff_size=struct.unpack_from("<I",head,4)[0]
    result.update({"valid":True,"file_size_bytes":size,"declared_riff_size":riff_size,"rf64":head[:4]==b"RF64"})
    pos=12; fmt=None; data_size=None; chunks=[]; malformed=False
    while pos+8<=len(head) and len(chunks)<256:
        tag=head[pos:pos+4]
        chunk_size=struct.unpack_from("<I",head,pos+4)[0]
        chunks.append({"id":tag.decode("ascii","replace"),"declared_size":chunk_size})
        start=pos+8; end=start+chunk_size
        if end>size: malformed=True; break
        if tag==b"fmt " and start+16<=len(head):
            fmt=struct.unpack_from("<HHIIHH",head,start)
        if tag==b"data": data_size=chunk_size
        if end+ (chunk_size&1) <= pos: malformed=True; break
        pos=end+(chunk_size&1)
        if pos>len(head): break
    result["chunks"]=chunks
    if fmt:
        code,channels,rate,byte_rate,align,bits=fmt
        result.update({"format_code":code,"channels":channels,"sample_rate":rate,"byte_rate":byte_rate,"block_align":align,"bits_per_sample":bits})
        if data_size is not None and byte_rate:
            result["estimated_duration_sec"]=data_size/byte_rate
    if data_size is not None: result["data_chunk_bytes"]=data_size
    result["malformed_chunk_bounds"]=malformed
    result["header_truncated_for_scan"]=len(head)==MAX_HEADER
    return result

def scan_wav_file(path: Path) -> List[Dict[str, Any]]:
    m=inspect_wav_header(path); out=[]
    if not m.get("valid"): return out
    bad=[]
    if m.get("malformed_chunk_bounds"): bad.append("chunk declares data beyond file bounds")
    if m.get("channels",0)>64: bad.append("channel count exceeds 64")
    if m.get("sample_rate",0)>768000 or (m.get("sample_rate",0) and m.get("sample_rate",0)<1000): bad.append("sample rate is outside conservative bounds")
    if m.get("block_align",0)==0 and "format_code" in m: bad.append("zero block alignment")
    if bad:
        out.append(_finding("WAV_MALFORMED_OR_EXTREME_HEADER",.80,str(path),
            "WAV header contains malformed chunk bounds or extreme format parameters: "+ "; ".join(bad)+". No audio samples were decoded.",
            "Keep the file quarantined outside the DAW until validated with a patched, sandboxed media parser; do not open it in the host to test it.",m))
    duration=m.get("estimated_duration_sec")
    if duration is not None and duration>6*60*60:
        out.append(_finding("WAV_EXTREME_DURATION",.55,str(path),
            "WAV metadata declares more than six hours of PCM audio, which can create large memory, disk, or processing demand.",
            "Verify the declared duration and enforce import limits in the DAW/audio service.",m))
    return out

def scan_audio_call_log(text: str, burst_window_sec: float=10.0, burst_limit: int=100) -> List[Dict[str, Any]]:
    """Detect repeated WAV/audio operations from timestamped JSONL call records."""
    events=[]
    for line in text.splitlines():
        if not line.strip(): continue
        try: item=json.loads(line)
        except json.JSONDecodeError: continue
        if isinstance(item,dict): events.append(item)
        if len(events)>=MAX_EVENTS: break
    buckets={}
    for e in events:
        name=str(e.get("tool_name") or e.get("method") or e.get("operation") or "")
        args=e.get("arguments") if isinstance(e.get("arguments"),dict) else e.get("params",{})
        serialized=json.dumps(args,ensure_ascii=False,default=str)
        if not (re.search(r"(?i)(wav|audio|render|decode|import|export|process)",name) or re.search(r"(?i)\.wav\b",serialized)): continue
        stamp=e.get("timestamp") or e.get("ts")
        try: t=float(stamp)
        except (TypeError,ValueError): continue
        session=str(e.get("session_id") or e.get("mcp_session_id") or "unknown")
        key=(session,name); buckets.setdefault(key,[]).append(t)
    out=[]
    for (session,name),times in buckets.items():
        times.sort(); left=0; peak=0
        for right,t in enumerate(times):
            while t-times[left]>burst_window_sec: left+=1
            peak=max(peak,right-left+1)
        if peak>=burst_limit:
            out.append(_finding("AUDIO_CALL_BURST",.70,name,
                f"Observed {peak} matching audio/WAV calls within a {burst_window_sec:g}-second window for session {session!r}. This is a workload/abuse indicator, not proof of a crash or denial of service.",
                "Review caller identity, retry behavior, rate limits, queue depth, timeouts, and per-session audio quotas.",{"session_id":session,"call_count":len(times),"peak_calls_in_window":peak,"window_sec":burst_window_sec,"source":"supplied_log"}))
    return out

def scan_audio_tree(root: Path) -> List[Dict[str, Any]]:
    out=[]
    if root.is_file(): candidates=[root]
    elif root.exists(): candidates=(p for p in root.rglob("*") if p.is_file() and not p.is_symlink())
    else: candidates=[]
    for path in candidates:
        if path.suffix.lower() in AUDIO_SUFFIXES: out.extend(scan_wav_file(path))
        elif path.suffix.lower()==CLAP_SUFFIX: out.extend(scan_clap_tree(path))
    return out
