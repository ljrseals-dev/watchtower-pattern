#!/usr/bin/env python3
"""Read-only stdlib indicators for AI music / DAW MCP surfaces."""
from __future__ import annotations
import json, ntpath, os, re, shlex, sys, unicodedata
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

AUDIO_SUFFIXES = {".flac", ".ogg", ".mp3", ".wav"}
PATH_KEY_RE = re.compile(r"^(?:(?:output|export|save|write|render)_?path|audio_path)$", re.I)
RETRIEVAL_TOOL_RE = re.compile(r"(retriev|search|query|caption|musicgen|augment|prompt)", re.I)
STARTUP_NAMES = {"start.sh", "startup.sh", "run.sh", "main.py", "app.py", "server.py"}
CONTROL_PATHS = {"/shutdown", "/restart", "/config", "/stop", "/reset"}
PIN_RE = re.compile(r"(?<![A-Za-z0-9_.-])(?:[A-Za-z0-9_.-]+)==[^ \t]+")
AUTH_RE = re.compile(r"(?:login_required|requires_auth|auth_required|Depends\s*\(\s*.*auth|current_user|request\.user|authorization|authenticate|is_authenticated)", re.I)
ROUTE_RE = re.compile(r"@[\w.]+\.(?:route|get|post|put|patch|delete)\s*\(\s*['\"]([^'\"]+)['\"]", re.I)
ACTION_RE = re.compile(r"(?:shutdown|os\._exit|sys\.exit|\.terminate\s*\(|restart|write_text|write_bytes|open\s*\(|unlink\s*\(|remove\s*\(|update_config|save_config|kill\s*\()", re.I)

def _tier(score: float) -> str:
    return "critical" if score >= .85 else "high" if score >= .65 else "medium" if score >= .45 else "low"

def _finding(rule_id: str, score: float, tool: str, session_id: Optional[str], explanation: str, action: str, evidence: Dict[str, Any]) -> Dict[str, Any]:
    score = min(1.0, max(0.0, float(score)))
    return {"surface":"ai_music_mcp","tool":tool or "static-scan","rule_id":rule_id,"score":score,"tier":_tier(score),"explanation":explanation,"suggested_action":action,"queued_for_review":True,"session_id":session_id,"evidence":evidence}

def _iter_values(value: Any, prefix: str = "") -> Iterable[Tuple[str, Any]]:
    if isinstance(value, dict):
        for key, child in value.items():
            name = str(key); path = f"{prefix}.{name}" if prefix else name
            yield path, child
            yield from _iter_values(child, path)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from _iter_values(child, f"{prefix}[{index}]")

def _is_absolute(value: str) -> bool:
    return os.path.isabs(value) or ntpath.isabs(value)

def _within_allowed(path: str, allowed: Sequence[str]) -> bool:
    if not allowed: return False
    if ntpath.isabs(path):
        candidate = ntpath.normcase(ntpath.normpath(path))
        for root in allowed:
            if ntpath.isabs(root):
                base = ntpath.normcase(ntpath.normpath(root))
                try:
                    if ntpath.commonpath([candidate, base]) == base: return True
                except ValueError: pass
        return False
    candidate = os.path.realpath(os.path.expanduser(path))
    for root in allowed:
        if ntpath.isabs(root): continue
        base = os.path.realpath(os.path.expanduser(root))
        try:
            if os.path.commonpath([candidate, base]) == base: return True
        except ValueError: pass
    return False

def _absolute_allowlist(profile: Dict[str, Any]) -> List[str]:
    values = profile.get("allowed_output_dirs", [])
    values = [str(x) for x in values if isinstance(x, str) and x.strip() and _is_absolute(x)] if isinstance(values, list) else []
    env_dir = os.environ.get("PHANTOM_OUTPUT_DIR")
    if env_dir and _is_absolute(env_dir): values.append(env_dir)
    return values

def _number(arguments: Dict[str, Any], names: Sequence[str]) -> Optional[float]:
    values = {str(k).lower(): v for k, v in arguments.items()}
    for name in names:
        value = values.get(name.lower())
        if isinstance(value, (int,float)) and not isinstance(value,bool) and value >= 0: return float(value)
    return None

def _audio_candidates(arguments: Dict[str, Any]) -> Iterable[str]:
    for _, value in _iter_values(arguments):
        if isinstance(value,str) and Path(value).suffix.lower() in AUDIO_SUFFIXES: yield value

def _scan_tool_call(event: Dict[str, Any], profile: Dict[str, Any]) -> List[Dict[str, Any]]:
    params = event.get("params") if isinstance(event.get("params"),dict) else {}
    tool = str(params.get("name") or event.get("tool_name") or "unknown")
    arguments = params.get("arguments")
    if not isinstance(arguments,dict): arguments = event.get("arguments") if isinstance(event.get("arguments"),dict) else {}
    server = str(event.get("server_id") or params.get("server_id") or event.get("server") or "unknown")
    session = event.get("session_id") or params.get("session_id") or event.get("mcp_session_id")
    session = str(session) if session is not None else None
    expected = profile.get("expected_tools", [])
    unexpected = isinstance(expected,list) and bool(expected) and tool not in expected
    allowed = _absolute_allowlist(profile)
    results: List[Dict[str,Any]] = []

    for key,value in _iter_values(arguments):
        leaf = key.rsplit(".",1)[-1].split("[",1)[0]
        if PATH_KEY_RE.match(leaf) and isinstance(value,str) and _is_absolute(value) and not _within_allowed(value,allowed):
            results.append(_finding("MCP_PATH_TRAVERSAL",.95+(.10 if unexpected else 0),tool,session,
                f"MCP tool '{tool}' requested an absolute output path outside the configured allowlist: {value!r}. This is a path-confinement indicator, not proof the server accepted or wrote the path.",
                "Confirm the agent session origin. Inspect whether the target is a shell startup file, DAW startup script, or project file. Preserve the MCP trace for review.",
                {"server_id":server,"argument":key,"path":value,"allowed_output_dirs":allowed,"request_only":True}))

    max_duration = profile.get("max_audio_duration_sec",600)
    try: max_duration=float(max_duration)
    except (TypeError,ValueError): max_duration=600.0
    for audio_path in _audio_candidates(arguments):
        try: compressed_size=os.path.getsize(audio_path)
        except OSError: continue
        if compressed_size >= 5*1024*1024: continue
        duration=_number(arguments,("duration_sec","duration","decoded_duration_sec"))
        pcm_bytes=_number(arguments,("pcm_bytes","decoded_bytes","memory_bytes"))
        rate=_number(arguments,("sample_rate",)); channels=_number(arguments,("channels","channel_count"))
        sample_bytes=_number(arguments,("bytes_per_sample",))
        if pcm_bytes is None and duration is not None and rate and channels:
            pcm_bytes=duration*rate*channels*(sample_bytes or 4)
        if (duration is not None and duration>max_duration) or (pcm_bytes is not None and pcm_bytes>500*1024*1024):
            results.append(_finding("AUDIO_DECOMPRESSION_DOS",.80+(.10 if unexpected else 0),tool,session,
                "Potential audio decoder resource-exhaustion indicator: a small compressed input is paired with metadata estimating excessive decoded duration or PCM memory. No decoding was attempted.",
                "Review MCP server memory limits and decoder versions. Validate the metadata independently; do not decode untrusted input as part of this scan.",
                {"server_id":server,"audio_path":audio_path,"compressed_size_bytes":compressed_size,"duration_sec":duration,"estimated_pcm_bytes":pcm_bytes,"max_duration_sec":max_duration}))

    if RETRIEVAL_TOOL_RE.search(tool):
        for key,value in _iter_values(arguments):
            if key.rsplit(".",1)[-1].lower() not in {"prompt","caption","query","text"} or not isinstance(value,str): continue
            mixed=[]
            for word in re.findall(r"\w+",value,flags=re.UNICODE):
                scripts=set()
                for char in word:
                    if char.isalpha():
                        name=unicodedata.name(char,"")
                        for script in ("LATIN","CYRILLIC","GREEK","ARMENIAN","HEBREW","ARABIC"):
                            if script in name: scripts.add(script); break
                if len(scripts)>1: mixed.append({"word":word,"scripts":sorted(scripts)})
            if mixed:
                results.append(_finding("CAPTION_MIXED_SCRIPT",.60+(.10 if unexpected else 0),tool,session,
                    "Possible caption/prompt obfuscation: retrieval text contains words mixing Unicode scripts. This heuristic does not infer phonetic or semantic poisoning.",
                    "Compare the retrieved caption with its source and normal caption distribution. Preserve the source record for integrity review.",
                    {"server_id":server,"argument":key,"mixed_script_words":mixed[:20]}))
                break
    if unexpected:
        results.append(_finding("UNEXPECTED_MCP_TOOL",.45,tool,session,
            f"MCP tool '{tool}' is not listed in the configured DAW profile.",
            "Confirm whether the tool was intentionally added and update the profile only after review.",
            {"server_id":server,"expected_tools":expected}))
    return results

def parse_mcp_log(text: str) -> List[Dict[str,Any]]:
    stripped=text.strip()
    if not stripped: return []
    try:
        value=json.loads(stripped)
        if isinstance(value,list): return [x for x in value if isinstance(x,dict)]
        return [value] if isinstance(value,dict) else []
    except json.JSONDecodeError:
        events=[]
        for line in text.splitlines():
            if not line.strip(): continue
            try:
                item=json.loads(line)
                if isinstance(item,dict): events.append(item)
            except json.JSONDecodeError: continue
        return events

def scan_mcp_events(events: Iterable[Dict[str,Any]], profile: Optional[Dict[str,Any]]=None) -> List[Dict[str,Any]]:
    config=profile if isinstance(profile,dict) else {}
    findings=[]
    for event in events:
        if isinstance(event,dict) and (event.get("method")=="tools/call" or (event.get("method") is None and ("tool_name" in event or "params" in event))):
            findings.extend(_scan_tool_call(event,config))
    return findings

def scan_mcp_log(text: str, profile: Optional[Dict[str,Any]]=None) -> List[Dict[str,Any]]:
    return scan_mcp_events(parse_mcp_log(text),profile)

def _pip_install_is_unpinned(line: str) -> bool:
    clean=line.strip()
    if not clean or clean.startswith("#"): return False
    if not re.search(r"(?:\bpip(?:3)?\s+install\b|\bpython(?:\d+(?:\.\d+)?)?\s+-m\s+pip\s+install\b)",clean): return False
    if "--require-hashes" in clean: return False
    try:
        tokens=shlex.split(clean)
    except ValueError:
        return True
    try:
        install_index=tokens.index("install")
    except ValueError:
        return True
    args=tokens[install_index+1:]
    if any(token in {"-r", "--requirement", "-c", "--constraint"} for token in args):
        return True
    value_options={"--index-url","--extra-index-url","--find-links","-f","--trusted-host"}
    packages=[]
    skip_next=False
    for token in args:
        if skip_next:
            skip_next=False
            continue
        if token in value_options:
            skip_next=True
            continue
        if token.startswith("-"):
            continue
        packages.append(token)
    if not packages:
        return True
    # Every requested package must have an exact pin; a pinned package must
    # not mask a second unpinned package on the same command line.
    return any(not PIN_RE.search(token) for token in packages)

def scan_static_tree(root: Path) -> List[Dict[str,Any]]:
    findings=[]
    if not Path(root).exists(): return findings
    candidates=[Path(root)] if Path(root).is_file() else sorted(p for p in Path(root).rglob("*") if p.is_file())
    for path in candidates:
        if path.suffix.lower() not in {".py",".sh",".bash"}: continue
        try: source=path.read_text(encoding="utf-8",errors="replace")
        except OSError: continue
        lines=source.splitlines()
        if path.name.lower() in STARTUP_NAMES or path.suffix.lower() in {".sh",".bash"}:
            for line_no,line in enumerate(lines,1):
                if _pip_install_is_unpinned(line):
                    findings.append(_finding("UNPINNED_STARTUP_INSTALL",.85,"static-startup-scan",None,
                        "Startup script contains pip install without an exact version pin or --require-hashes. This is a potential supply-chain path, not proof of compromise.",
                        "Freeze dependencies, require hash-pinned requirements, and review package index/mirror configuration.",
                        {"file":str(path),"line":line_no,"source_line":line.strip()[:300]}))
        for match in ROUTE_RE.finditer(source):
            route="/"+match.group(1).lstrip("/")
            if route.lower() not in CONTROL_PATHS: continue
            start=source.rfind("\n",0,match.start())+1
            tail=source[match.end():]
            next_decorator=re.search(r"\n\s*@[\w.]+\.",tail)
            region=source[start:match.end()]+(tail[:next_decorator.start()] if next_decorator else tail[:2500])
            if not ACTION_RE.search(region) or AUTH_RE.search(region): continue
            findings.append(_finding("UNAUTHENTICATED_CONTROL_ROUTE",.55,"static-route-scan",None,
                f"Potentially unprotected state-changing control route {route!r}; static inspection found no nearby authentication indicator. Manual review is required.",
                "Verify authentication and authorization on every code path, bind the service to localhost where appropriate, and remove unnecessary control endpoints.",
                {"file":str(path),"line":source.count("\n",0,match.start())+1,"route":route}))
    return findings

def load_profile(path: Optional[str]) -> Dict[str,Any]:
    if not path: return {}
    with open(path,"r",encoding="utf-8") as handle: value=json.load(handle)
    if not isinstance(value,dict): raise ValueError("DAW profile must be a JSON object")
    return value

def main(argv: Optional[Sequence[str]]=None) -> int:
    import argparse
    parser=argparse.ArgumentParser(description="Read-only AI music / DAW MCP indicator scanner")
    parser.add_argument("--mcp-log",default="-",help="JSON-RPC log path, or - for stdin")
    parser.add_argument("--scan-dir",help="Optional skill / harness source directory")
    parser.add_argument("--profile",help="Optional daw_profile.json")
    args=parser.parse_args(argv)
    text=sys.stdin.read() if args.mcp_log=="-" else Path(args.mcp_log).read_text(encoding="utf-8",errors="replace")
    findings=scan_mcp_log(text,load_profile(args.profile))
    if args.scan_dir: findings.extend(scan_static_tree(Path(args.scan_dir)))
    print(json.dumps(findings,indent=2,sort_keys=True))
    return 0

if __name__=="__main__": raise SystemExit(main())
