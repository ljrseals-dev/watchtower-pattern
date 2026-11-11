#!/usr/bin/env python3
"""Focused stdlib tests for the AI music / DAW MCP extension."""
import json, subprocess, sys, tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
import ai_music_mcp_scanner as scanner

def test_path_confinement():
    with tempfile.TemporaryDirectory() as tmp:
        allowed=Path(tmp)/"exports"; allowed.mkdir()
        outside=Path(tmp)/"outside.wav"
        event={"method":"tools/call","server_id":"phantom","session_id":"sess-1","params":{"name":"render_audio","arguments":{"output_path":str(outside)}}}
        assert any(x["rule_id"]=="MCP_PATH_TRAVERSAL" for x in scanner.scan_mcp_events([event],{"allowed_output_dirs":[str(allowed)]}))
        event["params"]["arguments"]["output_path"]=str(allowed/"mix.wav")
        assert not any(x["rule_id"]=="MCP_PATH_TRAVERSAL" for x in scanner.scan_mcp_events([event],{"allowed_output_dirs":[str(allowed)]}))

def test_audio_metadata_no_decode():
    with tempfile.TemporaryDirectory() as tmp:
        audio=Path(tmp)/"tiny.flac"; audio.write_bytes(b"fLaC"+b"\0"*64)
        event={"method":"tools/call","params":{"name":"analyze_audio","arguments":{"input_path":str(audio),"duration_sec":900,"sample_rate":48000,"channels":2}}}
        assert any(x["rule_id"]=="AUDIO_DECOMPRESSION_DOS" for x in scanner.scan_mcp_events([event]))

def test_caption_mixed_script():
    event={"method":"tools/call","params":{"name":"caption_retrieval","arguments":{"caption":"hello раypal"}}}
    assert any(x["rule_id"]=="CAPTION_MIXED_SCRIPT" for x in scanner.scan_mcp_events([event]))

def test_static_rules():
    with tempfile.TemporaryDirectory() as tmp:
        root=Path(tmp)
        (root/"start.sh").write_text("#!/bin/sh\npip install unpinned-package\n")
        (root/"server.py").write_text("app=object()\n@app.route('/shutdown', methods=['POST'])\ndef shutdown():\n    os._exit(0)\n")
        ids={x["rule_id"] for x in scanner.scan_static_tree(root)}
        assert "UNPINNED_STARTUP_INSTALL" in ids
        assert "UNAUTHENTICATED_CONTROL_ROUTE" in ids

def test_package_pin_detection():
    assert not scanner._pip_install_is_unpinned("python -m pip install package==1.2.3")
    assert scanner._pip_install_is_unpinned("pip install package==1.2.3 other-package")
    assert not scanner._pip_install_is_unpinned("pip install --require-hashes -r requirements.txt")

def test_cli_store_and_review():
    with tempfile.TemporaryDirectory() as tmp:
        root=Path(tmp); db=root/"h.db"; log=root/"mcp.jsonl"
        log.write_text(json.dumps({"method":"tools/call","session_id":"session-77","params":{"name":"render","arguments":{"output_path":"/tmp/escape.wav"}}})+"\n")
        cmd=[sys.executable,str(ROOT/"harness.py"),"--db",str(db),"scan","--mcp-log",str(log)]
        result=subprocess.run(cmd,text=True,capture_output=True)
        assert result.returncode==0,result.stderr
        assert "MCP_PATH_TRAVERSAL" in result.stdout
        report=subprocess.run([sys.executable,str(ROOT/"harness.py"),"--db",str(db),"report"],text=True,capture_output=True)
        assert "AI Music / DAW MCP" in report.stdout
        assert "explanation" in report.stdout
        assert "MCP tool 'render' requested" in report.stdout
        review=subprocess.run([sys.executable,str(ROOT/"harness.py"),"--db",str(db),"review","--id","1"],input="reviewed\nreviewer\nchecked trace\nsession-77\n",text=True,capture_output=True)
        assert review.returncode==0,review.stderr
        import sqlite3
        conn=sqlite3.connect(db); row=conn.execute("SELECT surface,mcp_session_id,review_session_id,rationale FROM findings WHERE id=1").fetchone(); conn.close()
        assert row==("ai_music_mcp","session-77","session-77","checked trace")

if __name__=="__main__":
    for name,fn in sorted(globals().copy().items()):
        if name.startswith("test_") and callable(fn): fn(); print(name+" OK")
    print("AI music / DAW MCP tests passed.")
