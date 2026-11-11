#!/usr/bin/env python3
"""Read-only CLAP/WAV scanner tests; fixtures are inert bytes, never loaded."""
import json, struct, subprocess, sys, tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
import clap_audio_scanner as scan

def test_clap_inventory_hashes_without_loading():
    with tempfile.TemporaryDirectory() as tmp:
        root=Path(tmp); bundle=root/"Example.clap"; bundle.mkdir()
        binary=bundle/"plugin.so"; binary.write_bytes(b"not executable; CLAP vendor Example version 1.2.3")
        results=scan.scan_clap_tree(root)
        assert any(x["rule_id"]=="CLAP_PLUGIN_INVENTORY" for x in results)
        # Normal inventory is intentionally not a security finding; it is returned by the inventory API.
        assert scan._sha256(binary)

def test_clap_symlink_indicator():
    with tempfile.TemporaryDirectory() as tmp:
        root=Path(tmp); bundle=root/"Bad.clap"; bundle.mkdir()
        (bundle/"plugin.so").write_bytes(b"fixture")
        outside=root/"outside.dat"; outside.write_text("external")
        try: (bundle/"external.dat").symlink_to(outside)
        except (OSError,NotImplementedError): return
        findings=scan.scan_clap_tree(root)
        assert any(x["rule_id"]=="CLAP_BUNDLE_SYMLINK" for x in findings)

def test_wav_header_and_extreme_metadata():
    with tempfile.TemporaryDirectory() as tmp:
        wav=Path(tmp)/"extreme.wav"
        fmt=struct.pack("<HHIIHH",1,2,48000,192000,4,16)
        data=b"\x00"*16
        body=b"WAVE"+b"fmt "+struct.pack("<I",len(fmt))+fmt+b"data"+struct.pack("<I",len(data))+data
        wav.write_bytes(b"RIFF"+struct.pack("<I",len(body))+body)
        meta=scan.inspect_wav_header(wav)
        assert meta["valid"] and meta["channels"]==2 and meta["sample_rate"]==48000
        assert scan.scan_wav_file(wav)==[]

def test_malformed_wav_bounds():
    with tempfile.TemporaryDirectory() as tmp:
        wav=Path(tmp)/"bad.wav"
        wav.write_bytes(b"RIFF"+struct.pack("<I",40)+b"WAVEdata"+struct.pack("<I",0xffffffff))
        assert any(x["rule_id"]=="WAV_MALFORMED_OR_EXTREME_HEADER" for x in scan.scan_wav_file(wav))

def test_repeated_audio_calls():
    records=[{"timestamp":i/10,"session_id":"s1","tool_name":"wav_import","arguments":{"path":"song.wav"}} for i in range(120)]
    findings=scan.scan_audio_call_log("\n".join(json.dumps(x) for x in records))
    assert any(x["rule_id"]=="AUDIO_CALL_BURST" for x in findings)

def test_cli_integration():
    with tempfile.TemporaryDirectory() as tmp:
        root=Path(tmp); wav=root/"bad.wav"
        wav.write_bytes(b"RIFF"+struct.pack("<I",40)+b"WAVEdata"+struct.pack("<I",0xffffffff))
        db=root/"watchtower.db"
        run=subprocess.run([sys.executable,str(ROOT/"harness.py"),"--db",str(db),"scan","--audio-scan-dir",str(wav)],text=True,capture_output=True)
        assert run.returncode==0,run.stderr
        assert "WAV_MALFORMED_OR_EXTREME_HEADER" in run.stdout
        report=subprocess.run([sys.executable,str(ROOT/"harness.py"),"--db",str(db),"report"],text=True,capture_output=True)
        assert "CLAP / WAV" in report.stdout

if __name__=="__main__":
    for name,fn in sorted(globals().copy().items()):
        if name.startswith("test_") and callable(fn): fn(); print(name+" OK")
    print("CLAP/WAV tests passed.")
