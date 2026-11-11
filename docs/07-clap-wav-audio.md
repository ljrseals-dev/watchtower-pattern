# CLAP Plugin and WAV / Audio-Call Detection

## Scope

This extension inventories CLAP bundles and inspects WAV headers and supplied timestamped audio-call logs. It is standard-library-only and advisory. It never loads a CLAP plugin, calls a plugin entry point, dlopens a binary, decodes PCM, renders audio, or controls a DAW process.

## Commands

```sh
python harness.py scan --clap-scan-dir /path/to/clap/plugins
python harness.py scan --audio-scan-dir /path/to/audio/files
python harness.py scan --audio-call-log audio-calls.jsonl
```

- `--clap-scan-dir`: find `.clap` bundles, report inventory entries, hash conventional binary files up to 512 MiB, collect a bounded set of printable metadata strings, and flag symlinks, missing conventional binaries, or bundles over 1 GiB.
- `--audio-scan-dir`: inspect WAV files under a directory (or a single WAV file) using at most the first 1 MiB. Only RIFF/RF64 headers and chunk boundaries are read.
- `--audio-call-log`: inspect JSONL records with numeric `timestamp` or `ts`, a tool/method/operation name, and optional `session_id`. It flags 100 or more matching audio/WAV calls within a 10-second window for the same session and tool.

## Rules

| Rule | Meaning |
|---|---|
| CLAP_PLUGIN_INVENTORY | Static inventory entry with bundle path, bounded binary SHA-256 hashes, sizes and printable metadata strings |
| CLAP_BUNDLE_SYMLINK | Bundle contains symlink entries that may redirect resources outside the plugin root |
| CLAP_BUNDLE_NO_BINARY | No conventional binary filename/extension was found; nonstandard bundle layouts may be legitimate |
| CLAP_BUNDLE_SIZE | Bundle exceeds 1 GiB; unusual footprint, not proof of maliciousness |
| CLAP_BINARY_UNHASHED | A binary could not be hashed under the scanner's bounded policy |
| WAV_MALFORMED_OR_EXTREME_HEADER | Malformed chunk bounds, zero block alignment, extreme channel count, or extreme sample rate |
| WAV_EXTREME_DURATION | WAV metadata declares more than six hours of audio |
| AUDIO_CALL_BURST | Repeated audio/WAV operations exceed the configured fixed threshold in supplied logs |

## Important limitations

CLAP does not define a universal static manifest that can safely provide every descriptor field without invoking the plugin entry point. This scanner therefore does not claim authoritative vendor/name/version identification; it reports path, binary hashes, and bounded embedded strings for human comparison. Hashes identify bytes, not reputation. No online vulnerability database or signature verification is performed.

WAV header parsing is not a full RIFF/RF64 validator. RF64's ds64 semantics, every codec-specific chunk, and all decoder edge cases are not implemented. A header indicator is not proof the file crashes a DAW. The audio-call burst rule only works when logs include timestamps and stable session/tool identifiers; missing or untrusted timestamps can defeat it. It does not observe live DAW audio callbacks or prove actual CPU spikes, xruns, memory exhaustion, or a crash.

Use isolated, patched media tooling and vendor-provided signatures/provenance checks for deeper validation. Findings are stored in the review queue under surface `clap_audio`; they never trigger blocking, deletion, quarantine, plugin disabling, or process termination.
