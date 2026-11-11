# Adapters

The core adapters (`InputAnomalyAdapter`, `FileIntegrityAdapter`, `AuthLogAdapter`) currently live inside `harness.py` for simplicity and zero-dependency packaging.

Future extractions / additional adapters can land here as separate modules and be imported by the CLI.

Suggested additions:

- `browser_devtools.py` — watch for chrome.debugger / native messaging
- `syslog_generic.py` — broader auth / privilege parsers
- `sbom_diff.py` — dependency / SBOM change detection
