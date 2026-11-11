# Changelog

## 1.0.3-review

- Add a stdlib-only, read-only AI music / DAW MCP scanner.
- Integrate MCP request and static-source findings into the existing SQLite review queue.
- Add surface, tool, rule, source MCP session, and reviewer-entered MCP session metadata.
- Add the AI Music / DAW MCP report section and DAW profile support.
- Preserve advisory-only behavior: no tool invocation, decoding, blocking, quarantine, package installation, or process control.
- Add focused tests and CI execution for the extension.
- Require every explicit package on a startup pip install line to be exactly pinned unless hash enforcement is enabled.
- Print the source-derived MCP explanation in the report and ignore relative output allowlist entries.

### Review notes

- This branch is based on the actual v1.0.0 main tree. The v1.0.1–v1.0.3 core audit-log replacement snippets discussed previously were paper revisions and are not represented as shipped code here.
- Earlier Fix A scan-pair reconstruction and Fix B audit-head positional repair cannot be applied to the live v1.0.0 audit implementation as written: it has neither the staged scan.started / scan.completed protocol nor an external audit-head file. They remain unapplied rather than being simulated.
- Fix C simultaneous-claim concurrency testing is not applicable to the live v1.0.0 auth adapter, which has no persistent source-claim table or transactional claim operation.
- Static rules C–E are heuristics, not proof of exploitation. Rule C detects mixed-script Unicode only; it does not claim to detect phonetic poisoning.
- Rule B uses metadata and file size only. It never decodes audio.
- The first CI run on this branch is the first automated execution of these changes; no passing result is claimed in advance.
