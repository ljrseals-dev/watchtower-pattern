# AI Music / DAW MCP Detection Extension

## Scope and operating model

The scanner adds a read-only detection surface for recorded MCP JSON-RPC tool calls and static source inspection in AI music / DAW skill directories. It does not connect to MCP servers, execute tools, decode audio, install packages, stop processes, quarantine sessions, or modify scanned files.

A logged tools/call request proves only that the request appears in the supplied log; it does not prove that a server accepted or executed it.

## Rules

| Rule | Default score | Evidence |
|---|---:|---|
| MCP_PATH_TRAVERSAL | 0.95 | Absolute output-like argument outside canonicalized allowlisted directory prefixes |
| AUDIO_DECOMPRESSION_DOS | 0.80 | Small audio file paired with supplied duration or PCM-memory metadata over configured limits |
| CAPTION_MIXED_SCRIPT | 0.60 | A word in retrieval prompt/caption text contains characters from multiple detected Unicode scripts |
| UNPINNED_STARTUP_INSTALL | 0.85 | Startup-like script contains pip install without exact == pin or --require-hashes |
| UNAUTHENTICATED_CONTROL_ROUTE | 0.55 | Static route scan sees a named control endpoint and state-changing code without a nearby auth indicator |
| UNEXPECTED_MCP_TOOL | 0.45 | Tool name is absent from a non-empty expected_tools profile |

Unexpected MCP tools add 0.10 to applicable MCP path, audio, and caption findings. Tool drift is also a separate medium indicator.

## DAW profile

The optional daw_profile.json accepts allowed_output_dirs (absolute prefixes), expected_tools, and max_audio_duration_sec. PHANTOM_OUTPUT_DIR is also accepted as an output-directory allowlist entry. Paths are canonicalized and checked with path-boundary semantics rather than raw string prefixes. POSIX real paths account for symlinks where targets exist; Windows drive paths use Windows normalization.

## Audio metadata limits

The scanner never decodes audio. Rule B requires a file smaller than 5 MiB and supplied metadata: duration greater than the profile limit (default 600 seconds), or estimated/declared decoded PCM size greater than 500 MiB. PCM estimates use duration × sample rate × channels × bytes per sample (default four). Missing metadata means no decompression-bomb conclusion.

## Caption indicators

The implemented indicator is deliberately narrow: mixed-script words in retrieval-related prompt/caption fields. It does not claim to detect Adversarial Phonetic Prompting or semantic steering; those need a defined corpus, algorithm, and measured false-positive rate.

## Static-analysis limitations

Startup and route scans are lexical heuristics. They can miss indirect calls, aliases, dynamic route registration, imported decorators, and authorization enforced by middleware outside the inspected function. Findings require manual code review.

## Review and traceability

MCP findings are stored with surface=ai_music_mcp, tool name, rule ID, and captured session ID when present. Review requires the reviewer to enter an MCP session ID and non-empty rationale. The entered value is stored separately from the source-captured session ID.

## References and attribution

Verify supplied vulnerability references against original advisories before production incident reporting. In particular, do not attribute the so-vits-svc CVE to Phantom Audio. This extension stores rule evidence and does not embed unverified CVE claims into findings.
