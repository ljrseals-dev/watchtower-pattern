# Part 5 — Honest gaps (the part conference talks skip)

- **The harness is not an EDR.**  
  It doesn't hook syscalls, it doesn't inspect memory, it doesn't catch kernel-level rootkits. Pair it with a real EDR where the threat model warrants.

- **The auth parser is sshd-shaped.**  
  Other log formats need their own adapter. The `AUTH_FAIL_RE` family is a template, not a universal parser.

- **The input adapter is pattern-based.**  
  It catches known injection idioms. Novel phrasing will pass. That's why the tool-call allowlist and the human confirmation gate exist — detection is one layer, not *the* layer.

- **SQLite is local and single-host.**  
  No correlation across machines. If you need fleet-wide correlation, that's a different tool, and it comes with a different data-protection posture.

- **The scorer is additive and transparent, which means it's also gameable.**  
  An attacker who reads this document knows the weights. That's acceptable because the weights are not the defense — the allowlists, the sandboxes, and the human are. The scorer exists to prioritize human attention, not to replace it.

---

## The conference line

Most security tools are built to *do* something.  
This one is built to *show* you something — and then get out of the way while a human decides.

- The hash-chained log means the showing can't be tampered with.
- The advisory-only tiers mean the deciding stays human.
- The excluded typo scorer means the showing doesn't lie about people it has no business judging.

That's not a smaller tool.  
That's a tool that survives an audit, a lawsuit, and a bad Tuesday.
