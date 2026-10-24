# Calibration

Static-scan results from Skill Bill 1.0 (October 2026), before the LLM review step. These are the targets used to tune false positives. Results on these public projects reflect patterns in their code at that time. They are not judgements about their authors.

| Target | Static level | What drove it | Reviewed verdict |
|---|---|---|---|
| Malicious test fixture (`tests/make_fixture.py`) | CRITICAL | Unicode-smuggled instruction (decoded), base64 payload piped to `sh`, reverse shell, auto-approving hook, cron and `.bashrc` persistence, secrets plus network in one file, npm postinstall | Malicious, as designed |
| `firecrawl/anydoc` | LOW | A child process used to detect musl | Safe |
| `rohitg00/agentmemory` | HIGH | Its installer downloads and runs a pinned engine binary; 12 hooks that only talk to localhost | Disclosed vendor binary; capture-everything hooks are a privacy decision |
| `FarzamHejaziK/claude-linkedin-assistant` | HIGH | Instructions to act on LinkedIn "with no confirmation prompt" | No malicious content; the risk is autonomous account actions |
| `NVIDIA/SkillSpector` | HIGH | Detection rules, YARA signatures and malware fixtures | Benign security tool; the patterns are data |
| Skill Bill itself | HIGH | Its own rule table, the fixture builder in `tests/`, and docs that describe the rules | Benign security tool. Every HIGH is a pattern definition, not behaviour; the scanner makes only read-only GET requests to GitHub/npm |

## False positives removed during tuning

- Invisible math operators (U+2061–U+2064) in MathML test data were reported as hidden text.
- Translated READMEs repeating one `curl | sh` install line 33 times.
- Prose such as "(curl | sh)?" read as a command.
- Redaction deny-lists containing `"id_rsa"` read as credential access.
- `process.env || {}` read as an environment dump.
- "local state" in prose matched Chrome's `Local State` file.
- Benign UX notes ("don't tell the user this optional file is missing") flagged as concealment. Concealment wording now escalates only when the same line contains a sensitive action.
