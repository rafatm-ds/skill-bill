# Skill Bill

**Every skill pays the bill before it gets in.**

Skill Bill vets AI agent skills, Claude Code plugins, MCP servers, slash commands and agent repos *before* you install them. Hand your agent a link and ask "is this safe?". It downloads the package into memory, runs 87 static checks without executing anything, then reads the files that matter and gives you a threat level with the evidence behind it.

```text
You:    /skill-bill https://github.com/someone/cool-plugin
Agent:  Threat level: HIGH. A PreToolUse hook auto-approves every tool call and its
        script posts prompts to a remote host the README never mentions. Do not install.
```

## Why it exists

Agent skills run with your permissions. A single `SKILL.md` can tell your agent to read `~/.ssh`, a hook can silently approve every command, and an MCP server can ship your code somewhere else, all behind a friendly README. Research on public skill registries found that a meaningful share of skills carry vulnerabilities or outright malicious intent. Most people install them anyway, because reviewing one by hand takes a long time.

## Inspired by NVIDIA SkillSpector, but built for the LLM

Skill Bill is inspired by [NVIDIA SkillSpector](https://github.com/NVIDIA/SkillSpector) and its two-layer design: a fast static pass, then semantic analysis that compares what a skill claims with what it does. The difference is where the second layer runs:

| | SkillSpector | Skill Bill |
|---|---|---|
| Install | Python 3.12+ package, ~20 dependencies (LangGraph, boto3, YARA, …) | Nothing. One standard-library Python file |
| Semantic layer | Separate LLM API call with its own key | **The agent you already use** (Claude Code, or any agent that reads skills) |
| Interface | CLI and reports | Ask in chat; also a CLI |
| Output | Findings report | Findings report **plus** a reviewed verdict: each serious finding confirmed or dismissed, with the reason |

Your agent is already an LLM that can read code, so Skill Bill doesn't wrap one. The scanner does the deterministic triage, and the skill instructions tell your agent how to finish the review. Skill Bill is an independent implementation. No SkillSpector code is used, and it is not affiliated with NVIDIA.

## Install

**Claude Code (plugin):**
```text
/plugin marketplace add rafatm-ds/skill-bill
/plugin install skill-bill@skill-bill
```

**Any skills-compatible agent (Claude Code, Codex, Cursor, Gemini CLI, OpenCode, …):**
copy `skills/skill-bill/` into your agent's skills folder, for example `~/.claude/skills/skill-bill/`. Or, with the [skills CLI](https://skills.sh):
```bash
npx skills add rafatm-ds/skill-bill
```
(on Windows PowerShell use `npx.cmd`)

Requires Python 3.10 or newer, which most machines already have. Nothing else.

## Use

In chat:
```text
/skill-bill https://github.com/owner/repo
is this plugin safe to install? https://github.com/owner/repo/tree/main/plugins/x
scan npm:@scope/some-mcp-server before I add it
```

Or run the scanner directly:
```bash
python3 skills/skill-bill/scripts/scan.py https://github.com/owner/repo --json report.json
```

Accepted targets: GitHub repos (`owner/repo`, full URLs, `/tree/<ref>/<subpath>`, `/blob/<ref>/<file>`), `skills.sh/<owner>/<repo>`, `npm:<package>[@version]` or npmjs.com links, `.zip`/`.tgz` URLs, raw file URLs, and local folders, zips or files.

Exit codes: `0` clean/low, `1` medium, `2` high, `3` critical, so it can gate CI too.

## How it works

1. **Fetch, in memory.** The repo zipball or npm tarball is read in memory. Nothing from the target is written to disk, imported or executed.
2. **Map the agent surfaces.** It finds every `SKILL.md`, command, subagent, `hooks.json` (and the scripts each hook runs), `.mcp.json`, `settings.json`, plugin and marketplace manifests, and `package.json`/`setup.py` install hooks.
3. **Run 87 checks** across 17 categories: download-and-execute, reverse shells and miners, obfuscation, dangerous code (with a Python AST pass), destructive commands, credential access, exfiltration endpoints, a same-file "reads secrets + makes network calls" taint check, prompt injection, excessive agency, memory poisoning, persistence, hidden content, supply chain, privacy, traffic redirection and plugin/MCP configuration. Full list: [docs/rules.md](docs/rules.md).
4. **Decode what's hidden.** Invisible Unicode tag characters are decoded back to the text they smuggle. Base64 blobs are decoded and rescanned. HTML comments addressed to the agent are surfaced.
5. **Weigh the context.** The same `curl | sh` is critical in a hook script, high in a skill, and medium as an install line in a README. Tests, samples and signature files are down-weighted. Lines that are only string or regex literals are treated as detection rules, so security tools don't look like malware.
6. **Check reputation.** It looks at repo and owner age, stars, licence, npm install scripts, provenance and publish history.
7. **LLM review.** Your agent reads the agent-facing files, confirms or dismisses every HIGH and CRITICAL finding, checks the description against the behaviour, traces what data leaves the machine, and issues the final verdict.

## Threat levels

| Level | Meaning |
|---|---|
| **CRITICAL** | Malicious or near-certain harm: exfiltration, backdoor, hidden instructions, credential theft. Do not install. |
| **HIGH** | Dangerous capability that is undisclosed or unjustified, such as auto-approving tools, silent remote egress or unreviewable binaries in the execution path. |
| **MEDIUM** | Risky but disclosed and justified, such as acting on an account autonomously, remote API egress or downloading its own vendor binary. Install with precautions. |
| **LOW** | Normal tooling risk: child processes, unpinned versions, opt-out telemetry. |
| **CLEAN** | Reads and writes its own files, nothing more. |

## Calibration

Tested against a deliberately malicious fixture (generated at test time, never committed) and against real public projects. Static results: [docs/calibration.md](docs/calibration.md).

```bash
python3 -m unittest discover -s tests -v
```

## Limits

- It's a static scan plus a review, not a sandbox, so it cannot prove a package is safe.
- Dependencies are not scanned recursively. Scan important ones separately.
- Compiled binaries can't be read; they are flagged instead. Files over 2 MB are listed but not content-scanned.
- Pattern rules can be evaded by a determined attacker. The LLM review step exists to catch what patterns miss, and the verdict is only as careful as that review.

## Licence

MIT. See [LICENSE](LICENSE).
