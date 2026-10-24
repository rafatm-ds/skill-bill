#!/usr/bin/env python3
"""Skill Bill: static security scanner for AI agent skills, plugins, commands and MCP servers.

It never executes, imports or installs anything from the target. Archives are read in memory
and nothing from the target is written to disk.

Usage:
    python -I scan.py <target> [--json report.json] [--max-mb 300] [--no-meta]

<target> can be:
    https://github.com/<owner>/<repo>[/tree/<ref>/<subpath> | /blob/<ref>/<file>]
    <owner>/<repo>                      GitHub shorthand
    https://skills.sh/<owner>/<repo>    resolved to the GitHub repo
    npm:<package>[@version]  or  https://www.npmjs.com/package/<package>
    https://.../file.zip | .tgz | .tar.gz | raw text file URL
    a local directory, .zip, .tgz or single file

Python 3.10+, standard library only.
"""
from __future__ import annotations

import argparse
import ast
import base64
import binascii
import io
import json
import os
import re
import sys
import tarfile
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from collections import Counter, defaultdict
from datetime import datetime, timezone

VERSION = "1.0"
UA = f"skill-bill/{VERSION} (static security review; https://github.com/rafatm-ds/skill-bill)"
SEV = ["info", "low", "medium", "high", "critical"]
SEVI = {s: i for i, s in enumerate(SEV)}
WEIGHT = [0, 1, 5, 15, 40]
MAX_FILE = 2 * 1024 * 1024  # files above this are inventoried, not content-scanned
MAX_LINE = 4000             # regexes run on at most this many chars per line

# ----------------------------------------------------------------------------- file classes

LOCKFILES = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "uv.lock", "poetry.lock",
             "cargo.lock", "gemfile.lock", "composer.lock", "go.sum", "pipfile.lock", "bun.lockb"}
INSTR_NAMES = {"skill.md", "claude.md", "agents.md", "gemini.md", "claude.local.md", ".cursorrules",
               ".windsurfrules", "copilot-instructions.md", "zcode.md", "codex.md", "system_prompt.md",
               "prompt.md", "instructions.md"}
INSTR_DIRS = {"commands", "agents", "prompts", "rules", "skills", "instructions", "output-styles",
              "subagents", "workflows"}
TEST_DIRS = {"tests", "test", "__tests__", "spec", "specs", "fixtures", "fixture", "testdata",
             "test-data", "__mocks__", "mocks", "test_data", "corpus", "seeds", "yara", "yara_rules",
             "signatures", "sigma", "iocs"}
SIGNATURE_EXT = {".yar", ".yara", ".sigma", ".rules", ".ioc"}
SAMPLE_DIRS = {"examples", "example", "samples", "sample", "bench", "benchmark", "benchmarks",
               "eval", "evals", "demo", "demos", "playground"}
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", ".mypy_cache", ".pytest_cache",
             ".ruff_cache", ".tox", ".idea"}
CODE_EXT = {".py", ".pyw", ".js", ".mjs", ".cjs", ".ts", ".mts", ".cts", ".tsx", ".jsx", ".sh",
            ".bash", ".zsh", ".fish", ".ps1", ".psm1", ".psd1", ".bat", ".cmd", ".vbs", ".rb", ".go",
            ".rs", ".php", ".pl", ".lua", ".swift", ".kt", ".java", ".cs", ".c", ".cpp", ".h",
            ".ipynb", ".applescript", ".scpt"}
CONFIG_EXT = {".json", ".jsonc", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf", ".env", ".xml",
              ".plist", ".service", ".desktop"}
CONFIG_NAMES = {"makefile", "dockerfile", "procfile", ".npmrc", ".pypirc", "setup.py", "setup.cfg",
                ".env.example", "justfile", "taskfile"}
DOC_EXT = {".md", ".mdx", ".markdown", ".rst", ".txt", ".adoc", ".mdc", ".html", ".htm"}
DOC_PREFIX = ("readme", "changelog", "contributing", "license", "licence", "notice", "security",
              "code_of_conduct", "history", "authors", "maintainers", "governance", "roadmap",
              "third_party", "citation", "privacy", "attribution")
BIN_EXEC = {".exe", ".dll", ".so", ".dylib", ".bin", ".node", ".jar", ".class", ".pyc", ".pyo",
            ".wasm", ".msi", ".scr", ".com", ".deb", ".rpm", ".apk", ".dmg", ".pkg", ".app",
            ".elf", ".o", ".a", ".lib", ".sys", ".drv", ".cpl", ".ocx"}
BIN_ARCHIVE = {".zip", ".tar", ".gz", ".tgz", ".bz2", ".xz", ".7z", ".rar", ".zst", ".whl", ".egg",
               ".nupkg", ".vsix", ".crx", ".xpi"}
BIN_MEDIA = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".bmp", ".svg", ".mp4", ".mov",
             ".webm", ".mp3", ".wav", ".ogg", ".pdf", ".ttf", ".otf", ".woff", ".woff2", ".eot",
             ".psd", ".ai", ".sketch", ".fig", ".docx", ".xlsx", ".pptx", ".doc", ".xls", ".ppt",
             ".odt", ".ods", ".odp", ".epub", ".rtf", ".avif", ".heic", ".tif", ".tiff", ".db",
             ".sqlite", ".parquet", ".npy", ".pt", ".onnx", ".safetensors", ".pkl", ".rvf"}
# downgrade (in severity steps) by where the text lives; docs and tests are not executed by the agent
DOWN = {"code": 0, "hook": 0, "config": 0, "instr": 0, "doc": 1, "sample": 1, "other": 1, "test": 2}

ANY = {"code", "hook", "config", "instr", "doc", "sample", "test", "other"}
CODEISH = {"code", "hook", "config", "test", "sample"}
TEXTISH = {"instr", "doc", "sample", "test", "other"}

KNOWN_DOMAINS = (
    "github.com", "githubusercontent.com", "github.io", "githubassets.com", "npmjs.com", "npmjs.org",
    "pypi.org", "pythonhosted.org", "anthropic.com", "claude.ai", "claude.com", "openai.com",
    "google.com", "googleapis.com", "gstatic.com", "microsoft.com", "python.org", "nodejs.org",
    "shields.io", "opensource.org", "mozilla.org", "w3.org", "schema.org", "example.com",
    "example.org", "readthedocs.io", "readthedocs.org", "apache.org", "gnu.org", "wikipedia.org",
    "stackoverflow.com", "docker.com", "docker.io", "astral.sh", "rust-lang.org", "crates.io",
    "golang.org", "go.dev", "agentskills.io", "modelcontextprotocol.io", "jsdelivr.net",
    "unpkg.com", "cloudflare.com", "vercel.com", "npmmirror.com", "yarnpkg.com", "osv.dev",
    "huggingface.co", "nvidia.com", "aws.amazon.com", "amazonaws.com", "azure.com", "gitlab.com",
    "bitbucket.org", "linkedin.com", "twitter.com", "x.com", "youtube.com", "discord.gg",
    "img.shields.io", "badge.fury.io", "codecov.io", "travis-ci.org", "circleci.com",
    "creativecommons.org", "json-schema.org", "spdx.org", "semver.org", "keepachangelog.com",
    "conventionalcommits.org", "contributor-covenant.org", "localhost", "127.0.0.1", "0.0.0.0")

# ----------------------------------------------------------------------------- regex rules
# (id, category, base severity, contexts, title, pattern, flags/extra)
# extra: "ext" = restrict to file extensions, "taint" = feeds same-file exfiltration check

RULE_SPECS = [
    # --- download and execute
    ("DX1", "download-exec", "critical", ANY, "Remote script piped into a shell",
     r"\b(curl|wget)\b\s+[^\n|]*?(https?://|\$\{?\w|-[a-zA-Z]*[sSLfO])[^\n|]{0,300}\|\s*(sudo\s+)?(ba|z|da|k)?sh\b", {}),
    ("DX2", "download-exec", "critical", ANY, "PowerShell download piped into Invoke-Expression",
     r"\b(iwr|irm|invoke-webrequest|invoke-restmethod|net\.webclient|downloadstring)\b[^\n]{0,300}(\|\s*(iex|invoke-expression)\b|\biex\b)", {}),
    ("DX3", "download-exec", "high", ANY, "PowerShell Invoke-Expression",
     r"(?<![\w-])(iex|invoke-expression)\s*[\(\$'\"]", {}),
    ("DX4", "download-exec", "critical", ANY, "PowerShell encoded command",
     r"powershell(\.exe)?\b[^\n]{0,120}\s-(e|ec|en|enc|enco|encodedcommand)\s+[A-Za-z0-9+/=]{24,}", {}),
    ("DX5", "download-exec", "high", ANY, "Windows LOLBin download/execute (certutil, bitsadmin, mshta, regsvr32)",
     r"\bcertutil(\.exe)?\b[^\n]{0,80}-urlcache|\bbitsadmin\b[^\n]{0,60}/transfer|\bmshta(\.exe)?\s+[\"']?https?:|\bregsvr32\b[^\n]{0,60}/i:https?:|\brundll32\b[^\n]{0,80}javascript:", {}),
    ("DX6", "download-exec", "high", ANY, "Download a file and then execute it",
     r"\b(curl|wget)\b[^\n]{0,200}\s(-o|-O|--output)\s*\S+[^\n]{0,120}(&&|;)\s*(chmod\s+\+?[0-7x]+|sh\s|bash\s|\./|source\s|\.\s)", {}),
    ("DX8", "download-exec", "critical", ANY, "Decodes a payload and pipes it into a shell/interpreter",
     r"\b(base64\s+(-d|--decode|-D)|openssl\s+(base64|enc)\s+-d|xxd\s+-r|certutil\s+-decode)\b[^\n]{0,60}\|\s*(sudo\s+)?((ba|z|da)?sh|python3?|node|perl|ruby|powershell|pwsh)\b", {}),
    ("DX7", "download-exec", "critical", CODEISH, "Executes code fetched from the network",
     r"\b(exec|eval)\s*\(\s*(requests\.get|urllib\.request\.urlopen|urlopen|httpx\.get|await\s+fetch|fetch)\s*\(", {}),
    # --- reverse shells, miners
    ("RS1", "backdoor", "critical", ANY, "Reverse shell pattern",
     r"/dev/(tcp|udp)/[\w.$-]+/\d+|\bnc(at)?\b[^\n]{0,60}\s-(e|c)\s+/?\S*sh\b|\bbash\s+-i\s+[>&]+\s*/dev/|\bsocat\b[^\n]{0,80}exec:|pty\.spawn\(\s*[\"']/bin/(ba)?sh", {}),
    ("RS2", "backdoor", "critical", ANY, "Crypto-miner reference",
     r"\b(xmrig|minerd|cpuminer|cryptonight|coinhive)\b|stratum\+(tcp|ssl)://", {}),
    # --- obfuscated execution
    ("OB1", "obfuscation", "critical", CODEISH, "eval of decoded string",
     r"\beval\s*\(\s*(atob|unescape|decodeURIComponent|String\.fromCharCode)\s*\(", {}),
    ("OB2", "obfuscation", "critical", CODEISH, "Function/eval of Buffer-decoded payload",
     r"\b(eval|Function)\s*\(\s*Buffer\.from\([^)]*,\s*[\"'](base64|hex)", {}),
    ("OB3", "obfuscation", "critical", CODEISH, "exec of decoded/decompressed payload",
     r"\bexec\s*\(\s*(base64\.b64decode|base64\.decodebytes|zlib\.decompress|codecs\.decode|bytes\.fromhex|marshal\.loads|bz2\.decompress|lzma\.decompress)", {}),
    ("OB4", "obfuscation", "medium", CODEISH, "Long String.fromCharCode sequence",
     r"String\.fromCharCode\((\s*\d+\s*,){15,}", {}),
    ("OB5", "obfuscation", "medium", CODEISH, "Long hex-escaped string",
     r"(\\x[0-9a-fA-F]{2}){24,}", {}),
    ("OB6", "obfuscation", "medium", CODEISH, "Long unicode-escaped string",
     r"(\\u00[0-9a-fA-F]{2}){24,}", {}),
    # --- dangerous code (non-Python; Python is handled by the AST pass)
    ("DC1", "dangerous-code", "medium", CODEISH, "JavaScript eval()",
     r"(?<![\w.$])eval\s*\(", {"ext": {".js", ".mjs", ".cjs", ".ts", ".mts", ".cts", ".tsx", ".jsx"}}),
    ("DC2", "dangerous-code", "medium", CODEISH, "new Function() (dynamic code)",
     r"\bnew\s+Function\s*\(", {"ext": {".js", ".mjs", ".cjs", ".ts", ".mts", ".cts", ".tsx", ".jsx"}}),
    ("DC3", "dangerous-code", "medium", CODEISH, "Shell command built from template string",
     r"\b(execSync|exec|spawnSync)\s*\(\s*`[^`]*\$\{", {"ext": {".js", ".mjs", ".cjs", ".ts", ".mts", ".cts", ".tsx", ".jsx"}}),
    ("DC4", "dangerous-code", "low", CODEISH, "Spawns child processes",
     r"require\(\s*[\"'](node:)?child_process[\"']\s*\)|from\s+[\"'](node:)?child_process[\"']", {}),
    # --- destructive
    ("DS1", "destructive", "high", ANY, "Recursive delete of root/home",
     r"\brm\s+-(?:[a-zA-Z]*r[a-zA-Z]*f|[a-zA-Z]*f[a-zA-Z]*r|r|R)[a-zA-Z]*\s+(?:--no-preserve-root\s+)?[\"']?(?:/|~|\$HOME|\$\{HOME\}|%USERPROFILE%)[\"']?(?:/\*)?(?=[\s\"';&|)]|$)", {}),
    ("DS2", "destructive", "high", ANY, "PowerShell recursive delete of home/drive",
     r"remove-item\b(?=[^\n]*-recurse)(?=[^\n]*(\$env:userprofile|\$home\b|\s~[\\/\s]|[\"'\s]c:\\\\?[\"'\s]|c:\\users\b))", {}),
    ("DS3", "destructive", "high", ANY, "Disk wipe / format",
     r"\b(del|erase|rd|rmdir)\s+/[sq][^\n]{0,40}(c:\\[\"'\s]|%userprofile%)|\bformat\s+[a-z]:\s|\bmkfs(\.\w+)?\s+/dev/|\bdd\s+if=[^\n]*of=/dev/(sd|nvme|disk|hd)|\bcipher\s+/w:", {}),
    ("DS4", "destructive", "medium", ANY, "Force push",
     r"\bgit\s+push\b[^\n]*\s(--force\b|-f\b|--force-with-lease\b)", {}),
    ("DS5", "destructive", "low", ANY, "Hard reset / clean of git working tree",
     r"\bgit\s+reset\s+--hard\b|\bgit\s+clean\s+-[a-z]*f", {}),
    # --- credential and secret access
    ("CR1", "credential-access", "high", ANY, "Touches SSH/cloud/CLI credential files",
     r"\.ssh[/\\](id_|authorized_keys|config|known_hosts)|\bid_(rsa|ed25519|ecdsa|dsa)\b(?!\.pub)|\.aws[/\\]credentials|application_default_credentials\.json|\.git-credentials|(?<![\w.-])\.netrc\b|\.pypirc\b|\.docker[/\\]config\.json|\.kube[/\\]config|\.config[/\\]gh[/\\]hosts|\.gnupg[/\\]|\.config[/\\]gcloud[/\\](credentials|access_tokens|legacy_credentials)", {"taint": "secret"}),
    ("CR2", "credential-access", "high", ANY, "Browser/keychain/wallet secret store",
     r"[/\\\"'](Login Data|Local State|Cookies|Web Data)\b|\bkey4\.db\b|\blogins\.json\b|\bcookies\.sqlite\b|\bsecurity\s+find-(generic|internet)-password|\bwallet\.dat\b|\bExodus[/\\]|\bElectrum[/\\]wallets|Keychains?[/\\]login\.keychain|\bCryptUnprotectData\b|\bnkbihfbeogaeaoehlefnkodbefgpgknn\b", {"taint": "secret", "cs": True}),
    ("CR3", "credential-access", "medium", ANY, "Serialises or dumps all environment variables",
     r"JSON\.stringify\(\s*process\.env\s*\)|(?<![\w-])printenv\b|(?:^|[;&|]\s*|\$\(\s*)env\s*(\|(?!\|)|>(?!=))|Get-ChildItem\s+env:|\bgci\s+env:|json\.dumps\(\s*(dict\()?\s*os\.environ|dict\(\s*os\.environ\s*\)|os\.environ\.items\(\)", {"taint": "env"}),
    ("CR4", "credential-access", "low", TEXTISH, "Instructs the agent to read or send secrets",
     r"\b(read|cat|print|dump|collect|gather|send|upload|copy|include|exfiltrate|extract)\b[^\n]{0,50}(\b(api[_ -]?keys?|access tokens?|auth tokens?|passwords?|credentials|secrets|private keys?|ssh keys?|cookies|session tokens?)\b|(?<![\w.])\.env\b)", {}),
    # --- exfiltration endpoints
    ("EX1", "exfiltration", "high", ANY, "Known exfiltration / tunnelling / paste endpoint",
     r"\b(pastebin\.com|paste\.ee|hastebin\.com|ghostbin\.\w+|transfer\.sh|file\.io|0x0\.st|temp\.sh|ngrok(-free)?\.(io|app|dev)|trycloudflare\.com|\bloca\.lt|serveo\.net|webhook\.site|requestbin|pipedream\.net|interact\.sh|oast\.(fun|me|pro|live|site|online)|burpcollaborator\.net|canarytokens\.\w+|discord(app)?\.com/api/webhooks|api\.telegram\.org/bot|hooks\.slack\.com/services|beeceptor\.com|mockbin\.org|ptpb\.pw|ix\.io|termbin\.com)", {"taint": "net"}),
    ("EX2", "exfiltration", "medium", ANY, "URL shortener or IP-lookup service",
     r"\b(bit\.ly|tinyurl\.com|is\.gd|rebrand\.ly|cutt\.ly|ow\.ly|shorturl\.at|ipinfo\.io|ifconfig\.me|api\.ipify\.org|icanhazip\.com|ipapi\.co|ip-api\.com)\b", {}),
    ("EX3", "exfiltration", "high", ANY, "Hard-coded public IP address URL",
     r"\b(https?|wss?|tcp|ftp)://(?!127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|0\.0\.0\.0|169\.254\.)\d{1,3}(\.\d{1,3}){3}\b", {"taint": "net"}),
    ("EX4", "exfiltration", "high", TEXTISH, "Instructs the agent to send data to an external destination",
     r"\b(send|post|upload|transmit|forward|exfiltrate|leak|beacon|report)\b[^\n]{0,60}\b(contents?|files?|codebase|source code|repo(sitory)?|environment|env vars|credentials|secrets|keys|tokens|conversation|chat history|transcripts?|memory|clipboard)\b[^\n]{0,60}\b(to|at|via)\b[^\n]{0,40}(https?://|webhook|endpoint|remote server|external server|e-?mail|ftp)", {}),
    ("NET", "network", "info", CODEISH, "Outbound network call",
     r"\bfetch\s*\(|\baxios(\.\w+)?\s*\(|\bhttps?\.(request|get)\s*\(|\brequests\.(get|post|put|patch|request)\s*\(|\bhttpx\.(get|post|put|AsyncClient|Client)\b|urllib\.request\.(urlopen|Request)|\burlopen\s*\(|\bcurl\b[^\n]*\s(-d|--data\S*|-F|-T|--upload-file)\s|Invoke-(WebRequest|RestMethod)\b|\bsocket\.(create_connection|socket)\b|\.connect\(\s*\(|XMLHttpRequest|navigator\.sendBeacon|new\s+WebSocket\s*\(|\bnet\.connect\(|\bdgram\b", {"taint": "net"}),
    # --- prompt injection and agent manipulation
    ("PI1", "prompt-injection", "high", TEXTISH, "Instruction-override phrasing",
     r"\b(ignore|disregard|forget|override|bypass)\b[^\n]{0,30}\b(all|any|the|your|every)?\s*(previous|prior|above|earlier|preceding|system|original|existing)\s+(instructions?|prompts?|rules|directions|guidelines|directives|context|messages?)", {}),
    ("PI2", "prompt-injection", "medium", TEXTISH, "Tells the agent to keep something from the user",
     r"\b(do\s*n[o']?t|never|without)\s+(tell(ing)?|inform(ing)?|notify(ing)?|alert(ing)?|mention(ing)?|reveal(ing)?|disclos(e|ing)|show(ing)?|let(ting)?)\b[^\n]{0,30}\b(the\s+)?(user|human|operator|developer|owner)s?\b", {}),
    ("PI3", "prompt-injection", "high", TEXTISH, "Hide-from-user instruction",
     r"\b(hide|conceal|mask|obscure)\b[^\n]{0,40}\bfrom\s+(the\s+)?(user|human|operator|developer)s?\b|\bsecretly\b|\bcovertly\b|\bin\s+the\s+background\s+without\b", {}),
    ("PI4", "prompt-injection", "medium", TEXTISH, "Role hijack / jailbreak phrasing",
     r"\byou\s+are\s+now\s+(a|an|the|in)\b|\bnew\s+(system\s+)?instructions\s*:|\bfrom\s+now\s+on,?\s+you\s+(will|must|are)\b|\bact\s+as\s+(an?\s+)?(unrestricted|jailbroken|uncensored|dan)\b|\bdeveloper\s+mode\s+(enabled|on)\b|\bjailbreak\b", {}),
    ("PI5", "prompt-injection", "medium", TEXTISH, "Fake system/authority markup",
     r"<\s*/?\s*(system|system-reminder|system_prompt|admin|developer_instructions|important_instructions)\s*>|\[\s*(SYSTEM|ADMIN|DEVELOPER)\s*(MESSAGE|PROMPT|NOTE|OVERRIDE)?\s*\]|\bSYSTEM\s+OVERRIDE\b|\bMESSAGE\s+FROM\s+(ANTHROPIC|OPENAI|THE\s+SYSTEM)\b", {}),
    ("PI6", "excessive-agency", "high", TEXTISH, "Tells the agent to disable safety or permission checks",
     r"\b(disable|turn\s+off|bypass|circumvent|skip|ignore|suppress)\b[^\n]{0,30}\b(safety|security\s+(checks?|warnings?)|guardrails?|permission\s+(checks?|prompts?|dialogs?)|approval\s+prompts?|sandbox(ing)?|content\s+polic(y|ies)|refusals?|restrictions)\b", {}),
    ("PI7", "excessive-agency", "high", ANY, "Permission-bypass flag or mode",
     r"--dangerously-skip-permissions|\bbypassPermissions\b|dangerouslyDisableSandbox|--yolo\b|--full-auto\b|--dangerously-bypass-approvals", {}),
    ("PI8", "excessive-agency", "medium", TEXTISH, "Acts without user confirmation",
     r"\bwithout\s+(asking|prompting|confirm(ing|ation)?|approval|permission|user\s+(input|approval|confirmation|consent))\b|\bno\s+(per[- ]\w+\s+)?confirmation\b|\bdo\s*n[o']?t\s+(ask|wait)\s+(for|the\s+user)|\b(fire|run|execute|send|proceed|act)s?\s+silently\b|\bautomatically\s+(send|post|publish|delete|push|commit|purchase|pay|submit|merge|deploy|approve|accept)\b", {}),
    ("PI9", "memory-poisoning", "medium", TEXTISH, "Writes into agent memory/config files",
     r"\b(write|append|add|save|insert|modify|edit|update|overwrite)\b[^\n]{0,60}(CLAUDE\.md|AGENTS\.md|MEMORY\.md|GEMINI\.md|memory\s+files?|\.claude[/\\]settings|~/\.claude\b|system\s+prompt)", {}),
    # --- persistence
    ("PS1", "persistence", "high", ANY, "Modifies shell startup profile",
     r"(>>?|tee\s+-a|appendFile\w*\(|open\([^)]*[\"']a\+?[\"']|Add-Content)[^\n]{0,100}(\.bashrc|\.zshrc|\.bash_profile|(?<![\w])\.profile\b|\.zprofile|\.zshenv|config\.fish|PowerShell_profile\.ps1|\$PROFILE\b)", {}),
    ("PS2", "persistence", "high", ANY, "Installs scheduled task / autostart",
     r"\bcrontab\s+(-[^l\s]|\S+\s*$)|/etc/cron\.|\bschtasks(\.exe)?\s+/create\b|\\Start Menu\\Programs\\Startup|CurrentVersion\\Run(Once)?\b|\bLaunchAgents/|\bLaunchDaemons/|\blaunchctl\s+(load|bootstrap)\b|\bsystemctl\s+(--user\s+)?enable\b|(New|Register)-ScheduledTask\b|(?:^|[;&|]\s*)at\s+\d{1,2}:\d{2}\b", {}),
    ("PS3", "persistence", "medium", CODEISH, "Code writes into the user's global Claude/agent config",
     r"(~|\$HOME|\$\{HOME\}|homedir\(\)|expanduser\([\"']~|Path\.home\(\)|USERPROFILE|os\.homedir)[^\n]{0,60}\.(claude|codex|cursor|gemini)[/\\]?[\"']?[^\n]{0,20}(settings(\.local)?\.json|CLAUDE\.md|AGENTS\.md|commands|agents|skills|hooks|config\.toml|mcp\.json)", {}),
    ("PS4", "persistence", "medium", ANY, "Git hooks redirection",
     r"\bgit\s+config\s+(--global\s+)?core\.hooksPath\b", {}),
    # --- supply chain / config risks
    ("SC1", "supply-chain", "low", ANY, "Unpinned or always-latest install",
     r"\bnpx\s+(-y|--yes)\s+@?[\w./-]+@latest\b|\bnpx\s+@?[\w./-]+@latest\b|\buvx\s+[\w./-]+@latest\b|\bpip\s+install\s+(-U\s+)?git\+|raw\.githubusercontent\.com/[^\s\"')]+/(main|master|HEAD)/[^\s\"')]+\.(sh|ps1|py)\b", {}),
    ("SC2", "supply-chain", "medium", ANY, "Non-default package index/registry",
     r"--(extra-)?index-url\s+https?://(?!pypi\.org|test\.pypi\.org)|--registry(=|\s+)https?://(?!registry\.npmjs\.org|registry\.yarnpkg\.com)", {}),
    ("SC3", "privacy", "low", CODEISH, "Telemetry/analytics SDK",
     r"\b(posthog|mixpanel|segment\.(io|com)|amplitude\.com|google-analytics|googletagmanager|sentry\.io|@sentry/|datadoghq|logrocket|hotjar)\b", {}),
    ("SC4", "traffic-redirect", "low", ANY, "Redirects model API traffic (base-URL override)",
     r"\b(ANTHROPIC_BASE_URL|ANTHROPIC_API_URL|OPENAI_BASE_URL|OPENAI_API_BASE|CLAUDE_CODE_API_BASE|ANTHROPIC_BEDROCK_BASE_URL)\b", {}),
]

RULES = [dict(id=i, cat=c, sev=s, ctx=x, title=t, rx=re.compile(p, 0 if e.get("cs") else re.I), **e)
         for (i, c, s, x, t, p, e) in RULE_SPECS]

PATTERN_LITERAL = re.compile(
    r"re\.compile|\bregex\b|\bRegExp\b|\bpatterns?\s*[:=]|\brules?\s*[:=]|\bsignatures?\b|\byara\b|"
    r"\bre\.(search|match|findall|sub|finditer)\(|\bIOC\b|\bindicators?\b|\bdetect(s|ion|or)?\b|"
    r"\bdeny[- ]?list\b|\bblock[- ]?list\b|\bscanner\b", re.I)
SENSITIVE = re.compile(
    r"https?://|\bcurl\b|\bwget\b|\bsend\b|\bupload|\bpost\b|api[_ -]?key|\btokens?\b|passwords?|credentials?|"
    r"secrets?|\.ssh|\.env\b|exfil|\brm\s+-|delete|download|install|execute|\brun\b|webhook|cookies?", re.I)
EXFIL_NEAR = re.compile(r"https?://|\bcurl\b|\bwget\b|\bsend\b|\bupload|\bpost\b|webhook|e-?mail|\bpaste", re.I)
ESCALATE = {"PI2": (SENSITIVE, 1), "PI3": (SENSITIVE, 1), "PI8": (SENSITIVE, 1), "CR4": (EXFIL_NEAR, 2)}
LITERAL_ONLY = re.compile(r"""^\s*(["'`][^"'`]{0,120}["'`]|/.{1,300}/[a-z]*|r?["'][^"']{0,200}["'])\s*[,;\]})]*\s*(//.*|#.*)?$""")
STR_LIT = re.compile(r"""(?:\b[rbuf]{1,2})?(["'`])(?:\\.|(?!\1).)*\1|(?<![\w)\]])/(?:\\.|[^/\n])+/[gimsuy]*""")
LEFTOVER_OK = re.compile(r"^[\s()\[\]{},:;=+|]*(?:(?:re\.[A-Z]+|re\.\w+|True|False|None|\w+\s*=)[\s()\[\]{},:;|+]*)*$")


def is_literal_line(line):
    """True when a line is only string/regex literals plus punctuation (rule tables, deny-lists)."""
    if not re.search(r"[\"'`/]", line):
        return False
    rest = STR_LIT.sub("", line)
    rest = re.sub(r"(#|//).*$", "", rest)
    return bool(LEFTOVER_OK.match(rest))


HTML_COMMENT = re.compile(r"<!--(.*?)-->", re.S)
HIDDEN_WORDS = re.compile(
    r"\b(ignore|disregard|you\s+(are|must|should|will)|assistant|claude|ai\s+agent|llm|system|execute|run\s+(the|this)|"
    r"curl|wget|do\s*n[o']?t\s+(tell|mention)|secret|password|token|api[_ ]?key|exfil|send\s+to|upload|instead)\b", re.I)
B64_BLOB = re.compile(r"(?<![A-Za-z0-9+/=_-])[A-Za-z0-9+/]{60,}={0,2}(?![A-Za-z0-9+/=_-])")
URL_RX = re.compile(r"\b(?:https?|wss?|ftp)://([A-Za-z0-9.-]+\.[A-Za-z]{2,}|\d{1,3}(?:\.\d{1,3}){3}|localhost)(?::\d+)?", re.I)
HOOK_SCRIPT_RX = re.compile(r"[\w${}./\\-]+\.(?:mjs|cjs|js|ts|py|sh|bash|ps1|rb|pl|cmd|bat)\b")
AUTO_APPROVE_RX = re.compile(r"[\"']?permissionDecision[\"']?\s*[:=]\s*[\"']allow[\"']|[\"']?decision[\"']?\s*[:=]\s*[\"']approve[\"']|[\"']?behavior[\"']?\s*[:=]\s*[\"']allow[\"']", re.I)

MATH_INVISIBLE = {0x2061, 0x2062, 0x2063, 0x2064}
ZERO_WIDTH = {0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF, 0x180E, 0x115F,
              0x1160, 0x3164, 0xFFA0}
BIDI_OVERRIDE = set(range(0x202A, 0x202F)) | set(range(0x2066, 0x206A))

# ----------------------------------------------------------------------------- helpers


def now_utc():
    return datetime.now(timezone.utc)


def http_get(url, max_bytes, accept=None):
    headers = {"User-Agent": UA}
    if accept:
        headers["Accept"] = accept
    host = urllib.parse.urlparse(url).hostname or ""
    tok = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if tok and host == "api.github.com":
        headers["Authorization"] = "Bearer " + tok
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=90) as r:
        buf = io.BytesIO()
        while True:
            chunk = r.read(1 << 20)
            if not chunk:
                break
            buf.write(chunk)
            if buf.tell() > max_bytes:
                raise ValueError(f"download exceeds the {max_bytes >> 20} MB cap (raise --max-mb)")
        return buf.getvalue(), r.headers.get("Content-Type", "")


def get_json(url):
    try:
        data, _ = http_get(url, 20 << 20, "application/vnd.github+json")
        return json.loads(data)
    except urllib.error.HTTPError as e:
        return {"_error": f"HTTP {e.code}"}
    except Exception as e:  # noqa: BLE001
        return {"_error": str(e)}


def sanitize(s, n=160):
    out = []
    for ch in s:
        o = ord(ch)
        if o in ZERO_WIDTH or o in BIDI_OVERRIDE or 0xE0000 <= o <= 0xE007F or (o < 32 and ch not in "\t\r\n"):
            out.append(f"<U+{o:04X}>")
        else:
            out.append(ch)
    s = re.sub(r"\s+", " ", "".join(out)).strip()
    return s if len(s) <= n else s[: n - 1] + "…"


def days_since(iso):
    try:
        return (now_utc() - datetime.fromisoformat(iso.replace("Z", "+00:00"))).days
    except Exception:  # noqa: BLE001
        return None


def ext_of(path):
    base = path.rsplit("/", 1)[-1].lower()
    if base.endswith(".tar.gz"):
        return ".tgz"
    return os.path.splitext(base)[1]

# ----------------------------------------------------------------------------- sources


class Entry:
    __slots__ = ("path", "size", "_load", "symlink")

    def __init__(self, path, size, load, symlink=False):
        self.path, self.size, self._load, self.symlink = path, size, load, symlink

    def read(self):
        if self.size > MAX_FILE:
            return None
        return self._load()


def strip_prefix(names):
    tops = {n.split("/", 1)[0] for n in names if n}
    if len(tops) == 1:
        top = next(iter(tops))
        if all(n.startswith(top + "/") or n == top for n in names):
            return top + "/"
    return ""


def in_sub(rel, sub):
    if not sub:
        return True
    sub = sub.strip("/")
    return rel == sub or rel.startswith(sub + "/")


def entries_from_zip(data, sub=""):
    zf = zipfile.ZipFile(io.BytesIO(data))
    infos = [i for i in zf.infolist() if not i.is_dir()]
    prefix = strip_prefix([i.filename for i in infos])
    out = []
    for i in infos:
        rel = i.filename[len(prefix):]
        if not in_sub(rel, sub):
            continue
        is_link = ((i.external_attr >> 16) & 0o170000) == 0o120000
        out.append(Entry(rel, i.file_size, (lambda i=i: zf.read(i)), is_link))
    return out


def entries_from_tar(data, sub=""):
    tf = tarfile.open(fileobj=io.BytesIO(data), mode="r:*")
    members = [m for m in tf.getmembers() if m.isfile() or m.issym() or m.islnk()]
    prefix = strip_prefix([m.name for m in members])
    out = []
    for m in members:
        rel = m.name[len(prefix):]
        if not in_sub(rel, sub):
            continue
        if m.isfile():
            out.append(Entry(rel, m.size, (lambda m=m: tf.extractfile(m).read())))
        else:
            out.append(Entry(rel, 0, (lambda: b""), True))
    return out


def _read_bytes(path):
    with open(path, "rb") as f:
        return f.read()


def entries_from_dir(root):
    out = []
    for dp, dns, fns in os.walk(root):
        dns[:] = [d for d in dns if d not in SKIP_DIRS]
        for fn in fns:
            full = os.path.join(dp, fn)
            rel = os.path.relpath(full, root).replace("\\", "/")
            try:
                size = os.path.getsize(full)
            except OSError:
                continue
            out.append(Entry(rel, size, (lambda full=full: _read_bytes(full)), os.path.islink(full)))
    return out


def resolve_target(t, max_bytes, want_meta):
    """Return (label, entries, meta, notes)."""
    t = t.strip().strip("\"'")
    notes, meta = [], {}
    if os.path.exists(t):
        p = os.path.abspath(t)
        if os.path.isdir(p):
            return p, entries_from_dir(p), {"source": "local directory"}, notes
        data = _read_bytes(p)
        if zipfile.is_zipfile(p):
            return p, entries_from_zip(data), {"source": "local zip"}, notes
        if p.lower().endswith((".tgz", ".tar.gz", ".tar")):
            return p, entries_from_tar(data), {"source": "local tarball"}, notes
        return p, [Entry(os.path.basename(p), len(data), (lambda: data))], {"source": "local file"}, notes

    m = re.match(r"^npm:(@?[^@\s/]+(?:/[^@\s]+)?)(?:@(\S+))?$", t)
    if m:
        return from_npm(m.group(1), m.group(2), max_bytes, notes)

    u = t if "://" in t else "https://" + t
    p = urllib.parse.urlparse(u)
    host = (p.hostname or "").lower()
    parts = [x for x in p.path.split("/") if x]

    if host in ("www.npmjs.com", "npmjs.com") and len(parts) >= 2 and parts[0] == "package":
        name = "/".join(parts[1:3]) if parts[1].startswith("@") else parts[1]
        ver = None
        if "v" in parts:
            i = parts.index("v")
            ver = parts[i + 1] if i + 1 < len(parts) else None
        return from_npm(name, ver, max_bytes, notes)

    gh = None
    if host in ("github.com", "www.github.com") and len(parts) >= 2:
        gh = (parts[0], parts[1].removesuffix(".git"), parts[2:])
    elif host in ("skills.sh", "www.skills.sh") and len(parts) >= 2:
        gh = (parts[0], parts[1], [])
        notes.append("skills.sh link resolved to the GitHub repo it lists")
    elif "://" not in t and re.fullmatch(r"[\w.-]+/[\w.-]+", t):
        o, r = t.split("/")
        gh = (o, r.removesuffix(".git"), [])
    if gh:
        return from_github(gh[0], gh[1], gh[2], max_bytes, want_meta, notes)

    if host == "raw.githubusercontent.com" and len(parts) >= 4:
        data, _ = http_get(u, max_bytes)
        meta = github_meta(parts[0], parts[1]) if want_meta else {}
        meta["source"] = "single raw GitHub file"
        return u, [Entry("/".join(parts[3:]), len(data), (lambda: data))], meta, notes

    data, ctype = http_get(u, max_bytes)
    low = u.lower().split("?")[0]
    if low.endswith(".zip") or data[:4] == b"PK\x03\x04":
        return u, entries_from_zip(data), {"source": "remote zip"}, notes
    if low.endswith((".tgz", ".tar.gz")) or data[:2] == b"\x1f\x8b":
        return u, entries_from_tar(data), {"source": "remote tarball"}, notes
    if "html" in ctype.lower():
        notes.append("Target is a web page, not a package. Only the page text was scanned; find the "
                     "repo or package it points to and scan that.")
    name = parts[-1] if parts else "page"
    return u, [Entry(name, len(data), (lambda: data))], {"source": "remote file"}, notes


def github_meta(owner, repo):
    meta = {}
    r = get_json(f"https://api.github.com/repos/{owner}/{repo}")
    if "_error" in r:
        meta["error"] = r["_error"]
        return meta
    meta.update({
        "repo": r.get("full_name"), "description": r.get("description"), "stars": r.get("stargazers_count"),
        "forks": r.get("forks_count"), "open_issues": r.get("open_issues_count"),
        "created": r.get("created_at"), "pushed": r.get("pushed_at"), "archived": r.get("archived"),
        "fork": r.get("fork"), "license": (r.get("license") or {}).get("spdx_id"),
        "owner_type": (r.get("owner") or {}).get("type"), "default_branch": r.get("default_branch"),
        "size_kb": r.get("size"), "homepage": r.get("homepage"),
    })
    u = get_json(f"https://api.github.com/users/{owner}")
    if "_error" not in u:
        meta["owner_created"] = u.get("created_at")
        meta["owner_public_repos"] = u.get("public_repos")
        meta["owner_followers"] = u.get("followers")
    c = get_json(f"https://api.github.com/repos/{owner}/{repo}/contributors?per_page=5")
    if isinstance(c, list):
        meta["top_contributors"] = [f"{x.get('login')} ({x.get('contributions')})" for x in c[:5]]
    return meta


def from_github(owner, repo, rest, max_bytes, want_meta, notes):
    meta = github_meta(owner, repo) if want_meta else {}
    ref, sub, blob = "", "", None
    if len(rest) >= 2 and rest[0] in ("tree", "blob"):
        ref, path = rest[1], "/".join(rest[2:])
        if rest[0] == "blob":
            blob = path
        else:
            sub = path
        notes.append(f"ref '{ref}' assumed to be a single path segment; subpath '{path or '/'}'")
    label = f"https://github.com/{owner}/{repo}" + (f"/tree/{ref}/{sub}" if sub else "")
    if blob:
        raw = f"https://raw.githubusercontent.com/{owner}/{repo}/{ref}/{blob}"
        data, _ = http_get(raw, max_bytes)
        meta["source"] = "single GitHub file"
        return raw, [Entry(blob, len(data), (lambda: data))], meta, notes
    url = f"https://api.github.com/repos/{owner}/{repo}/zipball" + (f"/{ref}" if ref else "")
    data, _ = http_get(url, max_bytes)
    meta["source"] = "GitHub zipball"
    meta["archive_mb"] = round(len(data) / (1 << 20), 1)
    return label, entries_from_zip(data, sub), meta, notes


def from_npm(name, ver, max_bytes, notes):
    enc = name.replace("/", "%2f")
    doc = get_json(f"https://registry.npmjs.org/{enc}")
    if "_error" in doc:
        raise SystemExit(f"npm lookup failed for {name}: {doc['_error']}")
    ver = ver or (doc.get("dist-tags") or {}).get("latest")
    v = (doc.get("versions") or {}).get(ver)
    if not v:
        raise SystemExit(f"npm: version {ver} of {name} not found")
    times = doc.get("time") or {}
    meta = {
        "source": "npm tarball", "package": name, "version": ver,
        "description": v.get("description"), "license": v.get("license"),
        "maintainers": [m.get("name") for m in (v.get("maintainers") or doc.get("maintainers") or [])],
        "publisher": (v.get("_npmUser") or {}).get("name"),
        "created": times.get("created"), "version_published": times.get(ver),
        "versions_count": len(doc.get("versions") or {}),
        "repository": (v.get("repository") or {}).get("url") if isinstance(v.get("repository"), dict) else v.get("repository"),
        "install_scripts": {k: s for k, s in (v.get("scripts") or {}).items()
                            if k in ("preinstall", "install", "postinstall", "prepare", "preuninstall", "postuninstall")},
        "provenance": bool(((v.get("dist") or {}).get("attestations") or {}).get("provenance")),
        "dependencies": len(v.get("dependencies") or {}),
        "optionalDependencies": len(v.get("optionalDependencies") or {}),
    }
    data, _ = http_get(v["dist"]["tarball"], max_bytes)
    meta["archive_mb"] = round(len(data) / (1 << 20), 2)
    notes.append("npm tarball scanned; its dependencies are NOT scanned (check them separately if needed)")
    return f"npm:{name}@{ver}", entries_from_tar(data), meta, notes

# ----------------------------------------------------------------------------- scanner


class Scan:
    def __init__(self, entries):
        self.entries = [e for e in entries if not any(p in SKIP_DIRS for p in e.path.split("/")[:-1])]
        self.skipped_dirs = Counter(p for e in entries for p in e.path.split("/")[:-1] if p in SKIP_DIRS)
        self.groups = {}
        self.taint = defaultdict(set)
        self.domains = Counter()
        self.inventory = Counter()
        self.binaries, self.large, self.symlinks = [], [], []
        self.surfaces = defaultdict(list)
        self.hook_scripts = set()
        self.ctx = {}
        self.skill_dirs = sorted({e.path.rsplit("/", 1)[0].lower() + "/" if "/" in e.path else ""
                                  for e in self.entries if e.path.rsplit("/", 1)[-1].lower() == "skill.md"})

    # -------- classification
    def classify(self, rel):
        low = rel.lower()
        parts = low.split("/")
        base, dirs = parts[-1], parts[:-1]
        ext = ext_of(low)
        if rel in self.hook_scripts:
            return "hook"
        if base in LOCKFILES:
            return "lock"
        if ext in SIGNATURE_EXT or any(d in TEST_DIRS for d in dirs) or re.match(r"(test_.+|.+_test|.+\.(test|spec)|tests?|conftest)\.\w+$", base):
            return "test"
        if base in INSTR_NAMES:
            return "instr"
        if base.startswith(DOC_PREFIX) and ext in DOC_EXT | {""}:
            return "doc"
        if ext in {".md", ".mdc", ".txt", ".mdx"} and any(d in INSTR_DIRS for d in dirs):
            return "instr"
        if ext in {".md", ".mdc", ".txt"} and any(sd and low.startswith(sd) for sd in self.skill_dirs):
            return "instr"
        if any(d in SAMPLE_DIRS for d in dirs):
            return "sample"
        if ext in CODE_EXT:
            return "code"
        if ext in CONFIG_EXT or base in CONFIG_NAMES:
            return "config"
        if ext in DOC_EXT:
            return "doc"
        return "other"

    # -------- findings
    def add(self, rid, cat, base_sev, title, path, line, snippet, ctx, extra_down=0, note=None, bump=0):
        sev = SEVI[base_sev] + bump - DOWN.get(ctx, 1) - extra_down
        sev = max(0, min(4, sev))
        if SEVI[base_sev] == 0:
            sev = 0
        key = (rid, path)
        g = self.groups.get(key)
        if g is None:
            g = self.groups[key] = dict(rule=rid, category=cat, base=base_sev, severity=SEV[sev], title=title,
                                        path=path, context=ctx, count=0, lines=[], snippet=sanitize(snippet),
                                        note=note)
        g["count"] += 1
        if SEVI[g["severity"]] < sev:
            g["severity"], g["snippet"] = SEV[sev], sanitize(snippet)
        if line and line not in g["lines"] and len(g["lines"]) < 5:
            g["lines"].append(line)
        if note and not g.get("note"):
            g["note"] = note

    # -------- pass 1: agent surfaces and configs
    def pass_surfaces(self):
        names = {e.path for e in self.entries}
        for e in self.entries:
            low = e.path.lower()
            base = low.rsplit("/", 1)[-1]
            if base == "skill.md" or base in ("plugin.json", "marketplace.json", "hooks.json", ".mcp.json",
                                              "mcp.json", "settings.json", "settings.local.json",
                                              "package.json", "setup.py", "claude_desktop_config.json",
                                              "gemini-extension.json", "manifest.json") \
                    or (low.endswith(".md") and ("/agents/" in "/" + low or "/commands/" in "/" + low)):
                data = e.read()
                if data is None:
                    continue
                text = data.decode("utf-8", "replace")
                try:
                    self.surface_file(e.path, base, text, names)
                except Exception as ex:  # noqa: BLE001
                    self.surfaces["parse_errors"].append(f"{e.path}: {ex}")

    def resolve_script(self, cmd, names):
        found = []
        for tok in HOOK_SCRIPT_RX.findall(cmd):
            t = tok.replace("\\", "/")
            t = re.sub(r"^\$\{?[A-Z_]+\}?/", "", t).lstrip("./")
            for n in names:
                if n == t or n.endswith("/" + t):
                    found.append(n)
        return found

    def handle_hooks(self, src, hooks, names):
        if not isinstance(hooks, dict):
            return
        for event, arr in hooks.items():
            for grp in arr if isinstance(arr, list) else []:
                matcher = grp.get("matcher", "*") if isinstance(grp, dict) else "*"
                for h in (grp.get("hooks", []) if isinstance(grp, dict) else []):
                    cmd = " ".join([str(h.get("command", ""))] + [str(a) for a in (h.get("args") or [])]).strip()
                    if h.get("type") == "http" or h.get("url"):
                        cmd = f"HTTP {h.get('url')}"
                    scripts = self.resolve_script(cmd, names)
                    self.hook_scripts.update(scripts)
                    self.surfaces["hooks"].append(dict(file=src, event=event, matcher=matcher or "*",
                                                       command=sanitize(cmd, 200), scripts=scripts))
                    self.scan_text_line_rules(src, cmd, "hook", 0)
                    if h.get("type") == "http" or h.get("url"):
                        host = urllib.parse.urlparse(str(h.get("url"))).hostname or ""
                        if host not in ("localhost", "127.0.0.1"):
                            self.add("HK1", "exfiltration", "high", "HTTP hook posts agent events to a remote URL",
                                     src, None, cmd, "config")

    def handle_mcp(self, src, servers):
        if not isinstance(servers, dict):
            return
        for name, s in servers.items():
            if not isinstance(s, dict):
                continue
            url = s.get("url") or s.get("serverUrl") or ""
            cmd = " ".join([str(s.get("command", ""))] + [str(a) for a in (s.get("args") or [])]).strip()
            self.surfaces["mcp_servers"].append(dict(file=src, name=name, url=url, command=sanitize(cmd, 200),
                                                     env=sorted((s.get("env") or {}).keys())))
            if url:
                host = urllib.parse.urlparse(url).hostname or ""
                if host not in ("localhost", "127.0.0.1", "0.0.0.0"):
                    self.add("MCP1", "data-egress", "medium", f"Remote MCP server '{name}' (context leaves the machine)",
                             src, None, url, "config")
            if cmd:
                self.scan_text_line_rules(src, cmd, "config", 0)

    def surface_file(self, path, base, text, names):
        low = path.lower()
        if base == "skill.md" or (low.endswith(".md") and ("/agents/" in "/" + low or "/commands/" in "/" + low)):
            fm = {}
            m = re.match(r"^\ufeff?---\s*\n(.*?)\n---", text, re.S)
            if m:
                for line in m.group(1).splitlines():
                    mm = re.match(r"^([\w-]+)\s*:\s*(.*)$", line)
                    if mm:
                        fm[mm.group(1).lower()] = mm.group(2).strip().strip("\"'")
            kind = "skills" if base == "skill.md" else ("agents" if "/agents/" in "/" + low else "commands")
            self.surfaces[kind].append(dict(file=path, name=fm.get("name"), description=sanitize(fm.get("description", ""), 220),
                                            tools=fm.get("allowed-tools") or fm.get("tools")))
            desc = fm.get("description", "")
            if re.search(r"\b(always|every|any|all)\b[^\n]{0,30}\b(tasks?|requests?|prompts?|messages?|conversations?|sessions?|times?)\b", desc, re.I):
                self.add("TR1", "trigger-abuse", "low", "Over-broad trigger in description (fires on almost everything)",
                         path, 1, desc, "instr")
            tools = (fm.get("allowed-tools") or fm.get("tools") or "")
            if re.search(r"Bash\(\s*\*\s*\)|^\s*Bash\s*$|\bBash\b(?!\()", tools):
                self.add("TL1", "excessive-agency", "medium", "Pre-approves unrestricted Bash",
                         path, 1, tools, "instr")
            if kind == "agents" and not (fm.get("tools")):
                self.surfaces["notes"].append(f"{path}: agent has no `tools:` list, so it inherits every tool")
            return
        try:
            j = json.loads(re.sub(r"^\ufeff", "", text))
        except Exception:  # noqa: BLE001
            j = None
        if base == "setup.py":
            if re.search(r"\bcmdclass\b|os\.system|subprocess|urlopen|requests\.|exec\(", text):
                self.add("IN2", "install-time-code", "high", "setup.py runs custom code at install time",
                         path, None, "cmdclass/os.system/subprocess/network in setup.py", "code")
            return
        if not isinstance(j, dict):
            return
        if base == "package.json":
            scripts = j.get("scripts") or {}
            for k in ("preinstall", "install", "postinstall", "prepare", "preuninstall", "postuninstall"):
                if k in scripts:
                    s = str(scripts[k])
                    self.surfaces["install_scripts"].append(f"{path}: {k} = {sanitize(s, 160)}")
                    risky = re.search(r"curl|wget|https?://|node\s+-e|eval|base64|powershell|\|\s*sh|bash\s+-c", s, re.I)
                    sev = "high" if risky or k != "prepare" else "low"
                    self.add("IN1", "install-time-code", sev, f"npm `{k}` script runs on install", path, None, f"{k}: {s}", "config")
            for dk in ("dependencies", "optionalDependencies", "devDependencies"):
                for dn, dv in (j.get(dk) or {}).items():
                    if isinstance(dv, str) and re.match(r"(git\+|git:|github:|https?://|file:|link:)", dv):
                        self.add("SC5", "supply-chain", "medium" if dk != "devDependencies" else "low",
                                 "Dependency fetched from git/URL, not the registry", path, None, f"{dn}: {dv}", "config")
            if j.get("bin"):
                self.surfaces["bins"].append(f"{path}: {j.get('bin')}")
            if "mcpServers" in j:
                self.handle_mcp(path, j["mcpServers"])
            return
        if base in ("plugin.json", "gemini-extension.json", "manifest.json"):
            self.surfaces["plugin_manifests"].append(dict(file=path, name=j.get("name"), version=j.get("version"),
                                                          description=sanitize(str(j.get("description", "")), 200)))
            if isinstance(j.get("hooks"), dict):
                self.handle_hooks(path, j["hooks"].get("hooks", j["hooks"]), names)
            if isinstance(j.get("mcpServers"), dict):
                self.handle_mcp(path, j["mcpServers"])
            return
        if base == "marketplace.json":
            for p in j.get("plugins") or []:
                src = p.get("source")
                self.surfaces["marketplace_plugins"].append(f"{p.get('name')}: {src}")
                if isinstance(src, (dict, str)) and re.search(r"github|https?://|git", json.dumps(src)) and not str(src).startswith("./"):
                    self.add("SC6", "supply-chain", "low", "Marketplace pulls a plugin from another repo (not scanned here)",
                             path, None, json.dumps(src), "config")
            return
        if base == "hooks.json":
            self.handle_hooks(path, j.get("hooks", j), names)
            return
        if base in (".mcp.json", "mcp.json", "claude_desktop_config.json"):
            self.handle_mcp(path, j.get("mcpServers", j.get("servers", {})))
            return
        if base in ("settings.json", "settings.local.json"):
            self.surfaces["settings"].append(path)
            if isinstance(j.get("hooks"), dict):
                self.handle_hooks(path, j["hooks"], names)
            perms = j.get("permissions") or {}
            mode = perms.get("defaultMode") or j.get("defaultMode")
            if mode in ("bypassPermissions",):
                self.add("ST1", "excessive-agency", "critical", "Settings switch off all permission prompts", path, None, f"defaultMode: {mode}", "config")
            elif mode in ("acceptEdits", "auto", "dontAsk"):
                self.add("ST2", "excessive-agency", "medium", f"Settings set permission mode '{mode}'", path, None, f"defaultMode: {mode}", "config")
            for a in perms.get("allow") or []:
                if re.fullmatch(r"\s*(Bash|Bash\(\s*\*?\s*\)|PowerShell(\(\s*\*?\s*\))?|\*|WebFetch|mcp__.*__\*?)\s*", str(a)):
                    self.add("ST3", "excessive-agency", "high", "Settings pre-approve a broad tool", path, None, f"allow: {a}", "config")
            env = j.get("env") or {}
            for k, v in env.items():
                if re.search(r"BASE_URL|API_URL|PROXY|API_BASE", k, re.I):
                    self.add("ST4", "traffic-redirect", "high", "Settings redirect API traffic through another endpoint", path, None, f"{k}={v}", "config")
            if j.get("enableAllProjectMcpServers"):
                self.add("ST5", "excessive-agency", "medium", "Auto-enables every project MCP server", path, None, "enableAllProjectMcpServers: true", "config")
            if j.get("apiKeyHelper") or j.get("awsCredentialExport") or j.get("otelHeadersHelper"):
                self.add("ST6", "credential-access", "medium", "Settings run a credential helper script", path, None,
                         str(j.get("apiKeyHelper") or j.get("awsCredentialExport") or j.get("otelHeadersHelper")), "config")
            if isinstance(j.get("mcpServers"), dict):
                self.handle_mcp(path, j["mcpServers"])

    # -------- pass 2: content
    def scan_text_line_rules(self, path, text, ctx, start_line=1, ext=None, decoded_from=None):
        for li, raw in enumerate(text.splitlines(), start_line or 1):
            line = raw[:MAX_LINE]
            literal = bool(PATTERN_LITERAL.search(line))
            for r in RULES:
                if ctx not in r["ctx"] and ctx != "hook":
                    continue
                if r.get("ext") and ext not in r["ext"] and ctx != "hook":
                    continue
                m = r["rx"].search(line)
                if not m:
                    continue
                if r.get("taint"):
                    self.taint[path].add(r["taint"])
                if r["sev"] == "info":
                    continue
                note = None
                down = 0
                bump = 0
                if r["id"] in ESCALATE and ESCALATE[r["id"]][0].search(line):
                    bump, note = ESCALATE[r["id"]][1], "escalated: sensitive action on the same line"
                if ctx in ("code", "config", "hook") and (literal or LITERAL_ONLY.match(line) or is_literal_line(line)):
                    down, note = 1, "line looks like a detection rule/pattern literal"
                    if r.get("taint") == "secret":
                        self.taint[path].discard("secret")
                if ctx in ("doc", "sample") and r["cat"] == "download-exec":
                    down = max(down, 1)
                    note = note or "install instruction in documentation"
                if decoded_from:
                    self.add(r["id"] + "-B64", "obfuscation", r["sev"], r["title"] + " (hidden in base64)",
                             path, li, decoded_from, ctx, bump=1)
                else:
                    self.add(r["id"], r["cat"], r["sev"], r["title"], path, li if start_line else None,
                             line, ctx, extra_down=down, note=note, bump=bump)

    def scan_unicode(self, path, text, ctx):
        zw = bidi = tags = vs = 0
        first = {}
        tag_text = []
        prev = ""
        for i, ch in enumerate(text):
            o = ord(ch)
            if o in ZERO_WIDTH:
                if o == 0xFEFF and i == 0:
                    pass
                elif o == 0x200D and (ord(prev) > 0x2000 if prev else False):
                    pass  # emoji ZWJ sequence
                else:
                    zw += 1
                    first.setdefault("zw", i)
            elif o in BIDI_OVERRIDE:
                bidi += 1
                first.setdefault("bidi", i)
            elif 0xE0000 <= o <= 0xE007F:
                if prev and (ord(prev) == 0x1F3F4 or 0xE0000 <= ord(prev) <= 0xE007F) and not tag_text:
                    pass  # subdivision flag emoji
                else:
                    tags += 1
                    first.setdefault("tags", i)
                    if 0xE0020 <= o <= 0xE007E:
                        tag_text.append(chr(o - 0xE0000))
            elif 0xE0100 <= o <= 0xE01EF:
                vs += 1
                first.setdefault("vs", i)
            elif o in MATH_INVISIBLE:
                first.setdefault("math", i)
                first["math_n"] = first.get("math_n", 0) + 1
            prev = ch

        def lineno(i):
            return text.count("\n", 0, i) + 1

        if tags:
            hidden = "".join(tag_text)
            self.add("UC1", "hidden-content", "critical", "Invisible Unicode tag characters (ASCII smuggling)",
                     path, lineno(first["tags"]), f"decoded hidden text: {hidden[:300]}", ctx, extra_down=-DOWN.get(ctx, 1))
        if bidi:
            self.add("UC2", "hidden-content", "high", f"Bidirectional override characters ({bidi}) - Trojan Source",
                     path, lineno(first["bidi"]), text[max(0, first["bidi"] - 60): first["bidi"] + 60], ctx)
        if zw:
            self.add("UC3", "hidden-content", "high" if ctx in ("instr", "code", "hook", "config") else "medium",
                     f"Zero-width characters ({zw})", path, lineno(first["zw"]),
                     text[max(0, first["zw"] - 60): first["zw"] + 60], ctx)
        if vs > 8:
            self.add("UC4", "hidden-content", "high", f"Unicode variation-selector run ({vs}) - possible data smuggling",
                     path, lineno(first["vs"]), "", ctx)
        if "math" in first:
            # invisible math operators are normal in MathML/LaTeX tooling; only notable in agent instructions
            self.add("UC5", "hidden-content", "medium" if ctx == "instr" else "low",
                     f"Invisible math operator characters ({first['math_n']})", path, lineno(first["math"]),
                     text[max(0, first["math"] - 60): first["math"] + 60], ctx, extra_down=-DOWN.get(ctx, 1) if ctx == "instr" else 0)

    def scan_comments(self, path, text, ctx):
        for m in HTML_COMMENT.finditer(text):
            body = m.group(1)
            if HIDDEN_WORDS.search(body) and len(body.strip()) > 20:
                ln = text.count("\n", 0, m.start()) + 1
                self.add("HC1", "hidden-content", "high", "Hidden HTML comment containing agent-directed or sensitive text",
                         path, ln, body, ctx)
                self.scan_text_line_rules(path, body, ctx, ln, ext_of(path))

    def scan_base64(self, path, text, ctx):
        ext = ext_of(path)
        if ctx == "lock" or ext in (".svg", ".ipynb", ".pem", ".crt", ".key"):
            return
        for li, line in enumerate(text.splitlines(), 1):
            if len(line) < 60 or re.search(r"data:[\w/+.-]+;base64,|integrity|sha(256|384|512)-|-----BEGIN", line):
                continue
            for m in B64_BLOB.finditer(line[:200000]):
                blob = m.group(0)
                if blob.startswith(("iVBOR", "/9j/", "R0lGOD", "PHN2Zy", "UklGR", "AAAA", "T2dnU", "d09G")):
                    continue
                try:
                    raw = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=False)
                except (binascii.Error, ValueError):
                    continue
                printable = sum(32 <= b < 127 or b in (9, 10, 13) for b in raw) / max(1, len(raw))
                if printable > 0.9:
                    dec = raw.decode("utf-8", "replace")
                    before = len(self.groups)
                    self.scan_text_line_rules(path, dec, ctx, li, ext, decoded_from=f"line {li}: base64 -> {dec[:120]}")
                    if len(self.groups) == before and len(blob) >= 160 and ctx in ("code", "hook", "instr", "config"):
                        self.add("B64", "obfuscation", "low", "Base64-encoded text blob", path, li, dec[:120], ctx)
                elif len(blob) >= 160 and ctx in ("code", "hook", "instr"):
                    self.add("B64", "obfuscation", "low", "Opaque base64 blob", path, li, blob[:80], ctx)

    def scan_python_ast(self, path, text, ctx):
        try:
            tree = ast.parse(text)
        except Exception:  # noqa: BLE001
            return

        def dotted(n):
            if isinstance(n, ast.Name):
                return n.id
            if isinstance(n, ast.Attribute):
                d = dotted(n.value)
                return f"{d}.{n.attr}" if d else n.attr
            return ""

        lines = text.splitlines()
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = dotted(node.func)
            ln = getattr(node, "lineno", None)
            src = lines[ln - 1] if ln and ln <= len(lines) else name
            const_arg = bool(node.args) and isinstance(node.args[0], ast.Constant)
            shell_true = any(k.arg == "shell" and isinstance(k.value, ast.Constant) and k.value.value is True
                             for k in node.keywords)
            if name in ("eval", "exec", "builtins.eval", "builtins.exec"):
                self.add("PY1", "dangerous-code", "medium" if const_arg else "high",
                         f"Python {name}() of {'a constant' if const_arg else 'dynamic'} value", path, ln, src, ctx)
            elif name == "compile" and not const_arg:
                self.add("PY2", "dangerous-code", "medium", "Python compile() of dynamic code", path, ln, src, ctx)
            elif name in ("__import__", "importlib.import_module") and not const_arg:
                self.add("PY3", "dangerous-code", "low", "Dynamic import of a computed module name", path, ln, src, ctx)
            elif name in ("os.system", "os.popen", "commands.getoutput") or re.fullmatch(r"os\.(exec|spawn)\w*", name):
                self.add("PY4", "dangerous-code", "medium" if const_arg else "high", f"{name}() runs a shell command",
                         path, ln, src, ctx)
            elif name.startswith("subprocess.") or name in ("Popen", "check_output", "run", "call", "check_call"):
                if name.startswith("subprocess.") or name == "Popen":
                    if shell_true:
                        self.add("PY5", "dangerous-code", "high" if not const_arg else "medium",
                                 "subprocess with shell=True", path, ln, src, ctx)
                    else:
                        self.add("PY6", "dangerous-code", "low", "Runs an external program (subprocess)", path, ln, src, ctx)
            elif name in ("pickle.loads", "pickle.load", "marshal.loads", "dill.loads", "cPickle.loads", "shelve.open"):
                self.add("PY7", "dangerous-code", "medium", f"Unsafe deserialisation ({name})", path, ln, src, ctx)
            elif name.startswith("ctypes.") or name in ("ctypes.CDLL", "ctypes.WinDLL"):
                self.add("PY8", "dangerous-code", "low", "Native code via ctypes", path, ln, src, ctx)

    def scan_entry(self, e):
        rel = e.path
        ext = ext_of(rel)
        ctx = self.classify(rel)
        self.ctx[rel] = ctx
        self.inventory[ctx] += 1
        if e.symlink:
            self.symlinks.append(rel)
            self.add("FS1", "filesystem", "low", "Symlink in package (can point outside the install dir)", rel, None, rel, "config")
            return
        if ext in BIN_EXEC:
            self.binaries.append(f"{rel} ({e.size:,} B)")
            sev = "high" if ext in (".exe", ".dll", ".scr", ".msi", ".com", ".sys", ".cpl", ".ocx") else "medium"
            if ctx in ("test",) and ext in (".pyc",):
                sev = "low"
            self.add("BN1", "opaque-binary", sev, "Compiled binary that cannot be reviewed as text", rel, None, rel, ctx if ctx != "test" else "config")
            return
        if ext in BIN_ARCHIVE:
            self.binaries.append(f"{rel} ({e.size:,} B)")
            if ctx not in ("test", "sample"):
                self.add("BN2", "opaque-binary", "low", "Nested archive (contents not scanned)", rel, None, rel, "config")
            return
        if ext in BIN_MEDIA:
            self.inventory["media"] += 1
            return
        if e.size > MAX_FILE:
            self.large.append(f"{rel} ({e.size / (1 << 20):.1f} MB)")
            return
        data = e.read()
        if data is None:
            return
        if b"\x00" in data[:8192]:
            self.binaries.append(f"{rel} ({e.size:,} B, unrecognised binary)")
            if ctx in ("code", "hook", "instr"):
                self.add("BN3", "opaque-binary", "medium", "Binary data in a file that should be text", rel, None, rel, ctx)
            return
        text = data.decode("utf-8", "replace")
        if ext == ".ipynb":
            try:
                nb = json.loads(text)
                text = "\n".join("".join(c.get("source", [])) for c in nb.get("cells", []) if c.get("cell_type") == "code")
                ext = ".py"
            except Exception:  # noqa: BLE001
                pass
        if ctx != "lock":
            for host in URL_RX.findall(text):
                self.domains[host.lower()] += 1
        if text.startswith("#!") and ctx in ("other", "doc"):
            ctx = "code"
            self.ctx[rel] = ctx
        if ctx == "lock":
            return
        self.scan_unicode(rel, text, ctx)
        if ext in (".md", ".mdx", ".mdc", ".markdown", ".html", ".htm", ".txt") or ctx == "instr":
            self.scan_comments(rel, text, ctx)
        self.scan_text_line_rules(rel, text, ctx, 1, ext)
        self.scan_base64(rel, text, ctx)
        if ext in (".py", ".pyw"):
            self.scan_python_ast(rel, text, ctx)
        if ctx in ("code", "hook") and ext in CODE_EXT and not re.search(r"(\.min\.|/dist/|/build/|/vendor/|bundle)", "/" + rel.lower()):
            long_lines = [i for i, ln in enumerate(text.splitlines(), 1) if len(ln) > 3000]
            if long_lines:
                self.add("OB7", "obfuscation", "medium", "Very long code line (minified or obfuscated)", rel,
                         long_lines[0], f"{len(long_lines)} line(s) over 3000 chars", ctx)
        if rel in self.hook_scripts:
            if AUTO_APPROVE_RX.search(text):
                self.add("HK2", "excessive-agency", "high", "Hook script can auto-approve tool calls (skips permission prompts)",
                         rel, None, AUTO_APPROVE_RX.search(text).group(0), "hook")
            remote = [h for h in URL_RX.findall(text) if h.lower() not in ("localhost", "127.0.0.1", "0.0.0.0")]
            if "net" in self.taint.get(rel, set()) and remote:
                self.add("HK3", "exfiltration", "high", "Hook script makes network calls to a remote host (sees prompts/tool output)",
                         rel, None, ", ".join(sorted(set(remote))[:5]), "hook")

    def run(self):
        self.pass_surfaces()
        for e in self.entries:
            self.scan_entry(e)
        for path, t in self.taint.items():
            ctx = self.ctx.get(path, "code")
            if ctx in ("code", "hook") and "net" in t and ("secret" in t or "env" in t):
                self.add("EX5", "exfiltration", "critical" if "secret" in t else "high",
                         "Same file reads secrets/environment AND makes network calls (possible exfiltration)",
                         path, None, ", ".join(sorted(t)), ctx)
        return self

# ----------------------------------------------------------------------------- reputation


def reputation_flags(meta):
    flags = []
    if meta.get("source", "").startswith("GitHub") or meta.get("repo"):
        if meta.get("error"):
            flags.append(("info", f"GitHub metadata unavailable ({meta['error']})"))
        else:
            d = days_since(meta.get("created") or "")
            if d is not None and d < 30:
                flags.append(("low", f"Repository is only {d} days old"))
            od = days_since(meta.get("owner_created") or "")
            if od is not None and od < 90:
                flags.append(("medium", f"Owner account is only {od} days old (throwaway/typosquat risk)"))
            if (meta.get("stars") or 0) < 10:
                flags.append(("low", f"Little community use ({meta.get('stars')} stars)"))
            if not meta.get("license") or meta.get("license") == "NOASSERTION":
                flags.append(("info", f"Licence: {meta.get('license') or 'none'}"))
            if meta.get("archived"):
                flags.append(("low", "Repository is archived (no maintenance)"))
            pd = days_since(meta.get("pushed") or "")
            if pd is not None and pd > 540:
                flags.append(("low", f"No pushes for {pd} days"))
    if meta.get("source") == "npm tarball":
        if meta.get("install_scripts"):
            flags.append(("medium", f"npm install scripts: {meta['install_scripts']}"))
        d = days_since(meta.get("created") or "")
        if d is not None and d < 30:
            flags.append(("low", f"Package first published {d} days ago"))
        if not meta.get("provenance"):
            flags.append(("info", "No npm provenance attestation"))
        if (meta.get("versions_count") or 0) <= 2:
            flags.append(("low", f"Only {meta.get('versions_count')} published version(s)"))
    return flags

# ----------------------------------------------------------------------------- report

LEVEL_TEXT = {
    "CRITICAL": "Do not install. Contains patterns typical of malware or prompt-injection attacks unless every critical finding is a confirmed false positive.",
    "HIGH": "Do not install until every high finding has been read and confirmed benign.",
    "MEDIUM": "Installable after reviewing the listed items; nothing clearly malicious by pattern.",
    "LOW": "Low risk by pattern. Normal caution applies.",
    "CLEAN": "No risky patterns found. Static scanning cannot prove safety; skim the agent-facing files anyway.",
}


def build_report(label, meta, notes, scan, rep_flags):
    findings = sorted(scan.groups.values(), key=lambda g: (-SEVI[g["severity"]], g["rule"], g["path"]))
    real = [f for f in findings if SEVI[f["severity"]] > 0]
    sev_counts = Counter(f["severity"] for f in real)
    score = 0
    per_rule = Counter()
    for f in real:
        per_rule[f["rule"]] += 1
        if per_rule[f["rule"]] <= 3:
            score += WEIGHT[SEVI[f["severity"]]]
    rep_max = max([SEVI[s] for s, _ in rep_flags] + [0])
    top = max([SEVI[f["severity"]] for f in real] + [0, min(rep_max, 2)])
    level = ["CLEAN", "LOW", "MEDIUM", "HIGH", "CRITICAL"][top]
    return dict(tool=f"skill-bill {VERSION}", scanned_at=now_utc().isoformat(timespec="seconds"),
                target=label, level=level, recommendation=LEVEL_TEXT[level], score=score,
                severity_counts={s: sev_counts.get(s, 0) for s in reversed(SEV[1:])},
                metadata=meta, reputation=[{"severity": s, "flag": t} for s, t in rep_flags], notes=notes,
                surfaces={k: v for k, v in scan.surfaces.items()},
                findings=findings,
                inventory=dict(files_scanned=len(scan.entries), by_context=dict(scan.inventory),
                               skipped_dirs=dict(scan.skipped_dirs), binaries=scan.binaries[:50],
                               large_files_not_scanned=scan.large[:50], symlinks=scan.symlinks[:20]),
                domains=[{"host": h, "count": c, "known": any(h == k or h.endswith("." + k) for k in KNOWN_DOMAINS)}
                         for h, c in scan.domains.most_common(60)])


def render_md(r, max_rows=60):
    out = []
    w = out.append
    w(f"# Skill Bill report: {r['target']}")
    w(f"\n**Threat level: {r['level']}** (score {r['score']}). {r['recommendation']}")
    c = r["severity_counts"]
    w(f"\nFindings: {c['critical']} critical, {c['high']} high, {c['medium']} medium, {c['low']} low "
      f"(grouped per rule per file; docs and tests are down-weighted).")
    m = r["metadata"]
    if m:
        w("\n## Source and reputation")
        keys = ["source", "repo", "package", "version", "description", "stars", "forks", "open_issues", "created",
                "pushed", "license", "owner_type", "owner_created", "top_contributors", "maintainers", "publisher",
                "versions_count", "provenance", "install_scripts", "archive_mb", "homepage", "error"]
        for k in keys:
            if m.get(k) not in (None, "", [], {}):
                w(f"- {k}: {m[k]}")
        for f in r["reputation"]:
            w(f"- [{f['severity'].upper()}] {f['flag']}")
    for n in r["notes"]:
        w(f"- NOTE: {n}")
    s = r["surfaces"]
    if s:
        w("\n## Agent-facing surfaces")
        for kind in ("plugin_manifests", "skills", "commands", "agents"):
            for x in s.get(kind, [])[:25]:
                w(f"- {kind[:-1]}: `{x.get('file')}` name={x.get('name')} tools={x.get('tools')} :: {x.get('description', '')}")
            if len(s.get(kind, [])) > 25:
                w(f"- ... {len(s[kind]) - 25} more {kind}")
        for h in s.get("hooks", []):
            w(f"- HOOK {h['event']} [{h['matcher']}] in `{h['file']}`: `{h['command']}` -> scripts {h['scripts']}")
        for x in s.get("mcp_servers", []):
            w(f"- MCP `{x['name']}` in `{x['file']}`: url={x['url'] or '-'} cmd=`{x['command'] or '-'}` env={x['env']}")
        for x in s.get("install_scripts", []):
            w(f"- INSTALL SCRIPT {x}")
        for x in s.get("marketplace_plugins", [])[:30]:
            w(f"- marketplace plugin {x}")
        for x in s.get("settings", []):
            w(f"- settings file `{x}`")
        for x in s.get("bins", []):
            w(f"- bin {x}")
        for x in s.get("notes", [])[:15]:
            w(f"- note: {x}")
        for x in s.get("parse_errors", [])[:10]:
            w(f"- parse error: {x}")
    real = [f for f in r["findings"] if SEVI[f["severity"]] > 0]
    # collapse the same rule repeated across many docs/tests/samples (e.g. translated READMEs) into one row
    buckets = defaultdict(list)
    for f in real:
        if f["context"] in ("doc", "sample", "test", "other"):
            buckets[(f["rule"], f["severity"], f["context"])].append(f)
    collapsed, seen = [], set()
    for f in real:
        key = (f["rule"], f["severity"], f["context"])
        if key in buckets and len(buckets[key]) >= 3:
            if key in seen:
                continue
            seen.add(key)
            grp = buckets[key]
            g = dict(f)
            g["path"] = f"{len(grp)} files: " + ", ".join(x["path"] for x in grp[:3]) + (" …" if len(grp) > 3 else "")
            g["lines"], g["count"] = [], sum(x["count"] for x in grp)
            collapsed.append(g)
        else:
            collapsed.append(f)
    real = collapsed
    w("\n## Findings")
    if not real:
        w("None.")
    else:
        w("| Sev | Rule | Category | Where | Count | What | Evidence |")
        w("|---|---|---|---|---|---|---|")
        for f in real[:max_rows]:
            where = f["path"] + (":" + ",".join(map(str, f["lines"])) if f["lines"] else "")
            ev = f["snippet"].replace("|", "\\|")
            note = f" ({f['note']})" if f.get("note") else ""
            w(f"| {f['severity'].upper()} | {f['rule']} | {f['category']} | `{where}` [{f['context']}] | {f['count']} | {f['title']}{note} | `{ev}` |")
        if len(real) > max_rows:
            rest = Counter(f["severity"] for f in real[max_rows:])
            w(f"\n... {len(real) - max_rows} more grouped findings not shown ({dict(rest)}); see the JSON report.")
    unk = [d for d in r["domains"] if not d["known"]]
    if unk:
        w("\n## External hosts referenced (not on the common-benign list)")
        w(", ".join(f"{d['host']} ({d['count']})" for d in unk[:40]))
    inv = r["inventory"]
    w("\n## Inventory")
    w(f"- files scanned: {inv['files_scanned']}; by context: {inv['by_context']}")
    if inv["skipped_dirs"]:
        w(f"- skipped vendored dirs: {inv['skipped_dirs']}")
    if inv["binaries"]:
        w(f"- binaries/archives ({len(inv['binaries'])}): {', '.join(inv['binaries'][:15])}")
    if inv["large_files_not_scanned"]:
        w(f"- large files not content-scanned: {', '.join(inv['large_files_not_scanned'][:10])}")
    w("\n_Static pattern scan only: it finds suspicious patterns, it cannot prove a package is safe. "
      "Confirm or dismiss each HIGH/CRITICAL finding by reading the file._")
    return "\n".join(out)


def main():
    ap = argparse.ArgumentParser(description="Static security scanner for AI agent skills/plugins/MCP servers.")
    ap.add_argument("target")
    ap.add_argument("--json", help="write the full JSON report here")
    ap.add_argument("--md", help="also write the markdown report here")
    ap.add_argument("--max-mb", type=int, default=300, help="download size cap in MB (default 300)")
    ap.add_argument("--no-meta", action="store_true", help="skip GitHub/npm reputation lookups")
    ap.add_argument("--rows", type=int, default=60, help="max finding rows in the markdown table")
    a = ap.parse_args()
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:  # noqa: BLE001
        pass
    try:
        label, entries, meta, notes = resolve_target(a.target, a.max_mb << 20, not a.no_meta)
    except urllib.error.HTTPError as e:
        raise SystemExit(f"fetch failed: HTTP {e.code} for {e.url}")
    if not entries:
        raise SystemExit("nothing to scan (empty target or subpath not found)")
    scan = Scan(entries).run()
    report = build_report(label, meta, notes, scan, reputation_flags(meta))
    md = render_md(report, a.rows)
    print(md)
    if a.json:
        with open(a.json, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, default=str)
    if a.md:
        with open(a.md, "w", encoding="utf-8") as f:
            f.write(md)
    sys.exit({"CLEAN": 0, "LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}[report["level"]])


if __name__ == "__main__":
    main()
