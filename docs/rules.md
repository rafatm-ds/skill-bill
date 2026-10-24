# Rule catalogue

Generated from `skills/skill-bill/scripts/scan.py`. Severities are the base level, before context weighting (docs -1, samples -1, tests and signature files -2, detection-rule literals -1, escalation +1/+2 when the same line is sensitive).

## Pattern rules

### backdoor

| ID | Base severity | Detects |
|---|---|---|
| RS1 | critical | Reverse shell pattern |
| RS2 | critical | Crypto-miner reference |

### credential-access

| ID | Base severity | Detects |
|---|---|---|
| CR1 | high | Touches SSH/cloud/CLI credential files |
| CR2 | high | Browser/keychain/wallet secret store |
| CR3 | medium | Serialises or dumps all environment variables |
| CR4 | low | Instructs the agent to read or send secrets |

### dangerous-code

| ID | Base severity | Detects |
|---|---|---|
| DC1 | medium | JavaScript eval() |
| DC2 | medium | new Function() (dynamic code) |
| DC3 | medium | Shell command built from template string |
| DC4 | low | Spawns child processes |

### destructive

| ID | Base severity | Detects |
|---|---|---|
| DS1 | high | Recursive delete of root/home |
| DS2 | high | PowerShell recursive delete of home/drive |
| DS3 | high | Disk wipe / format |
| DS4 | medium | Force push |
| DS5 | low | Hard reset / clean of git working tree |

### download-exec

| ID | Base severity | Detects |
|---|---|---|
| DX1 | critical | Remote script piped into a shell |
| DX2 | critical | PowerShell download piped into Invoke-Expression |
| DX3 | high | PowerShell Invoke-Expression |
| DX4 | critical | PowerShell encoded command |
| DX5 | high | Windows LOLBin download/execute (certutil, bitsadmin, mshta, regsvr32) |
| DX6 | high | Download a file and then execute it |
| DX8 | critical | Decodes a payload and pipes it into a shell/interpreter |
| DX7 | critical | Executes code fetched from the network |

### excessive-agency

| ID | Base severity | Detects |
|---|---|---|
| PI6 | high | Tells the agent to disable safety or permission checks |
| PI7 | high | Permission-bypass flag or mode |
| PI8 | medium | Acts without user confirmation |

### exfiltration

| ID | Base severity | Detects |
|---|---|---|
| EX1 | high | Known exfiltration / tunnelling / paste endpoint |
| EX2 | medium | URL shortener or IP-lookup service |
| EX3 | high | Hard-coded public IP address URL |
| EX4 | high | Instructs the agent to send data to an external destination |

### memory-poisoning

| ID | Base severity | Detects |
|---|---|---|
| PI9 | medium | Writes into agent memory/config files |

### obfuscation

| ID | Base severity | Detects |
|---|---|---|
| OB1 | critical | eval of decoded string |
| OB2 | critical | Function/eval of Buffer-decoded payload |
| OB3 | critical | exec of decoded/decompressed payload |
| OB4 | medium | Long String.fromCharCode sequence |
| OB5 | medium | Long hex-escaped string |
| OB6 | medium | Long unicode-escaped string |

### persistence

| ID | Base severity | Detects |
|---|---|---|
| PS1 | high | Modifies shell startup profile |
| PS2 | high | Installs scheduled task / autostart |
| PS3 | medium | Code writes into the user's global Claude/agent config |
| PS4 | medium | Git hooks redirection |

### privacy

| ID | Base severity | Detects |
|---|---|---|
| SC3 | low | Telemetry/analytics SDK |

### prompt-injection

| ID | Base severity | Detects |
|---|---|---|
| PI1 | high | Instruction-override phrasing |
| PI2 | medium | Tells the agent to keep something from the user |
| PI3 | high | Hide-from-user instruction |
| PI4 | medium | Role hijack / jailbreak phrasing |
| PI5 | medium | Fake system/authority markup |

### supply-chain

| ID | Base severity | Detects |
|---|---|---|
| SC1 | low | Unpinned or always-latest install |
| SC2 | medium | Non-default package index/registry |

### traffic-redirect

| ID | Base severity | Detects |
|---|---|---|
| SC4 | low | Redirects model API traffic (base-URL override) |

## Structural, config and Python-AST checks

| ID | Category | Base severity | Detects |
|---|---|---|---|
| B64 | obfuscation | low | Base64-encoded text blob |
| BN1 | opaque-binary | varies | Compiled binary that cannot be reviewed as text |
| BN2 | opaque-binary | low | Nested archive (contents not scanned) |
| BN3 | opaque-binary | medium | Binary data in a file that should be text |
| EX5 | exfiltration | varies | Same file reads secrets/environment AND makes network calls (possible exfiltration) |
| FS1 | filesystem | low | Symlink in package (can point outside the install dir) |
| HC1 | hidden-content | high | Hidden HTML comment containing agent-directed or sensitive text |
| HK1 | exfiltration | high | HTTP hook posts agent events to a remote URL |
| HK2 | excessive-agency | high | Hook script can auto-approve tool calls (skips permission prompts) |
| HK3 | exfiltration | high | Hook script makes network calls to a remote host (sees prompts/tool output) |
| IN1 | install-time-code | varies | npm `{k}` script runs on install |
| IN2 | install-time-code | high | setup.py runs custom code at install time |
| MCP1 | data-egress | medium | Remote MCP server '{name}' (context leaves the machine) |
| OB7 | obfuscation | medium | Very long code line (minified or obfuscated) |
| PY1 | dangerous-code | varies | Python {name}() of {'a constant' if const_arg else 'dynamic'} value |
| PY2 | dangerous-code | medium | Python compile() of dynamic code |
| PY3 | dangerous-code | low | Dynamic import of a computed module name |
| PY4 | dangerous-code | varies | {name}() runs a shell command |
| PY5 | dangerous-code | varies | subprocess with shell=True |
| PY6 | dangerous-code | low | Runs an external program (subprocess) |
| PY7 | dangerous-code | medium | Unsafe deserialisation ({name}) |
| PY8 | dangerous-code | low | Native code via ctypes |
| SC5 | supply-chain | varies | Dependency fetched from git/URL, not the registry |
| SC6 | supply-chain | low | Marketplace pulls a plugin from another repo (not scanned here) |
| ST1 | excessive-agency | critical | Settings switch off all permission prompts |
| ST2 | excessive-agency | medium | Settings set permission mode '{mode}' |
| ST3 | excessive-agency | high | Settings pre-approve a broad tool |
| ST4 | traffic-redirect | high | Settings redirect API traffic through another endpoint |
| ST5 | excessive-agency | medium | Auto-enables every project MCP server |
| ST6 | credential-access | medium | Settings run a credential helper script |
| TL1 | excessive-agency | medium | Pre-approves unrestricted Bash |
| TR1 | trigger-abuse | low | Over-broad trigger in description (fires on almost everything) |
| UC1 | hidden-content | critical | Invisible Unicode tag characters (ASCII smuggling) |
| UC2 | hidden-content | high | Bidirectional override characters ({bidi}) - Trojan Source |
| UC3 | hidden-content | varies | code |
| UC4 | hidden-content | high | Unicode variation-selector run ({vs}) - possible data smuggling |
| UC5 | hidden-content | varies | Invisible math operator characters ({first['math_n']}) |

Any pattern rule can also fire as `<ID>-B64` when it matches text hidden inside a base64 blob; those are raised one severity level.
