# Demo Video Script — SecureOps AI (Extended Cut)

**Duration:** ~5 minutes
**Style:** Screen recording with voiceover — terminal, MCP client UI, browser dashboard
**Tone:** Professional, confident, slightly dramatic. Judges should feel this is a production-grade solution, not just a hackathon project.

---

## [0:00-0:40] Opening Hook

**Visual:** Black screen. Green text types out character by character:

```
> Initializing SecureOps AI...
> Protocol: MCP (Model Context Protocol)
> Mode: Zero-Knowledge Auditing
> Status: READY
```

**Narrator:**
"Every company with proprietary code faces the same dilemma. They want AI-powered security auditing — but they can't risk sending their source code to a third-party cloud."

**Visual:** Split screen. Left side shows a red "X" over cloud upload icon. Right side shows a green shield with the SecureOps logo.

**Narrator:**
"What if the LLM came to your code instead of the other way around? That's what we built."

**Visual:** Animated transition — cloud icon fades, replaced by local laptop icon with MCP arrows flowing

**Narrator:**
"SecureOps AI. Zero-knowledge security auditing via the Model Context Protocol. Your code stays local. The LLM orchestrates. Vulnerabilities get caught."

---

## [0:40-1:20] What It Does — The Pitch

**Visual:** Three animated cards appear one by one

**Narrator:**
"Here's what it does in one sentence: SecureOps AI runs on your machine, scans your codebase for vulnerabilities across three detection layers, and exposes everything as MCP tools that an LLM can call."

**Visual:** First card — "Layer 1: Regex Scanner" (14 rules, 39 patterns)

**Narrator:**
"Layer one — a regex engine with 14 configurable rules and 39 patterns. It catches hardcoded secrets, SQL injection, XSS, command injection, path traversal — across 20+ languages."

**Visual:** Second card — "Layer 2: AST Analyzer" (Python semantic analysis)

**Narrator:**
"Layer two — a Python AST analyzer that understands code structure. It catches eval(), exec(), os.system() calls, insecure deserialization, and even variable names that suggest secrets."

**Visual:** Third card — "Layer 3: File Scanner" (.env + filename detection)

**Narrator:**
"Layer three — filename-based detection for sensitive files like .env and id_rsa, plus specialized .env KEY=VALUE parsing that doesn't require quotes."

**Visual:** All three cards merge into a single output stream: JSON + SARIF + Dashboard

**Narrator:**
"All three layers produce structured JSON, industry-standard SARIF output, and an interactive HTML dashboard."

---

## [1:20-2:00] MCP Integration — The Key Innovation

**Visual:** MCP architecture diagram appears. Central element: "MCP Protocol" connecting "LLM Client" to "SecureOps Server"

**Narrator:**
"The real innovation is how the LLM interacts with the code. Through the Model Context Protocol, the LLM gets five tools — and only five tools."

**Visual:** Five tool cards slide in:

```
┌─────────────────────────────────────────────────────┐
│  MCP TOOLS EXPOSED BY SECUREOPS AI                    │
├─────────────────────────────────────────────────────┤
│  scan_directory_structure(target_dir)                │
│  → Returns file tree (paths only, zero content)      │
│                                                       │
│  run_local_security_audit(target_dir)                 │
│  → Returns JSON with all findings + summary          │
│                                                       │
│  get_audit_summary(target_dir)                        │
│  → Returns summary counts only (fast triage)          │
│                                                       │
│  run_local_security_audit_sarif(target_dir)            │
│  → Returns SARIF v2.1.0 for GitHub/VS Code           │
│                                                       │
│  read_file_securely(filepath, base_dir)               │
│  → Returns file content WITH traversal protection    │
└─────────────────────────────────────────────────────┘
```

**Narrator:**
"The LLM can request a file tree to understand structure. It can request a full audit. It can request a specific flagged file — but only one file at a time, and path traversal is blocked. The LLM never sees your entire codebase. Ever."

**Visual:** Highlight the word "NEVER" in red, then fade

---

## [2:00-2:45] Configuring MCP in Real Tools

**Visual:** Split into three columns showing three different configurations

**Narrator:**
"SecureOps AI works with any MCP-compatible client. Here's how you connect it."

**Visual — Column 1: opencode.json**

```json
{
  "mcpServers": {
    "secureops": {
      "command": "python",
      "args": ["E:/projects/secureops-mcp/server.py"]
    }
  }
}
```

**Narrator:**
"In opencode — the AI coding assistant — you add a single MCP server entry to your configuration. The server starts automatically when opencode launches, and the tools appear in the tool list instantly."

**Visual — Column 2: Claude Desktop**

```json
{
  "mcpServers": {
    "secureops": {
      "command": "python",
      "args": ["E:/projects/secureops-mcp/server.py"]
    }
  }
}
```

**Narrator:**
"Same configuration for Claude Desktop. The tools show up as available actions — the LLM knows when to call them based on context."

**Visual — Column 3: VS Code + Any MCP Client**

```json
// VS Code settings.json or MCP extension config
{
  "mcp.servers": {
    "secureops": {
      "command": "python",
      "args": ["server.py"]
    }
  }
}
```

**Narrator:**
"VS Code, Continue.dev, custom MCP SDK clients — the pattern is identical. One JSON block, and SecureOps AI is available as a tool in your LLM workflow."

**Visual:** Zoom out to show all three configs side by side, then highlight the common pattern

**Narrator:**
"The beauty of MCP is this portability. Write the integration once, use it everywhere."

---

## [2:45-3:30] Live Demo — Scanning target_project

**Visual:** Terminal window. Type:

```bash
python server.py
```

**Narrator:**
"Let's run it. One command to start the server."

**Visual:** Server starts, shows "SecureOps-AI MCP server running on stdio"

**Narrator:**
"Now I'm in opencode. The MCP tools are already loaded. Let me ask the LLM to scan a project."

**Visual:** Switch to opencode interface. Type:

```
Scan this directory for security vulnerabilities using the secureops tool.
```

**Narrator:**
"The LLM recognizes it has access to SecureOps AI tools. It starts by getting context."

**Visual:** Show the LLM calling:

```
⚙ scan_directory_structure(target_dir="target_project")
← {"tree": "target_project/\n  .env\n  App.java\n  app.js\n  app.py\n  main.go\n  main.rs\n  requirements.txt"}
```

**Narrator:**
"It asks for the file tree first — just the structure, no content. Then it runs the audit."

```
⚙ run_local_security_audit(target_dir="target_project")
← {"summary": {"critical": 9, "high": 10, "medium": 1, "info": 1}, "findings": [...]}
```

**Narrator:**
"19 findings across 7 files. 9 critical. The LLM now has everything it needs to give us a full security report."

**Visual:** Show the LLM's response — the analysis text

```
Security Audit Results — target_project

Severity: 9 Critical | 10 High | 1 Medium | 1 Info

Key findings by file:
- .env — Exposed DATABASE_URL and GITHUB_TOKEN. Add to .gitignore and rotate tokens.
- app.py — Hardcoded AWS secret, os.system() command injection, exec(), pickle deserialization.
- app.js — Command injection via cp.exec(), XSS via innerHTML, unsafe eval().
- main.go — Hardcoded API secret (sk-live-...).
- App.java — Hardcoded DB password.
- main.rs — Path traversal via unsanitized file path concatenation.
```

**Narrator:**
"In seconds, the LLM analyzed 7 files across 5 languages and delivered a clear, actionable security report — without ever seeing the raw source code."

---

## [3:30-4:00] .env File Detection — Deep Dive

**Visual:** Open .env file in the code editor

```
DATABASE_URL=postgres://admin:supersecret@10.0.0.1:5432/prod
GITHUB_TOKEN=ghp_abc123def456ghi789jkl
```

**Narrator:**
"Let me highlight something most scanners miss. Our .env file has secrets in plain text — but they're not quoted. Most regex scanners expect quoted strings. SecureOps AI doesn't."

**Visual:** Animated highlight showing the KEY=VALUE parsing

**Narrator:**
"We parse the raw KEY=VALUE format line by line. If the key matches our list — database_url, github_token, api_key, secret, password — and the value is more than 8 characters, we flag it as critical."

**Visual:** Dashboard showing the .env findings

**Narrator:**
"The result? Three findings on one .env file. One high for the filename itself, two critical for the unquoted secrets. Add .gitignore, rotate the tokens, and you're protected."

---

## [4:00-4:30] Interactive Dashboard

**Visual:** Open dashboard.html in browser — full page load with CSS animations

**Narrator:**
"We also built an interactive HTML dashboard. Self-contained, zero dependencies, opens in any browser."

**Visual:** Mouse moves across elements:
1. Stats cards (Files: 7, Critical: 9, High: 10, etc.)
2. Severity donut chart animating
3. Risk score gauge showing 100/100
4. File-by-file breakdown expanding findings
5. Full findings table scrolling

**Narrator:**
"The severity donut chart, the risk score, the file-by-file breakdown, and a full searchable findings table. You can export everything as JSON or SARIF with one click."

**Visual:** Click Export SARIF button, show save dialog

**Narrator:**
"SARIF is the industry standard for static analysis. Open the .sarif file in VS Code with the SARIF Viewer extension — you get inline code annotations. Open it in GitHub — you get PR-level security alerts."

---

## [4:30-4:50] Remediation — The LLM Fixes Code

**Visual:** Back to the LLM interface

**Narrator:**
"Here's where it gets powerful. I'm going to ask the LLM to fix one of the findings."

**Visual:** Type: "Fix the command injection vulnerability in app.py"

**Narrator:**
"The LLM calls read_file_securely to see the flagged file."

```
⚙ read_file_securely(filepath="app.py", base_dir="./target_project")
← {"file": "app.py", "content": "import os\n..."}
```

**Visual:** Show the LLM reading the file, analyzing the vulnerable code, and generating a fix

**Narrator:**
"It reads the specific file — path traversal protected — analyzes the vulnerability, and generates a fix."

**Visual:** The LLM outputs the fixed code:

```python
# Before:
os.system(f"ping {user_input}")

# After:
import subprocess
subprocess.run(["ping", user_input], capture_output=True, text=True)
```

**Narrator:**
"From detection to remediation in one conversation. The LLM never saw the rest of the codebase — just the one file it needed."

---

## [4:50-5:20] Wrap Up — The Bigger Picture

**Visual:** Montage of all the pieces:
- Terminal with server running
- LLM analysis text
- Dashboard with charts
- SARIF file in VS Code
- Docker container running

**Narrator:**
"SecureOps AI is production-ready. Docker support, docker-compose, Python 3.13+, configurable YAML rules, SARIF v2.1.0 output. One command to deploy:"

```
docker compose up
```

**Visual:** Text appears — "Zero-Knowledge. Local-First. LLM-Powered."

**Narrator:**
"This isn't just a hackathon project. This solves a real problem that every security-conscious engineering team faces — how to leverage LLM intelligence without compromising code privacy."

**Visual:** Final screen:

```
SecureOps AI
Built for Global Tech Innovation 2026
LLM with MCP + Cybersecurity & Privacy

github.com/[your-team]/secureops-mcp
```

**Narrator:**
"We're SecureOps AI. Your code stays yours. The LLM does the work. Vulnerabilities get caught. Thank you."

**Visual:** Fade to black

---

## Production Notes

- **Resolution**: 1920x1080, 60fps
- **Terminal**: Dark theme, green-on-black, font size 14pt+
- **MCP Client UI**: Use opencode or Claude Desktop — show the tool call flow
- **Dashboard**: Full-screen in Chrome, disable bookmarks bar
- **Audio**: Clear voice, steady pace, slight emphasis on security/trust keywords
- **Transitions**: Clean cuts between segments, no flashy effects
- **Captions**: Yes — closed captions throughout
- **Duration**: Target 4:30-5:00 (edit for pacing)

## Segment Timing Summary

| Time | Segment | Key Visual |
|------|---------|------------|
| 0:00-0:40 | Opening Hook | Terminal boot sequence → Problem/Solution split |
| 0:40-1:20 | Three Detection Layers | Animated cards → merged output stream |
| 1:20-2:00 | MCP Innovation | Tool cards → "NEVER" highlight |
| 2:00-2:45 | Configuring MCP Clients | 3-column config comparison (opencode, Claude, VS Code) |
| 2:45-3:30 | Live Scan Demo | opencode interface → tool calls → LLM analysis |
| 3:30-4:00 | .env Deep Dive | Code editor → KEY=VALUE parsing → dashboard findings |
| 4:00-4:30 | Dashboard | HTML page → donut → files → table → SARIF export |
| 4:30-4:50 | Remediation | LLM reads file → generates fix → before/after code |
| 4:50-5:20 | Wrap Up | Montage → Docker → final screen → thank you |

## Required Recordings Checklist

- [ ] Terminal: `python server.py` startup (with venv activation)
- [ ] opencode: Configuration file showing MCP server entry
- [ ] opencode: Tool call flow (scan → audit → analysis)
- [ ] Claude Desktop: MCP config JSON
- [ ] VS Code: MCP configuration + SARIF viewer
- [ ] Browser: Full dashboard walkthrough (stats → donut → files → table → export)
- [ ] Code editor: .env file content, before/after fix comparison
- [ ] Docker: docker compose up command
- [ ] Final screen with team + GitHub link
