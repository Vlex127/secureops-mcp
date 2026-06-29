# SecureOps AI — Presentation Guide

## Slide Deck Outline (6 slides)

### Slide 1: Title Slide
**Title:** SecureOps AI
**Subtitle:** Zero-Knowledge Security Auditing via Model Context Protocol
**Track:** LLM with MCP + Cybersecurity & Privacy
**Logos:** [Team Name], [University/Organization], Global Tech Innovation 2026

### Slide 2: The Problem
**Headline:** Your code is your crown jewel. Don't ship it to a black box.

**Bullet points:**
- Developers want LLM-powered security auditing
- But sending proprietary source code to third-party APIs is a security risk
- Enterprise compliance (SOC 2, HIPAA, GDPR) blocks bulk code upload
- Existing SAST tools lack LLM reasoning capabilities

**Visual:** Split screen — left side shows "code → cloud LLM" with a red X, right side shows "code stays local" with a green checkmark

### Slide 3: Our Solution
**Headline:** Invert the paradigm. The LLM comes to your code.

**How it works:**
1. Local MCP Server runs on your machine
2. Three-layer detection engine scans your codebase
3. LLM orchestrates via sandboxed MCP tools
4. Only flagged snippets are ever exposed

**Visual:** Architecture diagram showing MCP Client → MCP Protocol → SecureOps Server → File System

### Slide 4: Technical Architecture
**Headline:** Three detection layers, one unified output

**Layer 1 — Regex Scanner:**
- 14 rules, 39 patterns across 20+ languages
- Configurable via YAML (add custom rules)
- Severity triage (critical → info)

**Layer 2 — AST Analyzer:**
- Python AST walker catches semantic patterns
- Detects eval(), exec(), os.system(), pickle.loads()
- Variable-name-based secret detection

**Layer 3 — File Scanner:**
- Filename-based detection (.env, id_rsa, credentials)
- .env unquoted KEY=VALUE parsing
- Dependency manifest flagging

**Output:**
- Structured JSON → LLM-friendly
- SARIF v2.1.0 → GitHub/VS Code compatible
- Interactive HTML Dashboard

**Visual:** Three stacked layers feeding into output formats

### Slide 5: Demo
**Headline:** See it in action

**Demo Walkthrough:**
1. Start the MCP server (`python server.py`)
2. Connect MCP client (Claude Desktop / VS Code)
3. Run `scan_directory_structure("./target_project")` — see the file tree
4. Run `run_local_security_audit("./target_project")` — 19 findings in 7 files
5. Open `dashboard.html` — interactive charts and risk scoring
6. Export SARIF — upload to GitHub for inline annotations

**Sample results:**
```
.env         → 3 findings (sensitive file, 2 unquoted secrets)
app.py       → 7 findings (secrets, command injection, deserialization)
app.js       → 4 findings (command injection, XSS, eval)
App.java     → 1 finding (hardcoded DB password)
main.go      → 1 finding (hardcoded API secret)
main.rs      → 1 finding (path traversal)
```

### Slide 6: Impact & Future
**Headline:** Beyond the hackathon

**Real-world impact:**
- Pre-commit security gating
- CI/CD pipeline integration
- Third-party code review
- Developer security education
- Legacy codebase migration

**Future roadmap:**
- Real-time file watching
- Auto-fix suggestions via LLM
- Semgrep integration
- Git history scanning
- VS Code extension

**Links:**
- GitHub: [repo-url]
- Devpost: [devpost-url]
- Demo: [video-url]

---

## Key Talking Points for Judges

### Why This Matters
"Every company with proprietary code faces this dilemma: they want AI-powered security auditing but can't risk leaking their IP. SecureOps AI solves this by keeping code local while still leveraging LLM reasoning."

### Technical Depth
"We built three detection layers because no single approach catches everything. Regex is fast and broad, AST catches semantic patterns that regex misses, and filename detection catches configuration exposure that content scanning might skip."

### The MCP Advantage
"Model Context Protocol is the enabler here. It gives the LLM structured tools to request exactly what it needs — a file tree, a scan report, a specific flagged file — without ever seeing the full codebase. This is a fundamentally new security paradigm."

### Real-World Readiness
"SARIF output means this integrates with existing tooling immediately. GitHub Advanced Security, VS Code, and Azure DevOps all consume SARIF. The Docker setup means one command to deploy."

---

## Demo Script (3 minutes)

```
[0:00-0:30] — Introduction
"Hi, we're [Team Name] and this is SecureOps AI. We're solving the problem of secure
code auditing with LLMs. The core insight: instead of sending your code to the LLM,
bring the LLM to your code via MCP."

[0:30-1:00] — Show the problem
"Here's our target project — 7 files across 5 languages. It's intentionally vulnerable.
Let's scan it."

Open dashboard.html and show the clean state (or terminal showing scan starting)

[1:00-1:45] — Run the scan
"In one command, SecureOps AI scans everything. 19 findings across 7 files."

Show the terminal output with findings, then switch to dashboard.html

[1:45-2:30] — Dashboard walkthrough
"The interactive dashboard shows severity breakdown, risk score at 73/100,
file-by-file findings, and a full table. You can export to JSON or SARIF."

Click through: donut chart → risk score → file breakdown → table → export

[2:30-3:00] — The MCP flow
"What makes this powerful is the MCP protocol. The LLM orchestrates the audit
through sandboxed tools — it can request a file tree, get the scan report, or
read a specific flagged file. But it never sees your entire codebase."

Show MCP tools being called (screen recording from Claude or similar)

[3:00-3:30] — Wrap up
"SecureOps AI is open source, Docker-ready, and ready for CI/CD integration.
We're excited about the future — real-time monitoring, auto-fixes, and deeper
SAST integration. Thank you!"
```
