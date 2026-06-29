# Demo Video Script — SecureOps AI

**Duration:** ~3 minutes
**Style:** Screen recording with voiceover, clean terminal + browser

---

## [0:00-0:25] Introduction

**Visual:** Split screen — left half shows code editor with secure code, right half shows terminal

**Narrator:**
"Every developer wants to use AI to find security vulnerabilities in their code. But sending your entire codebase to a cloud LLM? That's a hard no for most enterprises."

**Visual:** Transition to architecture diagram — laptop icon with shield, MCP arrow to LLM

**Narrator:**
"SecureOps AI solves this. We flip the paradigm — instead of sending code to the LLM, the LLM comes to your code, through the Model Context Protocol."

---

## [0:25-0:55] Setup & Scan

**Visual:** Terminal window

**Narrator:**
"Let's see it in action. One command to start the server."

```bash
# Terminal recording
python server.py
```

**Visual:** Server starts, shows "SecureOps-AI MCP server running"

**Narrator:**
"The MCP server is now running locally. Any MCP-compatible client — Claude, VS Code, your own app — can connect and start auditing."

**Visual:** Switch to dashboard view or second terminal showing MCP tool calls

**Narrator:**
"We'll scan this sample project with 7 files across 5 languages — Python, JavaScript, Java, Go, and Rust — all with intentional vulnerabilities."

```bash
# Tool call result
get_audit_summary("./target_project")
# Response: 19 total findings, 7 files scanned
```

---

## [0:55-1:40] Results Walkthrough

**Visual:** Open dashboard.html in browser — show full page load animation

**Narrator:**
"Results come back as structured JSON, but we also have this interactive dashboard. Let me show you what we found."

**Visual:** Mouse highlights stats cards

**Narrator:**
"9 critical, 8 high, 1 medium finding across 7 files. Risk score of 73 out of 100 — that's a red alert."

**Visual:** Click on donut chart area, then scroll to file breakdown

**Narrator:**
"The donut chart shows severity distribution. Below that, our file breakdown shows you exactly which files have issues."

**Visual:** Expand `.env` file finding

**Narrator:**
"Our .env detection caught unquoted secrets — a DATABASE_URL with a hardcoded password and a GITHUB_TOKEN. No quotes needed, we parse the KEY=VALUE format directly."

**Visual:** Expand `app.py` findings

**Narrator:**
"In app.py, we found 7 issues including hardcoded AWS secrets, command injection via os.system, eval() execution, and insecure pickle deserialization. Three detection layers working together."

---

## [1:40-2:15] MCP Protocol Flow

**Visual:** Animated diagram showing MCP tool flow

**Narrator:**
"Here's the key innovation. The LLM never sees your raw codebase. Instead, it uses MCP tools to request specific information."

**Visual:** Tool call animation
1. `scan_directory_structure()` → returns file tree
2. `run_local_security_audit()` → returns findings JSON
3. `read_file_securely("app.py")` → returns specific file content only when needed

**Narrator:**
"The LLM requests a file tree to understand structure. It asks for a security scan. Only when a specific file is flagged does it read that file — with path traversal protection built in."

---

## [2:15-2:40] Export & Integration

**Visual:** Dashboard export buttons, then VS Code with SARIF

**Narrator:**
"Results can be exported as JSON or SARIF. SARIF is the industry standard for static analysis — it integrates directly with GitHub Advanced Security and VS Code."

**Visual:** Show SARIF file being saved, then open in VS Code with SARIF viewer

**Narrator:**
"This means SecureOps AI fits right into your existing workflow — CI/CD pipelines, PR reviews, or local development."

---

## [2:40-3:00] Wrap Up

**Visual:** Final slide with key points

**Narrator:**
"SecureOps AI is open source, Docker-ready, and production-grade. One command to deploy:"

```bash
docker compose up
```

**Narrator:**
"We built this for Global Tech Innovation 2026. It addresses two tracks: LLM with MCP, and Cybersecurity & Privacy. But more importantly, it solves a real problem that every security-conscious team faces."

**Visual:** Text overlay — "Zero-Knowledge. Local-First. LLM-Powered."

**Narrator:**
"Your code stays yours. The LLM does the work. Vulnerabilities get caught. That's SecureOps AI."

**Visual:** Fade to black with GitHub QR code and "Thank you"

---

## Production Notes

- **Screen resolution**: Record at 1920x1080
- **Terminal**: Use dark theme with green-on-black (matches cybersecurity aesthetic)
- **Dashboard**: Open in full-screen browser, use Chrome/Safari for best results
- **Audio**: Clear narration, no background music during demo
- **Don't show**: Don't display the actual secret values in close-up — blur or mask them
- **Captions**: Add closed captions for accessibility

## Required Recordings

1. Terminal: `python server.py` startup
2. Terminal/Dashboard: MCP tool calls showing results
3. Browser: Full dashboard walkthrough (stats → donut → files → table → export)
4. VS Code: SARIF file open with extension (optional but impressive)
5. Screen: Diagram animation of MCP flow (can use PowerPoint or similar)
