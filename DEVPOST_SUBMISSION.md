# Devpost Submission — SecureOps AI

## Project Title
**SecureOps AI** — Zero-Knowledge Security Auditing via MCP

## Tagline
Your code stays local. The LLM orchestrates. Vulnerabilities get caught.

## Track
LLM with MCP + Cybersecurity & Privacy

---

## Problem Statement

Developers want to use LLMs to audit their code for security vulnerabilities, but sending proprietary source code to third-party cloud APIs is a non-starter for most enterprises. How do you leverage LLM intelligence for security auditing without leaking your codebase?

## Solution

SecureOps AI inverts the traditional approach. Instead of sending code to the LLM, a local MCP (Model Context Protocol) server acts as a secure, sandboxed guardian:

1. **MCP Server** runs locally on the developer's machine
2. **Three-layer detection engine** (regex + AST + filename) scans the codebase
3. **LLM orchestrates** via MCP tools — requesting file trees, scan results, and targeted file reads
4. **Zero bulk code exposure** — only flagged snippets are ever shown to the LLM

## Architecture

```
┌─────────────────────────────────────────────────────┐
│              MCP Client (Claude / any LLM)           │
│                                                      │
│  scan_directory_structure("./project")               │
│  run_local_security_audit("./project") ───► JSON     │
│  read_file_securely("flagged.py", "./project")       │
│                                                      │
│  LLM sees: findings + summary + only flagged files   │
│  NEVER sees: entire codebase                         │
└──────────────────────┬──────────────────────────────┘
                       │ MCP Protocol (local)
┌──────────────────────▼──────────────────────────────┐
│            SecureOps MCP Server (Python)             │
│                                                      │
│  RegexScanner  → 14 rules, 39 patterns              │
│  ASTAnalyzer   → Python AST (eval, exec, pickle)    │
│  FileScanner   → Filename detection, .env parsing    │
│  DepScanner    → Dependency manifest flagging        │
│  SARIF Builder → Standard static analysis format     │
└─────────────────────────────────────────────────────┘
```

## Key Features

### 1. Zero-Knowledge Auditing
No source code ever leaves the developer's machine. The LLM coordinates the audit through sandboxed MCP tools but never receives raw file content unless a specific flagged file is requested.

### 2. Three-Layer Detection
- **Regex Scanner**: 14 configurable rules, 39 patterns covering API keys, SQL injection, XSS, command injection, insecure deserialization, hardcoded secrets, open redirects, path traversal, and more
- **AST Analyzer**: Python AST walker catches `eval()`, `exec()`, `os.system()`, `subprocess.Popen(shell=True)`, `pickle.loads()`, `yaml.load()`, and variable-name-based secret detection
- **File Scanner**: Filename-based sensitive file detection (.env, id_rsa, credentials) + .env unquoted KEY=VALUE parsing

### 3. Multi-Language Support
Python, JavaScript, TypeScript, JSX, TSX, Go, Rust, Java, Ruby, PHP, Shell, Batch, PowerShell, C/C++, C#, Kotlin, Swift, Terraform, HTML, Vue, Svelte, YAML, JSON, TOML, and more.

### 4. SARIF Output
Generates standard SARIF v2.1.0 output compatible with GitHub Advanced Security, VS Code SARIF Viewer, and Azure DevOps.

### 5. Interactive Dashboard
Self-contained HTML dashboard with live severity donut charts, risk scoring, file-by-file breakdown, and full findings table with JSON/SARIF export.

### 6. Configurable Rules
All detection rules are defined in `secureops_config.yaml` — add custom patterns, change severity levels, target specific file types.

### 7. Path Traversal Protection
All file reads are guarded against directory traversal attacks, ensuring the LLM can't escape the target directory.

### 8. Parallel Scanning
Multi-threaded file scanning with configurable worker pool for fast performance on large codebases.

## Tech Stack

- **Runtime**: Python 3.13+
- **Protocol**: Model Context Protocol (MCP) via FastMCP SDK
- **Analysis**: regex (re module), Python AST (ast module), filename matching
- **Config**: YAML-based rule definitions
- **Output**: JSON, SARIF v2.1.0, Interactive HTML Dashboard
- **Infrastructure**: Docker, docker-compose

## Security Rules (14 rules, 39 patterns)

| Rule | Severity | CWE |
|------|----------|-----|
| Hardcoded API Key / Secret | Critical | CWE-312 |
| Hardcoded Private Key | Critical | CWE-312 |
| Command Injection Risk | Critical | CWE-78 |
| Hardcoded JWT Secret | Critical | CWE-312 |
| Insecure Execution (eval/exec/compile) | High | CWE-95 |
| SQL Injection Risk | High | CWE-89 |
| Insecure Deserialization | High | CWE-502 |
| S3 / Cloud Permission Exposure | High | CWE-732 |
| XSS Vulnerability (Unsafe DOM API) | High | CWE-79 |
| Path Traversal | High | CWE-22 |
| Sensitive File Exposure | High | CWE-530 |
| Debug / Verbose Mode | Medium | CWE-489 |
| Hardcoded Internal / Localhost Address | Medium | CWE-200 |
| Open Redirect | Medium | CWE-601 |

## .env File Detection

SecureOps AI has specialized .env file detection:

- **Filename detection**: .env, .env.local, .env.prod, .env.dev, .env.staging, .env.test
- **Unquoted secret detection**: `DATABASE_URL=postgres://admin:pass@10.0.0.1/db` — no quotes required
- **Quoted value detection**: Standard regex rules also apply to .env content

## Sample Output

Scanning `target_project/` (7 files) produces 19 findings:

```
Critical: 9  │  High: 8  │  Medium: 1  │  Info: 1  │  Risk Score: 73/100

Findings by file:
  .env           → Sensitive File + 2 Unquoted Secrets (DATABASE_URL, GITHUB_TOKEN)
  app.py         → 2 Hardcoded Secrets, Command Injection, eval(), exec(), pickle, yaml
  app.js         → Command Injection, XSS (innerHTML), eval()
  App.java       → Hardcoded DB Password, SQL Injection
  main.go        → Hardcoded API Secret, Command Injection
  main.rs        → Path Traversal
  requirements.txt → Dependency manifest flagged
```

## How to Run

### Option 1: Direct (Python)
```bash
pip install mcp pyyaml
python server.py
```

### Option 2: Docker
```bash
docker compose up
```

The server starts and exposes 5 MCP tools. Connect any MCP-compatible client (Claude Desktop, VS Code MCP extension, etc.) to begin.

### MCP Tools
| Tool | Purpose |
|------|---------|
| `run_local_security_audit` | Full scan with findings + summary |
| `get_audit_summary` | Quick summary (no findings) |
| `run_local_security_audit_sarif` | SARIF-format results |
| `scan_directory_structure` | Tree view of project |
| `read_file_securely` | Read file with traversal protection |

## Use Cases

1. **Pre-commit Security Check**: Run SecureOps AI before every git commit to catch secrets before they hit the repository
2. **CI/CD Pipeline Gate**: Integrate SARIF output into GitHub Actions / GitLab CI for automated PR security checks
3. **Third-Party Code Review**: Audit vendor code before integration without exposing your own infrastructure
4. **Developer Education**: Teams learn secure coding patterns as the LLM explains each finding and suggests fixes
5. **Legacy Codebase Migration**: Scan millions of lines of legacy code to prioritize remediation efforts

## Future Roadmap

- Real-time file watching (watch mode)
- Auto-fix suggestions via LLM
- Semgrep integration for deeper SAST
- Git history scanning for leaked secrets
- VS Code extension with inline annotations
- Team dashboard with trend tracking

## Links

- **GitHub Repository**: [https://github.com/vlex127/secureops-mcp](https://github.com/vlex127/secureops-mcp)
- **Interactive Dashboard**: Open `dashboard.html` in any browser
- **Demo Video**: [Link to YouTube/Loom Demo]

## Team

[Your Team Name]
- [Member 1] — [Role]
- [Member 2] — [Role]
- [Member 3] — [Role]
- [Member 4] — [Role]

---

*Built for Global Tech Innovation 2026 — LLM with MCP + Cybersecurity & Privacy Track*
