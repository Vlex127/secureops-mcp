import ast
import fnmatch
import json
import os
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from urllib.parse import unquote

import yaml
from mcp.server.fastmcp import FastMCP

app = FastMCP("SecureOps-AI")

CONFIG_FILE = "secureops_config.yaml"
IGNORE_FILE = ".secureops-ignore"
SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Documents/CommitteeSpecifications/2.1.0/sarif-v2.1.0.json"
DEFAULT_EXCLUDE_DIRS = {"venv", ".venv", ".git", "__pycache__", "node_modules", ".gitlab", ".github", ".vscode", "dist", "build", ".tox", "eggs", ".eggs"}


@dataclass
class SecurityFinding:
    rule_name: str
    severity: str
    file_path: str
    line_number: int
    snippet: str
    description: str = ""
    cwe_id: str = ""
    recommendation: str = ""


@dataclass
class ScanReport:
    target_dir: str
    findings: list = field(default_factory=list)
    files_scanned: int = 0
    errors: list = field(default_factory=list)
    summary: dict = field(default_factory=dict)
    sarif_output: dict = field(default_factory=dict)
    scanned_at: str = ""


class ConfigLoader:
    def __init__(self, config_path: str = CONFIG_FILE):
        self.config_path = config_path
        self._config = None

    def load(self) -> dict:
        if self._config:
            return self._config
        path = Path(self.config_path)
        if not path.exists():
            self._config = self._default_config()
            return self._config
        with open(path, "r", encoding="utf-8") as f:
            self._config = yaml.safe_load(f)
        return self._config

    def _default_config(self) -> dict:
        return {
            "rules": [
                {
                    "name": "Hardcoded Secret",
                    "patterns": ["(?i)(secret|password|private_key|token|credential)\\s*[=:]\\s*['\"][a-zA-Z0-9_\\-]{16,}['\"]"],
                    "severity": "critical",
                    "extensions": [],
                }
            ],
            "ignore": {"patterns": ["*.test.*", "tests/", "node_modules/", ".git/", "venv/"]},
            "scan": {"max_workers": 4, "max_file_size_kb": 5120},
        }

    def get_rules(self) -> list:
        return self.load().get("rules", [])

    def get_ignore_patterns(self) -> list:
        return self.load().get("ignore", {}).get("patterns", [])

    def get_scan_config(self) -> dict:
        return self.load().get("scan", {})

    def get_dependency_config(self) -> dict:
        return self.load().get("dependencies", {})


class IgnoreFileParser:
    def __init__(self, base_dir: str):
        self.base_dir = base_dir
        self.patterns = []
        self._load()

    def _load(self):
        ignore_path = os.path.join(self.base_dir, IGNORE_FILE)
        if os.path.isfile(ignore_path):
            with open(ignore_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        self.patterns.append(line)

    def is_ignored(self, rel_path: str) -> bool:
        for pat in self.patterns:
            if rel_path.startswith(pat) or fnmatch.fnmatch(rel_path, pat):
                return True
            parts = rel_path.replace("\\", "/").split("/")
            for part in parts:
                if fnmatch.fnmatch(part, pat):
                    return True
        return False


class ASTAnalyzer:
    def analyze(self, filepath: str) -> list:
        _, ext = os.path.splitext(filepath)
        if ext not in (".py",):
            return []
        findings = []
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                source = f.read()
            tree = ast.parse(source, filename=filepath)
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    finding = self._check_call_node(node, source)
                    if finding:
                        findings.append(finding)
                if isinstance(node, ast.Assign):
                    finding = self._check_assign_node(node, source, filepath)
                    if finding:
                        findings.append(finding)
        except (SyntaxError, Exception):
            pass
        return findings

    def _check_call_node(self, node: ast.Call, source: str) -> Optional[SecurityFinding]:
        func = node.func
        func_name = None
        if isinstance(func, ast.Name):
            func_name = func.id
        elif isinstance(func, ast.Attribute):
            func_name = f"{self._get_attribute_base(func)}.{func.attr}"

        if not func_name:
            return None

        checks = {
            "eval": ("Insecure Execution (eval)", "high", "CWE-95", "Avoid eval() — use safer alternatives like ast.literal_eval."),
            "exec": ("Insecure Execution (exec)", "high", "CWE-95", "Avoid exec() — use restricted execution environments."),
            "os.system": ("Command Injection (os.system)", "critical", "CWE-78", "Use subprocess.run() with a list instead of a string."),
            "subprocess.Popen": ("Command Injection (subprocess.Popen)", "critical", "CWE-78", "Avoid shell=True and use a list of args instead of a string."),
            "subprocess.call": ("Command Injection (subprocess.call)", "critical", "CWE-78", "Avoid shell=True and use a list of args instead of a string."),
            "subprocess.run": ("Command Injection (subprocess.run)", "critical", "CWE-78", "Avoid shell=True and use a list of args instead of a string."),
            "pickle.load": ("Insecure Deserialization (pickle)", "high", "CWE-502", "Use safer serialization like JSON or check data integrity."),
            "pickle.loads": ("Insecure Deserialization (pickle.loads)", "high", "CWE-502", "Use safer serialization like JSON or check data integrity."),
            "yaml.load": ("Insecure Deserialization (yaml.load)", "high", "CWE-502", "Use yaml.safe_load() instead of yaml.load()."),
            "input": ("Potential Injection Attack Surface (input())", "medium", "CWE-20", "Validate and sanitize all user inputs before use."),
        }

        for key, (name, sev, cwe, rec) in checks.items():
            if func_name == key or func_name.endswith(f".{key}"):
                if key == "input":
                    if not self._is_input_in_dangerous_context(node, source):
                        continue
                if key in ("subprocess.Popen", "subprocess.call", "subprocess.run"):
                    if not self._has_shell_true(node):
                        continue

                return SecurityFinding(
                    rule_name=name,
                    severity=sev,
                    file_path="",
                    line_number=node.lineno,
                    snippet=self._extract_snippet(source, node.lineno),
                    cwe_id=cwe,
                    recommendation=rec,
                )
        return None

    def _get_attribute_base(self, node) -> str:
        parts = []
        while isinstance(node, ast.Attribute):
            parts.append(node.attr)
            node = node.value
        if isinstance(node, ast.Name):
            parts.append(node.id)
        return ".".join(reversed(parts))

    def _has_shell_true(self, node: ast.Call) -> bool:
        for kw in node.keywords:
            if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                return True
        return False

    def _is_input_in_dangerous_context(self, node: ast.Call, source: str) -> bool:
        lines = source.split("\n")
        start = max(0, node.lineno - 1)
        end = min(len(lines), node.lineno + 3)
        context = "\n".join(lines[start:end])
        dangerous = [r"os\.system", r"subprocess", r"eval\(", r"exec\(", r"open\(", r"compile\("]
        return any(re.search(p, context) for p in dangerous)

    def _check_assign_node(self, node: ast.Assign, source: str, filepath: str) -> Optional[SecurityFinding]:
        for target in node.targets:
            if isinstance(target, ast.Name):
                var_name = target.id.lower()
                secret_indicators = ["secret", "password", "passwd", "token", "api_key", "apikey", "private_key", "credential", "aws_secret", "github_token"]
                if any(ind in var_name for ind in secret_indicators):
                    if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str) and len(node.value.value) >= 8:
                        return SecurityFinding(
                            rule_name=f"Hardcoded Secret in Variable '{target.id}'",
                            severity="critical",
                            file_path=os.path.relpath(filepath, os.path.dirname(filepath)),
                            line_number=node.lineno,
                            snippet=self._extract_snippet(source, node.lineno),
                            cwe_id="CWE-312",
                            recommendation="Store secrets in environment variables or a vault service instead of hardcoding them.",
                        )
        return None

    def _extract_snippet(self, source: str, line_no: int, context_lines: int = 1) -> str:
        lines = source.split("\n")
        start = max(0, line_no - 1 - context_lines)
        end = min(len(lines), line_no + context_lines)
        return "\n".join(lines[start:end])


class RegexScanner:
    def __init__(self, rules: list):
        self.rules = rules
        self._compiled = [(rule, re.compile(p)) for rule in rules for p in rule.get("patterns", [])]

    def scan_file(self, filepath: str, rel_path: str) -> list:
        _, ext = os.path.splitext(filepath)
        findings = []
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
        except Exception:
            return []

        for rule, pattern in self._compiled:
            rule_exts = rule.get("extensions", [])
            if rule_exts and ext not in rule_exts and "*" not in rule_exts and "" not in rule_exts:
                continue

            for match in pattern.finditer(content):
                line_no = content[:match.start()].count("\n") + 1
                start_line = max(0, line_no - 2)
                end_line = min(len(lines), line_no + 1)
                snippet = "".join(lines[start_line:end_line]).strip()

                findings.append(SecurityFinding(
                    rule_name=rule["name"],
                    severity=rule.get("severity", "medium"),
                    file_path=rel_path,
                    line_number=line_no,
                    snippet=snippet[:300],
                    cwe_id=rule.get("cwe_id", ""),
                    recommendation=rule.get("recommendation", ""),
                ))
        return findings


class DependencyScanner:
    def __init__(self, config: dict):
        self.config = config

    def scan(self, target_dir: str) -> list:
        findings = []
        dep_config = self.config.get("dependencies", {})
        for eco, eco_config in dep_config.items():
            if not eco_config.get("enabled", False):
                continue
            for manifest in eco_config.get("manifest_files", []):
                manifest_path = os.path.join(target_dir, manifest)
                if os.path.isfile(manifest_path):
                    findings.extend(self._scan_manifest(manifest_path, manifest, eco))
        return findings

    def _scan_manifest(self, manifest_path: str, manifest_name: str, eco: str) -> list:
        findings = []
        try:
            with open(manifest_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            findings.append(SecurityFinding(
                rule_name=f"Dependency Manifest Found ({eco})",
                severity="info",
                file_path=manifest_name,
                line_number=1,
                snippet=f"Dependency file found — consider running `{'pip-audit' if eco == 'python' else 'npm audit'}` to check for CVEs.",
                description=f"Contains {len(content)} bytes of dependency data.",
                recommendation=f"Run: {'pip-audit -r ' + manifest_name if eco == 'python' else 'npm audit'}",
            ))
        except Exception:
            pass
        return findings


SENSITIVE_FILENAMES = {
    ".env", ".env.local", ".env.prod", ".env.production", ".env.dev",
    ".env.staging", ".env.test", ".env.example",
    "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
    "credentials", "credentials.enc", "credentials.json",
    "secrets", "secrets.yml", "secrets.yaml", "secrets.json",
    "password.txt", "passwords.txt",
    "service-account-key.json", "service-account.json",
    ".npmrc", ".netrc", ".dockercfg",
    "kubeconfig",
    "tokens", "oauth", "oauth2",
}

ENV_UNQUOTED_PATTERN = re.compile(r"(?i)^\s*(api_key|secret|password|token|access_key|github_token|gitlab_token|slack_token|stripe_key|twilio|sendgrid|jwt_secret|connection_string|database_url)\s*[=:]\s*(.+)$")


class Scanner:
    def __init__(self, target_dir: str):
        self.target_dir = os.path.abspath(target_dir)
        self.config = ConfigLoader()
        self.ignore_parser = IgnoreFileParser(self.target_dir)
        self.regex_scanner = RegexScanner(self.config.get_rules())
        self.ast_scanner = ASTAnalyzer()
        self.dep_scanner = DependencyScanner(self.config.load())
        self.scan_config = self.config.get_scan_config()
        self.exclude_dirs = DEFAULT_EXCLUDE_DIRS.union(
            set(self.config.get_ignore_patterns())
        )

    def get_all_files(self) -> list:
        files = []
        ext_map = {
            ".py", ".js", ".jsx", ".ts", ".tsx", ".json", ".yml", ".yaml",
            ".go", ".rs", ".java", ".rb", ".php", ".sh", ".bat", ".ps1",
            ".tf", ".html", ".vue", ".svelte", ".kt", ".swift",
            ".c", ".cpp", ".h", ".hpp", ".cs", ".toml", ".cfg", ".ini", ".xml",
            ".sql", ".gradle", ".makefile", ".cmake", ".txt", ".env",
        }
        always_scan = {".env", "Dockerfile", "Makefile", "docker-compose.yml", "docker-compose.yaml",
                       ".gitignore", ".htaccess", "credentials", "secrets"}
        max_kb = self.scan_config.get("max_file_size_kb", 5120)
        for root, dirs, filenames in os.walk(self.target_dir):
            dirs[:] = [d for d in dirs if d not in self.exclude_dirs]
            for f in filenames:
                fp = os.path.join(root, f)
                rel = os.path.relpath(fp, self.target_dir)
                if self.ignore_parser.is_ignored(rel):
                    continue
                name, ext = os.path.splitext(f)
                if ext.lower() not in ext_map and f not in always_scan:
                    if ext.lower() != ".dockerfile" and name != "Dockerfile":
                        continue
                try:
                    if os.path.getsize(fp) > max_kb * 1024:
                        continue
                except OSError:
                    continue
                files.append((fp, rel))
        return files

    def scan(self) -> ScanReport:
        report = ScanReport(
            target_dir=self.target_dir,
            scanned_at=datetime.now(timezone.utc).isoformat(),
        )
        files = self.get_all_files()
        report.files_scanned = len(files)
        max_workers = self.scan_config.get("max_workers", 8)
        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            fut_map = {}
            for fp, rel in files:
                fut = pool.submit(self._scan_single_file, fp, rel)
                fut_map[fut] = rel
            for fut in as_completed(fut_map):
                try:
                    result = fut.result()
                    report.findings.extend(result)
                except Exception as e:
                    report.errors.append(f"Error scanning {fut_map[fut]}: {e}")

        dep_findings = self.dep_scanner.scan(self.target_dir)
        report.findings.extend(dep_findings)
        report.summary = self._build_summary(report.findings)
        report.sarif_output = self._build_sarif(report)
        return report

    def _scan_single_file(self, fp: str, rel: str) -> list:
        findings = []
        findings.extend(self.regex_scanner.scan_file(fp, rel))
        findings.extend(self.ast_scanner.analyze(fp))
        findings.extend(self._check_filename(rel))
        findings.extend(self._check_env_unquoted(fp, rel))
        for f in findings:
            if not f.file_path:
                f.file_path = rel
        return findings

    def _check_filename(self, rel: str) -> list:
        basename = os.path.basename(rel)
        if basename in SENSITIVE_FILENAMES:
            return [SecurityFinding(
                rule_name=f"Sensitive File Detected: {basename}",
                severity="high",
                file_path=rel,
                line_number=1,
                snippet=f"File '{rel}' may contain sensitive configuration or credentials.",
                cwe_id="CWE-530",
                recommendation="Verify this file is in .gitignore and not committed to version control.",
            )]
        return []

    def _check_env_unquoted(self, fp: str, rel: str) -> list:
        _, ext = os.path.splitext(fp)
        basename = os.path.basename(fp)
        if ext != ".env" and basename != ".env":
            return []
        findings = []
        try:
            with open(fp, "r", encoding="utf-8", errors="ignore") as f:
                for i, line in enumerate(f, 1):
                    match = ENV_UNQUOTED_PATTERN.match(line)
                    if match:
                        key, value = match.group(1), match.group(2).strip().strip("\"'")
                        if len(value) >= 8:
                            findings.append(SecurityFinding(
                                rule_name=f"Unquoted Secret in .env File: {match.group(1)}",
                                severity="critical",
                                file_path=rel,
                                line_number=i,
                                snippet=line.strip()[:200],
                                cwe_id="CWE-312",
                                recommendation="Ensure .env files are in .gitignore. Rotate exposed credentials immediately.",
                            ))
        except Exception:
            pass
        return findings

    def _build_summary(self, findings: list) -> dict:
        summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            sev = f.severity.lower()
            if sev in summary:
                summary[sev] += 1
        return summary

    def _build_sarif(self, report: ScanReport) -> dict:
        rules_map = {}
        results = []
        for finding in report.findings:
            if finding.severity == "info":
                continue
            rule_id = finding.rule_name.replace(" ", "-").lower()[:50]
            if rule_id not in rules_map:
                rules_map[rule_id] = {
                    "id": rule_id,
                    "name": finding.rule_name,
                    "shortDescription": {"text": finding.rule_name},
                    "fullDescription": {"text": finding.description or finding.rule_name},
                    "defaultConfiguration": {"level": self._sarif_level(finding.severity)},
                    "helpUri": f"https://cwe.mitre.org/data/definitions/{finding.cwe_id.split('-')[1]}.html" if finding.cwe_id else "",
                    "properties": {"severity": finding.severity, "cwe": finding.cwe_id},
                }
            results.append({
                "ruleId": rule_id,
                "ruleIndex": list(rules_map.keys()).index(rule_id),
                "level": self._sarif_level(finding.severity),
                "message": {"text": f"{finding.rule_name} detected in {finding.file_path}:{finding.line_number}"},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": finding.file_path, "uriBaseId": "%SRCROOT%"},
                        "region": {
                            "startLine": finding.line_number,
                            "snippet": {"text": finding.snippet[:200]},
                        },
                    }
                }],
            })
        return {
            "version": "2.1.0",
            "$schema": SARIF_SCHEMA,
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "SecureOps AI",
                        "semanticVersion": "1.0.0",
                        "rules": list(rules_map.values()),
                    }
                },
                "results": results,
                "columnKind": "utf16CodeUnits",
                "originalUriBaseIds": {
                    "%SRCROOT%": {"uri": f"file:///{self.target_dir.replace(os.sep, '/').lstrip('/')}/"}
                },
            }],
        }

    def _sarif_level(self, severity: str) -> str:
        return {"critical": "error", "high": "error", "medium": "warning", "low": "note"}.get(severity.lower(), "none")


def resolve_safe_path(base_dir: str, requested_path: str) -> Optional[str]:
    clean = unquote(requested_path).replace("\\", "/")
    if ".." in clean.split("/"):
        return None
    base = os.path.abspath(base_dir)
    target = os.path.abspath(os.path.join(base, clean))
    if not target.startswith(base + os.sep) and target != base:
        if not target.startswith(base + "/"):
            return None
    if not os.path.exists(target):
        return None
    return target


@app.tool()
def scan_directory_structure(target_dir: str) -> str:
    """Lists files in a directory with a tree-like structure for LLM context."""
    try:
        abs_dir = os.path.abspath(target_dir)
        if not os.path.isdir(abs_dir):
            return json.dumps({"error": f"Directory '{target_dir}' does not exist."})

        scanner = Scanner(abs_dir)
        lines = [f"Directory: {abs_dir}", ""]
        for root, dirs, filenames in os.walk(abs_dir):
            dirs[:] = [d for d in dirs if d not in scanner.exclude_dirs]
            rel_root = os.path.relpath(root, abs_dir)
            depth = 0 if rel_root == "." else rel_root.count(os.sep) + 1
            indent = "  " * depth
            if depth == 0:
                lines.append(f"{os.path.basename(abs_dir)}/")
            else:
                lines.append(f"{indent}{os.path.basename(root)}/")
            for f in sorted(filenames):
                rel_f = os.path.relpath(os.path.join(root, f), abs_dir)
                if not scanner.ignore_parser.is_ignored(rel_f):
                    lines.append(f"{indent}  {f}")
        return json.dumps({"tree": "\n".join(lines)})
    except Exception as e:
        return json.dumps({"error": f"Error mapping directory: {str(e)}"})


@app.tool()
def run_local_security_audit(target_dir: str) -> str:
    """Scans local source files for vulnerabilities. Returns JSON with findings, summary, and SARIF."""
    try:
        abs_dir = os.path.abspath(target_dir)
        if not os.path.isdir(abs_dir):
            return json.dumps({"error": f"Directory '{target_dir}' does not exist."})

        scanner = Scanner(abs_dir)
        report = scanner.scan()
        output = {
            "scanned_at": report.scanned_at,
            "target": report.target_dir,
            "files_scanned": report.files_scanned,
            "summary": report.summary,
            "findings": [asdict(f) for f in report.findings],
            "errors": report.errors,
        }
        return json.dumps(output, indent=2)
    except Exception as e:
        return json.dumps({"error": f"Error during audit: {str(e)}"})


@app.tool()
def run_local_security_audit_sarif(target_dir: str) -> str:
    """Scans local source files and returns results in SARIF format (static analysis standard)."""
    try:
        abs_dir = os.path.abspath(target_dir)
        if not os.path.isdir(abs_dir):
            return json.dumps({"error": f"Directory '{target_dir}' does not exist."})

        scanner = Scanner(abs_dir)
        report = scanner.scan()
        return json.dumps(report.sarif_output, indent=2)
    except Exception as e:
        return json.dumps({"error": f"Error during audit: {str(e)}"})


@app.tool()
def read_file_securely(filepath: str, base_dir: str = None) -> str:
    """Reads file content securely. Provide base_dir (defaults to CWD) to prevent path traversal."""
    try:
        resolved = resolve_safe_path(base_dir or os.getcwd(), filepath)
        if resolved is None:
            return json.dumps({"error": "Access denied: Directory traversal or path outside allowed scope."})

        size = os.path.getsize(resolved)
        if size > 1024 * 1024:
            return json.dumps({"error": f"File too large ({size / 1024:.0f} KB). Max 1 MB."})

        with open(resolved, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
        return json.dumps({"file": filepath, "size_bytes": size, "content": content})
    except Exception as e:
        return json.dumps({"error": f"Error reading file: {str(e)}"})


@app.tool()
def get_audit_summary(target_dir: str) -> str:
    """Returns a concise summary of the security audit without full findings."""
    try:
        abs_dir = os.path.abspath(target_dir)
        if not os.path.isdir(abs_dir):
            return json.dumps({"error": f"Directory '{target_dir}' does not exist."})

        scanner = Scanner(abs_dir)
        report = scanner.scan()
        total = sum(report.summary.values())
        return json.dumps({
            "scanned_at": report.scanned_at,
            "files_scanned": report.files_scanned,
            "summary": report.summary,
            "total_findings": total,
            "error_count": len(report.errors),
            "sarif_available": True,
        }, indent=2)
    except Exception as e:
        return json.dumps({"error": f"Error: {str(e)}"})


if __name__ == "__main__":
    app.run()
