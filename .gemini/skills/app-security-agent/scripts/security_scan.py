#!/usr/bin/env python3
"""
App Security Specialist Scanner (security_scan.py)
Automated SAST, Secret Leak, and Security Configuration Audit Tool for Antigravity Projects.
Zero-dependency (runs on standard Python 3.8+).
"""

import os
import sys
import re
import json
from pathlib import Path
import argparse

# Color terminal output (Windows ANSI compatible)
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
BLUE = "\033[94m"
CYAN = "\033[96m"
RESET = "\033[0m"
BOLD = "\033[1m"

# Ignored directories & extensions
IGNORED_DIRS = {
    ".git", "node_modules", "dist", "build", ".next", "__pycache__", 
    ".venv", "venv", ".idea", ".vscode", "coverage", ".tmp"
}

IGNORED_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".webp", ".mp4",
    ".mp3", ".woff", ".woff2", ".ttf", ".eot", ".zip", ".tar", ".gz",
    ".pdf", ".exe", ".dll", ".so", ".dylib", ".pyc"
}

# Regex Patterns for Vulnerability Scans
SECRET_PATTERNS = [
    ("AWS Access Key ID", re.compile(r'(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}')),
    ("Generic Hardcoded API Key", re.compile(r'(?i)(?:api_key|apikey|secret_key|app_secret|auth_token)\s*[:=]\s*["\'][A-Za-z0-9_\-]{16,}["\']')),
    ("OpenAI API Key", re.compile(r'sk-[A-Za-z0-9]{32,}')),
    ("Stripe Live Key", re.compile(r'sk_live_[0-9a-zA-Z]{24}')),
    ("GitHub Personal Access Token", re.compile(r'ghp_[a-zA-Z0-9]{36}')),
    ("Private Key Header", re.compile(r'-----BEGIN (?:RSA|DSA|EC|OPENSSH|PRIVATE) KEY-----')),
    ("Database Connection String with Credentials", re.compile(r'(?:mongodb(?:\+srv)?|postgres|postgresql|mysql)://[^:\s]+:[^@\s]+@[^/\s]+')),
    ("Hardcoded JWT Token", re.compile(r'eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}')),
]

CODE_VULN_PATTERNS = [
    ("DOM XSS - Unsafe innerHTML assignment", re.compile(r'\.innerHTML\s*=\s*(?!\s*["\'][\w\s<>/]*["\'])'), "HIGH"),
    ("DOM XSS - Unsafe outerHTML assignment", re.compile(r'\.outerHTML\s*=\s*(?!\s*["\'][\w\s<>/]*["\'])'), "HIGH"),
    ("DOM XSS - document.write execution", re.compile(r'document\.write\s*\('), "HIGH"),
    ("React Unsafe HTML Injection (dangerouslySetInnerHTML)", re.compile(r'dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:'), "MEDIUM"),
    ("Unsafe Code Execution (eval)", re.compile(r'\beval\s*\('), "HIGH"),
    ("Unsafe Dynamic Function Constructor", re.compile(r'new\s+Function\s*\('), "HIGH"),
    ("Unsafe Dynamic Command Execution (exec/system)", re.compile(r'(?:child_process\.exec|os\.system|subprocess\.Popen)\s*\(\s*f?["\'].*?\+'), "HIGH"),
    ("Insecure Wildcard CORS with Credentials", re.compile(r'(?i)Access-Control-Allow-Origin.*?[\'"]\*[\'"].*?Access-Control-Allow-Credentials.*?true'), "HIGH"),
    ("Insecure HTTP Protocol URL in Production Code", re.compile(r'http://(?:(?!localhost|127\.0\.0\.1|0\.0\.0\.0)[a-zA-Z0-9\-.]+)+(?:/[^\s"\']*)?'), "LOW"),
    ("Unsanitized Direct Body Usage (Potential AI Payload Fuzzing)", re.compile(r'(?:req\.body|request\.json\(\))\s*(?:;|$)'), "LOW"),
]


class SecurityScanner:
    def __init__(self, root_dir):
        self.root_dir = Path(root_dir).resolve()
        self.findings = []
        self.stats = {"scanned_files": 0, "secrets_found": 0, "vulns_found": 0, "config_issues": 0}

    def add_finding(self, category, title, severity, file_path, line_number=None, snippet=None, recommendation=None):
        self.findings.append({
            "category": category,
            "title": title,
            "severity": severity,
            "file": str(Path(file_path).relative_to(self.root_dir) if self.root_dir in Path(file_path).parents or Path(file_path) == self.root_dir else file_path),
            "line": line_number,
            "snippet": snippet.strip() if snippet else None,
            "recommendation": recommendation
        })

    def scan_git_hygiene(self):
        """Audit .gitignore and sensitive configuration tracking."""
        gitignore_path = self.root_dir / ".gitignore"
        env_path = self.root_dir / ".env"
        env_example_path = self.root_dir / ".env.example"

        if env_path.exists():
            if not gitignore_path.exists():
                self.add_finding(
                    "Config Hygiene",
                    "Missing .gitignore file while .env exists",
                    "HIGH",
                    env_path,
                    recommendation="Create a .gitignore file and add '.env' to prevent committing sensitive keys."
                )
                self.stats["config_issues"] += 1
            else:
                content = gitignore_path.read_text(encoding="utf-8", errors="ignore")
                if not re.search(r'^\s*\.env(?:\..*)?\s*$', content, re.MULTILINE):
                    self.add_finding(
                        "Config Hygiene",
                        ".env file is not explicitly listed in .gitignore",
                        "CRITICAL",
                        env_path,
                        recommendation="Add '.env' and '.env.*' to your .gitignore file immediately."
                    )
                    self.stats["config_issues"] += 1

        if env_path.exists() and not env_example_path.exists():
            self.add_finding(
                "Config Hygiene",
                "Missing .env.example template file",
                "LOW",
                self.root_dir,
                recommendation="Create a .env.example template with dummy values so collaborators know required variables safely."
            )
            self.stats["config_issues"] += 1

    def scan_file_contents(self, file_path):
        """Audit file content for secrets and SAST code vulnerabilities."""
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
        except Exception:
            return

        self.stats["scanned_files"] += 1
        rel_path = str(file_path.relative_to(self.root_dir))

        # Do not scan security_scan.py itself for secret patterns to avoid self-reporting
        if "security_scan.py" in rel_path:
            return

        is_markdown = file_path.suffix.lower() in {".md", ".markdown", ".txt"}

        for idx, line in enumerate(lines, start=1):
            # 1. Secret Detection (runs on all non-ignored files)
            for secret_name, pattern in SECRET_PATTERNS:
                if pattern.search(line):
                    self.add_finding(
                        "Secret Leak",
                        f"Potential Hardcoded Secret Detected ({secret_name})",
                        "CRITICAL",
                        file_path,
                        line_number=idx,
                        snippet=line,
                        recommendation="Move secret credentials to environment variables (.env) and access via process.env / os.environ."
                    )
                    self.stats["secrets_found"] += 1

            # 2. Code Vulnerability Detection (skip markdown/doc files to avoid false positives)
            if not is_markdown:
                for vuln_name, pattern, severity in CODE_VULN_PATTERNS:
                    if pattern.search(line):
                        self.add_finding(
                            "Code Vulnerability",
                            vuln_name,
                            severity,
                            file_path,
                            line_number=idx,
                            snippet=line,
                            recommendation="Refactor unsafe pattern. Use safe DOM API (textContent), parameterized queries, or sanitized input."
                        )
                        self.stats["vulns_found"] += 1

    def scan_html_security_headers(self, html_path):
        """Check HTML files for Content-Security-Policy meta tags."""
        try:
            content = html_path.read_text(encoding="utf-8", errors="ignore")
            if "<meta" in content and "http-equiv=\"Content-Security-Policy\"" not in content and "http-equiv='Content-Security-Policy'" not in content:
                self.add_finding(
                    "Security Headers",
                    "Missing Content-Security-Policy (CSP) meta tag in HTML",
                    "MEDIUM",
                    html_path,
                    recommendation="Add a strict CSP meta tag in <head> to prevent unauthorized script execution and XSS attacks."
                )
                self.stats["config_issues"] += 1
        except Exception:
            pass

    def run(self):
        print(f"\n{BOLD}{CYAN}=== Antigravity App Security Specialist Scanner ==={RESET}")
        print(f"Target Directory: {self.root_dir}\n")

        # 1. Scan Git and Config Hygiene
        self.scan_git_hygiene()

        # 2. Iterate Files
        for root, dirs, files in os.walk(self.root_dir):
            # Filter ignored directories
            dirs[:] = [d for d in dirs if d not in IGNORED_DIRS and not d.startswith(".")]

            for file in files:
                file_path = Path(root) / file

                # Check extension
                if file_path.suffix.lower() in IGNORED_EXTENSIONS:
                    continue

                # Run file content scan
                self.scan_file_contents(file_path)

                # HTML security check
                if file_path.suffix.lower() in {".html", ".htm"}:
                    self.scan_html_security_headers(file_path)

        self.print_report()

    def print_report(self):
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        sorted_findings = sorted(self.findings, key=lambda x: severity_order.get(x["severity"], 4))

        critical_count = sum(1 for f in self.findings if f["severity"] == "CRITICAL")
        high_count = sum(1 for f in self.findings if f["severity"] == "HIGH")
        medium_count = sum(1 for f in self.findings if f["severity"] == "MEDIUM")
        low_count = sum(1 for f in self.findings if f["severity"] == "LOW")

        print(f"{BOLD}--- Security Findings Summary ---{RESET}")
        print(f"Scanned Files: {self.stats['scanned_files']}")
        print(f"Total Findings: {len(self.findings)} ("
              f"{RED}Critical: {critical_count}{RESET}, "
              f"{YELLOW}High: {high_count}{RESET}, "
              f"{BLUE}Medium: {medium_count}{RESET}, "
              f"Low: {low_count})\n")

        if not sorted_findings:
            print(f"{GREEN}{BOLD}[OK] No security vulnerabilities or secret leaks detected! Excellent security posture.{RESET}\n")
            return

        for finding in sorted_findings:
            sev = finding["severity"]
            color = RED if sev in {"CRITICAL", "HIGH"} else (YELLOW if sev == "MEDIUM" else BLUE)
            print(f"[{color}{sev}{RESET}] {BOLD}{finding['title']}{RESET}")
            print(f"  Category: {finding['category']}")
            print(f"  File: {finding['file']}" + (f":{finding['line']}" if finding['line'] else ""))
            if finding['snippet']:
                print(f"  Snippet: {CYAN}{finding['snippet']}{RESET}")
            if finding['recommendation']:
                print(f"  Fix: {finding['recommendation']}")
            print("-" * 60)

        # Output JSON report for automated tools if requested
        report_path = self.root_dir / ".gemini" / "security_report.json"
        try:
            report_path.parent.mkdir(parents=True, exist_ok=True)
            with open(report_path, "w", encoding="utf-8") as f:
                json.dump({
                    "summary": self.stats,
                    "findings": self.findings
                }, f, indent=2)
            print(f"\n{CYAN}Detailed report saved to: {report_path.relative_to(self.root_dir)}{RESET}\n")
        except Exception:
            pass

def main():
    if hasattr(sys.stdout, 'reconfigure'):
        try:
            sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        except Exception:
            pass

    parser = argparse.ArgumentParser(description="Antigravity App Security Specialist Scanner")
    parser.add_argument("target", nargs="?", default=".", help="Target directory to scan (default: current directory)")
    args = parser.parse_args()

    scanner = SecurityScanner(args.target)
    scanner.run()

if __name__ == "__main__":
    main()
