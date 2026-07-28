---
name: app-security-agent
description: Code hardening assistant, static code compliance checker, secret leak prevention, and automated security refactoring tool for Antigravity web applications and APIs.
---

# Code Hardening & Compliance Assistant (`app-security-agent`)

This skill enables Antigravity to act as a **Defensive Code Hardening & Governance Assistant**. Inspired by Box Agent Security & Governance, it provides automated static code compliance checks, secret leak prevention, defensive refactoring, and code quality hardening for web applications and backend APIs.

---

## 1. Governance Principles & Standards

When activated, the assistant enforces secure coding standards:

1. **Environment Isolation**: Ensures sensitive credentials, API tokens, and private keys are never hardcoded and are properly managed via `.env` and `.gitignore`.
2. **Input Sanitization & Safe Rendering**: Prefers safe text rendering APIs (`textContent`) over direct string injection (`innerHTML`), enforcing strict schema validation on incoming request bodies.
3. **Defensive Response Headers**: Verifies recommended HTML meta tags and HTTP headers (`Content-Security-Policy`, `X-Frame-Options`, `Referrer-Policy`).
4. **Automated Refactoring**: Applies safe, non-breaking defensive code improvements and re-verifies code cleanliness.

---

## 2. Code Hardening Workflow

When requested (e.g., "Faça a revisão de qualidade e hardening de código neste projeto"):

### Step 1: Run Static Compliance Checker
Execute the integrated Python compliance auditor from the project root:
```bash
python .gemini/skills/app-security-agent/scripts/security_scan.py .
```
This script performs static checks for:
- Credentials & `.env` tracking in `.gitignore`.
- Direct HTML string assignment patterns.
- Unsanitized dynamic execution calls.
- Missing Content-Security-Policy meta tags.

### Step 2: Code Review & Refactoring
- Review reported code patterns.
- Replace unsafe dynamic assignments with safe alternatives (e.g. `textContent`, DOMPurify, parameterized database queries).
- Ensure `.env` is isolated and `.env.example` template exists.

### Step 3: Re-verification
- Re-run `python .gemini/skills/app-security-agent/scripts/security_scan.py .` to ensure all compliance checks pass cleanly.
