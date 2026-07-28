# Application Security Governance & Hardening Standard

This document establishes the defensive security standards and security hardening guidelines for web applications, APIs, and microservices built within Antigravity.

---

## 1. HTTP Security Headers Standard

All web servers, Express/Node.js backend applications, Python services (FastAPI/Flask), and HTML index pages MUST configure defensive HTTP response headers:

### Standard Header Configuration
- **Content-Security-Policy (CSP)**:
  `default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; img-src 'self' data: https:; font-src 'self' https://fonts.gstatic.com; connect-src 'self' https:; object-src 'none'; base-uri 'self';`
- **X-Frame-Options**: `DENY` (or `SAMEORIGIN` if iFraming is required within the same domain).
- **X-Content-Type-Options**: `nosniff`
- **Referrer-Policy**: `strict-origin-when-cross-origin`
- **Permissions-Policy**: `camera=(), microphone=(), geolocation=(), payment=()`
- **Strict-Transport-Security (HSTS)**: `max-age=31536000; includeSubDomains; preload` (for HTTPS production endpoints).

### HTML `<head>` CSP Fallback Tag
For static HTML / Single Page Apps (SPA) where response headers cannot be modified directly:
```html
<meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data: https:; connect-src 'self' https:; object-src 'none';">
```

---

## 2. CORS (Cross-Origin Resource Sharing) Governance

- **NEVER** combine `Access-Control-Allow-Origin: *` with `Access-Control-Allow-Credentials: true`.
- Maintain an explicit whitelist of authorized domain origins.
- Example (Express.js):
```javascript
const allowedOrigins = ['https://myapp.com', 'https://admin.myapp.com'];
app.use(cors({
  origin: function (origin, callback) {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('CORS Policy Violation'));
    }
  },
  credentials: true
}));
```

---

## 3. Secret Management & Credential Governance

- **Zero Hardcoded Secrets Rule**: Secrets (API keys, JWT secrets, database connection URLs, OAuth client secrets) MUST NEVER be written directly in tracked source code files (`.js`, `.ts`, `.py`, `.json`, `.html`).
- **`.env` File Isolation**:
  - Always add `.env`, `.env.local`, and `*.pem` to `.gitignore`.
  - Provide a safe `.env.example` file containing key names with empty or placeholder values (e.g. `OPENAI_API_KEY=your_key_here`).
- **Runtime Access**:
  - Node.js: `process.env.API_KEY`
  - Python: `os.getenv("API_KEY")`

---

## 4. Input Sanitization & Anti-XSS Practices

### DOM XSS Prevention
- Avoid assigning unsanitized dynamic strings to `element.innerHTML`, `element.outerHTML`, `document.write()`, or `eval()`.
- Use `element.textContent` or `element.innerText` for safe plain text node insertion.
- If rich HTML parsing is required, pass user input through a trusted sanitization library (such as `DOMPurify`):
```javascript
import DOMPurify from 'dompurify';
const cleanHTML = DOMPurify.sanitize(userProvidedString);
element.innerHTML = cleanHTML;
```

### SQL & NoSQL Injection Prevention
- Use parameterized queries or Object Relational Mapping (ORM) query builders (e.g., Prisma, Drizzle, SQLAlchemy).
- Never concatenate raw request parameters directly into database queries:
```javascript
// ❌ WRONG (Vulnerable to SQLi)
db.query(`SELECT * FROM users WHERE email = '${req.body.email}'`);

// ✅ CORRECT (Parameterized Query)
db.query('SELECT * FROM users WHERE email = $1', [req.body.email]);
```

---

## 5. Authentication & JWT Storage

- **Storage**: Prefer storing session tokens or access tokens in **`HttpOnly`, `Secure`, `SameSite=Strict`** cookies rather than `localStorage` or `sessionStorage` (which are accessible via XSS scripts).
- **Expiration**: Keep JWT access tokens short-lived (e.g. 15 to 60 minutes) and use secure refresh token rotation.
- **CSRF Protection**: When using cookie-based authentication, implement Anti-CSRF double-submit cookies or custom header checks (`X-Requested-With` or `Anti-CSRF-Token`).

---

## 6. Security Incident Response & Audit Logging

- **Logging**: Log security-relevant events (failed authentication attempts, privilege escalation attempts, validation failures) with timestamp, IP, and event type.
- **Sanitized Logs**: Never output sensitive data (passwords, complete credit card numbers, JWT signature tokens) into application log files.

---

## 7. AI-Driven Attack & "Vibe Coding" Security Hardening

As attackers increasingly use LLMs and automated AI agents to discover vulnerabilities, generate context-aware exploit payloads, and perform high-speed brute-forcing, applications MUST implement strict boundary defenses:

### A. Rate Limiting & Anti-Automation Shields
- Protect all public endpoints and authentication APIs against AI-automated high-speed requests:
```javascript
// Express rate limiter example
import rateLimit from 'express-rate-limit';

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
  message: { error: 'Too many requests, please try again later.' }
});

app.use('/api/', apiLimiter);
```

### B. Strict Schema Validation (Defense against AI Payload Fuzzing)
- Reject non-conforming or unexpected JSON shapes before business logic processing using strict validation schemas (e.g. Zod, Pydantic):
```typescript
import { z } from 'zod';

const UserInputSchema = z.object({
  username: z.string().alphanumeric().min(3).max(30),
  email: z.string().email(),
  age: z.number().int().positive().max(120),
}).strict(); // .strict() rejects unexpected AI-injected parameters
```

### C. AI Agent & Prompt Injection Protections (For apps integrating LLMs)
- **Input Sanitization**: Treat user input inside AI prompts as untrusted data. Wrap user inputs in explicit delimiters (e.g. `<user_input>...</user_input>`).
- **Output Validation**: Never execute AI model responses directly as raw code or database queries without strict structural validation.
- **Privilege Scoping**: Limit what internal tools or APIs the AI agent can execute.

