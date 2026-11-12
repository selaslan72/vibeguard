<div align="center">
  <img src="assets/logo.svg" alt="VibeGuard Logo" width="110" height="110" />
  <h1>VibeGuard</h1>
  <p><strong>AI Security & Internal Audit Skill for Vibe-Coded Projects</strong></p>
  <p>Scan your codebase for external vulnerabilities, leaked secrets, access-control flaws, BaaS misconfigurations, AI/LLM risks, and internal security gaps — presented in one clear, prioritized table.</p>
</div>

---

## Why VibeGuard?

Most vibe-coded apps move fast from prompt to production — and silently ship with:
- `NEXT_PUBLIC_` or `VITE_` exposed secrets and committed `.env` files
- Unprotected Next.js Server Actions, API routes, and missing IDOR ownership checks
- Open Firebase rules (`if true`) or Supabase tables missing Row-Level Security (RLS)
- Unverified Stripe webhooks and client-trusted prices/roles
- Prompt injection, unauthenticated AI proxy routes, and unsafe LLM output sinks
- Internal security gaps: hardcoded dev/admin bypasses, PII/secret logging, debug backdoors, risky GitHub Actions, and `root` Docker containers

**VibeGuard** combines a **zero-dependency deterministic static scanner** with a **deep contextual AI audit workflow** so any developer can audit their repository in seconds and review every issue in a single actionable table.

---

## Quick Installation

### Option 1: Universal Agent Skills CLI (`npx skills`)
Works with Antigravity, Claude Code, Cursor, Codex, OpenCode, and GitHub Copilot:

```bash
npx skills add selaslan72/vibeguard
```

### Option 2: Google Antigravity Plugin (`agy`)
```bash
agy plugin install https://github.com/selaslan72/vibeguard.git
```
Or clone directly into your global Antigravity plugins directory:
```bash
git clone https://github.com/selaslan72/vibeguard.git ~/.gemini/config/plugins/vibeguard
```

### Option 3: Project-Local Installation
Copy `skills/vibeguard` into your project's `.agents/skills/vibeguard` (Antigravity) or `.claude/skills/vibeguard` directory:
```bash
mkdir -p .agents/skills
git clone --depth 1 https://github.com/selaslan72/vibeguard.git /tmp/vibeguard
cp -R /tmp/vibeguard/skills/vibeguard .agents/skills/vibeguard
```

---

## How to Use

Once installed, ask your AI coding assistant:

> `"Run VibeGuard security audit on this project and show all vulnerabilities in a table."`

> `"Perform an external and internal security check before we deploy."`

### Standalone CLI Usage (No AI Required)
You can also run the deterministic scanner directly in any terminal or CI pipeline using Python 3.9+ (zero external dependencies):

```bash
# Print a full Markdown Security Report & Vulnerability Table
python3 skills/vibeguard/scripts/security_scan.py --path . --format markdown

# Output structured JSON (used by the AI skill for Phase 2 deep audit)
python3 skills/vibeguard/scripts/security_scan.py --path . --format json

# Include npm audit / pip-audit checks and fail CI on HIGH or CRITICAL findings
python3 skills/vibeguard/scripts/security_scan.py --path . --format markdown --run-ecosystem-audits --fail-on HIGH
```

---

## What VibeGuard Audits (Two-Phase Hybrid Engine)

### Phase 1: Deterministic Static & Internal Scan (`security_scan.py`)
- **Secrets & Credential Hygiene**: OpenAI, Anthropic, Google/Gemini, AWS, GitHub, Stripe, Slack, SendGrid, private keys, DB URIs, `NEXT_PUBLIC_`/`VITE_` secret exposure, git-tracked `.env` or key files, missing `.gitignore` rules.
- **Injection & Code Safety**: SQL injection (`$queryRawUnsafe`, string-concat queries), OS command injection (`exec`, `shell=True`), XSS (`dangerouslySetInnerHTML`, `innerHTML`, `v-html`), `eval`/`new Function`, unsafe `pickle`/`yaml.load`/SSTI.
- **Auth, Crypto & APIs**: Hardcoded fallback JWT secrets, unverified `jwt.decode()`, disabled TLS checks, weak RNG/hashing, `httpOnly: false`, wildcard CORS + credentials, Python `DEBUG = True`.
- **Internal Security Controls**: Client-side `service_role` / `firebase-admin` imports, Firebase `if true` rules, Supabase tables missing `ENABLE ROW LEVEL SECURITY` or `USING (true)` policies, mass assignment (`req.body` spread), hardcoded admin bypasses, PII/token logging, stack trace leaks, debug/seed endpoints.
- **AI / LLM & Infrastructure**: System prompt interpolation, LLM output executed in dangerous sinks, GitHub Actions script injection (`pull_request_target`, `${{ github.event.* }}`), `write-all` permissions, `Dockerfile` running as root or leaking secrets in `ENV`, `privileged: true` containers, missing lockfiles.

### Phase 2: Contextual AI Security Audit
Guided by [audit-checklist.md](skills/vibeguard/references/audit-checklist.md) and [vibecoding-traps.md](skills/vibeguard/references/vibecoding-traps.md), the agent inspects `audit_surfaces` indexed by Phase 1 to catch contextual flaws regexes cannot see:
- Unauthenticated Next.js Server Actions, API routes, and middleware matcher bypasses
- IDOR / BOLA (queries missing `userId` / tenant scoping)
- Client-trusted prices, plan tiers, or roles & unverified payment webhooks
- Race conditions (TOCTOU) in credits/balances/coupons
- SSRF, path traversal, open redirects, and AI cost-abuse routes
- False-positive filtering so your final table stays high-signal

---

## Example Output Table

| ID | Severity | Audit Scope | Category | CWE | Location | Finding & Impact | Recommended Fix |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `VG-001` | **CRITICAL** | Internal Security | Secrets | CWE-200 | `.env.local:2` | **Sensitive Secret Exposed via Client-Bundled Env Prefix** — `NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY` is inlined into client JS bundles. | Remove `NEXT_PUBLIC_` prefix and restrict `service_role` usage to server-only code. |
| `VG-002` | **CRITICAL** | Internal Security | BaaS/DB | CWE-284 | `firestore.rules:4` | **Permissive Firebase Security Rule (`if true`)** — Anyone on the internet can read and overwrite all documents. | Enforce `request.auth != null` and document-level ownership checks. |
| `VG-003` | **CRITICAL** | External AppSec | Auth/IDOR | CWE-862 | `app/api/invoices/[id]/route.ts:15` | **Missing ownership check (IDOR)** — Authenticated users can delete another user's invoice by changing `id`. | Filter query by `userId: session.user.id` and return `404`/`403` on mismatch. |
| `VG-004` | **HIGH** | External AppSec | Injection | CWE-89 | `src/db/users.ts:28` | **Potential SQL Injection** — Raw SQL string interpolation with user input allows full DB compromise. | Switch to parameterized `$queryRaw` tagged templates or bound query placeholders. |

---

## Suppressing Intentional Findings

- **Inline ignore**: Append `# vibeguard-ignore` or `// vibeguard-ignore` on a line (or `vibeguard-ignore-next-line` on the preceding line).
- **Path ignore**: Add glob patterns to a `.vibeguardignore` file at your repository root.

---

## Development & Tests

```bash
python3 -m unittest discover -s tests -v
```

---

## License

[MIT](LICENSE)
