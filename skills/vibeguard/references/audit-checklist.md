# VibeGuard Audit Checklist: External AppSec & Internal Security

Use this checklist during **Phase 2 (Contextual AI Audit)** after running `scripts/security_scan.py`.
Prioritize files listed under `audit_surfaces` in the scanner's JSON output.

---

## Pillar 1: External Application Security (AppSec & OWASP)

### 1. Authentication, Sessions & Middleware
- [ ] **Protected Route Coverage**: Verify every non-public API route, Server Action (`"use server"`), tRPC procedure, and GraphQL resolver checks an authenticated session (`auth()`, `getServerSession()`, `supabase.auth.getUser()`, `Depends(get_current_user)`).
- [ ] **Trusted Server Identity**: In Supabase, verify server code uses `supabase.auth.getUser()` (re-validates JWT with auth server) rather than trusting `getSession()` blindly from cookies.
- [ ] **Next.js Middleware Matcher Pitfalls**: Check `middleware.ts` `matcher` config — ensure API routes, Server Actions, or `_next/data` paths are not accidentally excluded or bypassed via alternate HTTP methods or trailing paths. Never rely *only* on `middleware.ts` for auth (enforce defense-in-depth inside each handler/action!).
- [ ] **Password & Token Hygiene**: Passwords hashed with `argon2` / `bcrypt` / `scrypt`; reset/OTP tokens generated via `crypto.randomBytes` / `secrets` with short expiration (`<= 15m`) and single-use invalidation.
- [ ] **Cookie Security**: Session cookies use `HttpOnly`, `Secure` (in production), `SameSite=Lax` or `Strict`.

### 2. Authorization, IDOR / BOLA & Business Logic
- [ ] **Object Ownership Checks (IDOR/BOLA)**: On every read/update/delete by `:id` (`params.id`, `body.projectId`), verify the database query scopes by the authenticated user (`where: { id, userId: session.user.id }`) or verifies membership/role.
- [ ] **Server-Side Pricing & Entitlements**: Ensure Stripe checkout amounts, plan tiers, credits, discounts, and `isPro` flags are computed or verified on the server from DB/Stripe price IDs — NEVER read `price`, `amount`, `role`, or `credits` directly from `req.body`.
- [ ] **Webhook Signature Verification**: Confirm Stripe (`stripe.webhooks.constructEvent`), GitHub (`X-Hub-Signature-256` with `timingSafeEqual`), Clerk/Svix, and Resend webhooks verify signatures against the **raw request body** before mutating database state.
- [ ] **Atomic Transactions & Race Conditions (TOCTOU)**: Check credit deductions, wallet transfers, coupon redemptions, and seat limits for atomic DB transactions (`$transaction`, `UPDATE ... WHERE balance >= $1`) so concurrent requests cannot double-spend.

### 3. Injection, SSRF & File Handling
- [ ] **SQL / NoSQL Injection**: All SQL queries use bound parameters; MongoDB/Mongoose queries sanitize `$`-operator objects from `req.body` (preventing `$gt`, `$ne` auth bypass).
- [ ] **SSRF (Server-Side Request Forgery)**: Any backend `fetch` / `axios` / `requests` taking a user-supplied URL (link previews, webhooks, PDF generators, image proxies) blocks private/loopback/cloud metadata IPs (`127.0.0.0/8`, `10.0.0.0/8`, `169.254.169.254`, `::1`) and restricts schemes to `https://`.
- [ ] **Path Traversal & File Uploads**: File read/write/download paths resolve cleanly with `path.resolve` + `startsWith(BASE_DIR + path.sep)`. File uploads validate MIME/magic bytes, enforce size limits, randomize filenames, and serve user uploads from isolated domains/storage buckets (never inline HTML/SVG on primary origin).
- [ ] **XSS & Open Redirect**: Redirect query params (`?next=`, `?redirect=`, `?callbackUrl=`) validate relative paths or an explicit allowlist of origins.

### 4. API Abuse, Rate Limiting & Headers
- [ ] **Rate Limiting on High-Cost / Auth Routes**: Login, signup, password reset, OTP verification, email sending, and AI generation endpoints enforce per-IP / per-user rate limits.
- [ ] **Security Headers**: Check `next.config.*` / Express `helmet` / reverse proxy for `Content-Security-Policy`, `X-Content-Type-Options: nosniff`, `X-Frame-Options` / `frame-ancestors`, `Referrer-Policy`, and `Strict-Transport-Security`.

---

## Pillar 2: Internal Security Audit (İç Güvenlik Denetimi)

### 5. Secrets, Repo Hygiene & Privilege Boundaries
- [ ] **Client/Server Separation**: Confirm no admin SDKs (`firebase-admin`, `SUPABASE_SERVICE_ROLE_KEY`, Stripe secret keys, OpenAI/Anthropic/Gemini keys) are imported into client bundles or `NEXT_PUBLIC_*` / `VITE_*` variables.
- [ ] **Git & Environment Hygiene**: `.env*` files (except `.env.example`) are in `.gitignore` and never appear in git tracking/history.
- [ ] **BaaS Row-Level Security (Supabase / Firebase)**:
  - Every public table in Supabase has `ENABLE ROW LEVEL SECURITY` and least-privilege policies (`auth.uid() = user_id`), not blanket `USING (true)`.
  - `firestore.rules` and `storage.rules` deny by default and enforce `request.auth != null` + per-document ownership/role checks.

### 6. Internal Access Controls, Logging & Data Privacy
- [ ] **Internal Admin & Staff Functions**: Admin panels (`/admin`, `/api/admin/*`) enforce server-side role/claim verification on EVERY endpoint (not just hiding UI buttons in React!).
- [ ] **Audit Trail for Sensitive Actions**: Role changes, account deletions, billing changes, and API key creations record structured audit events (`actorId`, `action`, `targetId`, `timestamp`).
- [ ] **Response Data Minimization**: API responses and Server Components do not serialize full DB user models containing `passwordHash`, `resetToken`, `twoFactorSecret`, `stripeCustomerId`, or internal notes.
- [ ] **PII & Secret Logging Hygiene**: Logs redact tokens, passwords, cookies, and full request headers; production errors never return raw stack traces or SQL error messages to clients.
- [ ] **Dead Debug / Seed Routes**: No unguarded `/api/debug`, `/api/seed`, `/api/test`, or hardcoded dev-login bypasses remain reachable in production builds.

### 7. AI / LLM & Agentic Security (OWASP LLM Top 10)
- [ ] **Prompt & Context Isolation**: System prompts remain static; untrusted user input or RAG/web documents are clearly delimited in `user` messages and never trusted for tool authorization.
- [ ] **Output Handling**: Model outputs passed to UI, SQL, shell, or tool calls are strictly schema-validated (`zod` / `pydantic`) and escaped/sanitized.
- [ ] **AI Cost & Quota Guardrails**: AI proxy endpoints require authentication, enforce token/character caps (`max_tokens`), and enforce per-user rate/spend limits.
- [ ] **Tool / MCP Least Privilege**: Agent tool functions validate paths, restrict allowed domains/commands, and require explicit confirmation for destructive actions.

### 8. CI/CD, Supply Chain & Infrastructure
- [ ] **GitHub Actions Security**: Workflows avoid `pull_request_target` with PR code checkout, avoid `${{ github.event.* }}` interpolation in `run:` scripts, and follow `permissions: read-all` / minimal job scopes.
- [ ] **Container Hardening**: Dockerfiles run as non-root `USER`, avoid embedding secrets in `ENV`/`ARG`, and Compose files avoid `privileged: true` or Docker socket mounts.
- [ ] **Dependency Integrity**: Lockfiles are committed and third-party dependencies have no critical unpatched CVEs.
