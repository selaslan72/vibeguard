---
name: vibeguard
description: >-
  Comprehensive AI security and internal audit assistant for vibe-coded projects.
  Use whenever the user asks for a security audit, vulnerability scan, internal
  security check, secret leak detection, pre-launch security review, or wants to
  see all codebase vulnerabilities in a structured table. Combines deterministic
  static scanning with deep contextual auditing of auth, IDOR, BaaS rules,
  AI/LLM safety, and internal controls.
compatibility: Python 3.9+ (standard library only; optional git, npm, pip-audit)
metadata:
  author: selaslan72
  version: "1.0.0"
  category: security
---

# VibeGuard Security & Internal Audit Assistant

VibeGuard performs a **two-phase hybrid security audit** covering both **External Application Security (AppSec & OWASP)** and **Internal Security Controls** (secrets hygiene, privilege boundaries, database RLS/rules, PII logging, debug backdoors, AI/LLM safety, and CI/CD/container posture), presenting every verified vulnerability in a single prioritized Markdown table.

> **Audit Mode Rule:** Keep the audit **read-only**. Do not modify target project files unless the user explicitly asks you to fix findings after reviewing the report. Never print raw unredacted secrets in your output.

---

## Workflow

### Phase 1: Run the Deterministic Scanner

Locate [security_scan.py](./scripts/security_scan.py) relative to this `SKILL.md` file and run it against the target project root (`<TARGET_DIR>`):

```bash
python3 <SKILL_DIR>/scripts/security_scan.py --path "<TARGET_DIR>" --format json
```

- If the user also wants dependency vulnerability checks and the environment has package managers available, pass `--run-ecosystem-audits`.
- Inspect the JSON output carefully:
  - `stack`: detected frameworks, BaaS providers, AI SDKs, and infrastructure.
  - `summary`: deterministic security score (0–100), risk rating, and counts.
  - `findings`: candidate static findings with file, line, CWE, and redacted evidence.
  - `audit_surfaces`: indexed high-risk files (`api_and_server_routes`, `auth_and_middleware`, `baas_and_db`, `payments_and_webhooks`, `ai_and_agentic`, `ci_and_containers`) to inspect in Phase 2.

---

### Phase 2: Verify Static Findings & Perform Contextual AI Audit

Static regexes cannot see cross-file auth flows, missing ownership checks, or business logic flaws. Read the relevant files from `audit_surfaces` and execute the deep checks in:

- [Audit Checklist (External AppSec & Internal Security)](./references/audit-checklist.md)
- [Top Vibe-Coding Security Traps](./references/vibecoding-traps.md)

During Phase 2, you MUST:

1. **Verify Phase 1 Findings in Context**: Read the surrounding lines of flagged files to confirm whether each automated finding is a true positive (and adjust severity if context warrants, or drop verified false positives).
2. **Audit Authentication & Server Boundaries**: Check every API route, Server Action (`"use server"`), tRPC/GraphQL resolver, and `middleware.ts` to catch unprotected endpoints or client-only auth guards.
3. **Audit IDOR / BOLA & Multi-Tenant Isolation**: On endpoints accepting `:id` / `projectId` / `orgId`, verify database queries enforce ownership (`userId: session.user.id`) or RBAC role checks.
4. **Audit BaaS & Database Security**: Inspect Supabase SQL migrations / RLS policies, `firestore.rules`, `storage.rules`, Prisma/Drizzle models, and check whether sensitive DB columns (`passwordHash`, `tokens`) leak into React Server Component props or JSON responses.
5. **Audit Payments, Webhooks & Race Conditions**: Verify Stripe/webhook signature checks use raw request bodies, server-side pricing/entitlements, and atomic transactions for credits/balances.
6. **Audit Internal Security & AI/LLM Safety**: Check for hardcoded admin/dev backdoors, sensitive PII/secret logging, debug/seed routes, prompt injection into system prompts, unvalidated LLM output sinks, missing AI endpoint auth/rate limits, and CI/CD/Docker misconfigurations.

---

### Phase 3: Present the Unified Vulnerability Table

Format your entire final report strictly according to [Report & Vulnerability Table Template](./references/report-template.md):

1. **Executive Scorecard**: Target, detected stack, Security Score (`XX/100` + Risk Rating adjusted if Phase 2 uncovered critical/high contextual flaws), Severity & Scope breakdown, and Top 3 Immediate Fixes.
2. **Consolidated Vulnerability Table**: Merge verified Phase 1 findings and new Phase 2 contextual findings into **one** Markdown table sorted `CRITICAL` → `HIGH` → `MEDIUM` → `LOW` → `INFO`, with columns:
   `ID | Severity | Audit Scope | Category | CWE | Location | Finding & Impact | Recommended Fix`
3. **Manual Verification Checklist**: List runtime/dashboard controls that cannot be checked purely from source code (e.g., cloud IAM, live Stripe webhook secrets, Supabase dashboard RLS toggle).
4. **Offer Remediation**: Ask the user which findings (starting with `CRITICAL` / `HIGH`) they would like you to fix next.
