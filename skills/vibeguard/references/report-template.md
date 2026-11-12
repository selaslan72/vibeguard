# VibeGuard Report & Vulnerability Table Format

Every VibeGuard audit MUST present its findings cleanly using this exact structure so users can immediately see their security posture and fix issues in priority order.

---

## Required Output Structure

### 1. Executive Scorecard
Summarize:
- **Target Project & Detected Stack**
- **Overall Security Score**: `XX / 100` (`CRITICAL RISK` | `HIGH RISK` | `MODERATE RISK` | `LOW RISK` | `HARDENED`)
- **Severity Breakdown**: `CRITICAL: X | HIGH: Y | MEDIUM: Z | LOW: W | INFO: N`
- **Audit Scope Breakdown**: `External AppSec: A | Internal Security: B`
- **Top 3 Immediate Actions Before Shipping** (concise bullet list of the highest-impact fixes)

### 2. Unified Security & Internal Audit Table (MANDATORY)
Merge verified findings from **Phase 1 (Automated Scan)** and **Phase 2 (AI Contextual Audit)** into **one consolidated Markdown table**, sorted by severity (`CRITICAL` -> `HIGH` -> `MEDIUM` -> `LOW` -> `INFO`), with **no unverified guesses**.

Exact columns:

| ID | Severity | Audit Scope | Category | CWE | Location | Finding & Impact | Recommended Fix |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `VG-001` | **CRITICAL** | External AppSec | Secrets | CWE-798 | `src/lib/ai.ts:14` | **Hardcoded OpenAI key** — Anyone reading the repo or bundle can abuse your paid API quota. | Rotate the key, move to `.env` (`OPENAI_API_KEY`), and scrub git history. |
| `VG-002` | **CRITICAL** | Internal Security | Auth/IDOR | CWE-862 | `app/api/projects/[id]/route.ts:22` | **Missing ownership check (IDOR)** — Authenticated users can delete any tenant's project by changing `id`. | Scope query with `where: { id, userId: session.user.id }` after checking session. |

### 3. Formatting Rules
1. **Escape pipes (`\|`)** inside table cells and keep each cell concise (1–2 crisp sentences) so the table never breaks rendering.
2. **Never output raw secrets** in the table or prose — always mask/redact (`sk-p...9a2F`).
3. **Every finding must cite observed file & line** (`path/to/file:line`) or repository-wide target (`.gitignore`, `package.json`).
4. **Separate verified facts from manual review recommendations**: if something could not be verified statically (e.g., runtime cloud dashboard settings like Supabase dashboard RLS or Stripe webhook dashboard config), list it under a short **"Manual Verification Checklist (Runtime / Dashboard)"** section below the table rather than fabricating a vulnerability.
5. **Offer next steps**: Ask the user if they want you to patch the `CRITICAL` and `HIGH` findings directly (starting with the top priority items).
