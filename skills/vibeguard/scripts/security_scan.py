#!/usr/bin/env python3
"""VibeGuard Deterministic Security & Internal Audit Scanner.

Zero-dependency Python 3 scanner designed for vibe-coded repositories.
Combines External AppSec checks (secrets, injection, auth, CORS, AI/LLM)
with Internal Security Audit checks (IAM/service-role boundaries, RLS/Firestore
rules, PII logging, debug backdoors, Git hygiene, CI/CD, and container posture).
"""

from __future__ import annotations

import argparse
import dataclasses
import fnmatch
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Iterable, Optional

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
SEVERITY_WEIGHTS = {"CRITICAL": 25, "HIGH": 12, "MEDIUM": 5, "LOW": 2, "INFO": 0}

SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    "node_modules",
    ".next",
    ".nuxt",
    ".svelte-kit",
    ".vercel",
    ".netlify",
    ".turbo",
    "dist",
    "build",
    "out",
    "coverage",
    ".venv",
    "venv",
    "env",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    "target",
    "vendor",
    "Pods",
    ".gradle",
}

LOCKFILES = {
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "bun.lockb",
    "bun.lock",
    "poetry.lock",
    "uv.lock",
    "Pipfile.lock",
    "Cargo.lock",
    "go.sum",
    "composer.lock",
}

BINARY_EXTENSIONS = {
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".webp",
    ".ico",
    ".pdf",
    ".zip",
    ".tar",
    ".gz",
    ".7z",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
    ".mp4",
    ".mp3",
    ".mov",
    ".wav",
    ".exe",
    ".dll",
    ".so",
    ".dylib",
    ".pyc",
    ".sqlite",
    ".db",
    ".wasm",
}

MAX_FILE_BYTES = 1_500_000

TEST_OR_EXAMPLE_PATH_RE = re.compile(
    r"(?:^|/)(?:tests?|__tests__|__mocks__|spec|specs|fixtures?|examples?|samples?|demos?|mocks?)(?:/|$)"
    r"|\.(?:test|spec)\.[^.]+$|\.example(?:\.[^.]+)?$",
    re.IGNORECASE,
)

PLACEHOLDER_VALUE_RE = re.compile(
    r"(?:example|placeholder|your[-_]|<your|replace[-_]?me|dummy|test[-_]?key|fake[-_]?|"
    r"changeme|change[-_]?this|xxxx+|0000+|\*{4,}|\$\{[^}]+\}|process\.env\.|os\.environ|"
    r"import\.meta\.env)",
    re.IGNORECASE,
)

CLIENT_DIR_OR_FILE_RE = re.compile(
    r"(?:^|/)(?:components|client|hooks|views|screens|ui)/|"
    r"(?:^|/)(?:app|src/app)/.*(?:/|^)(?:page|layout|loading|error)\.(?:jsx|tsx|js|ts)$|"
    r"(?:^|/)src/pages/(?!api/).*\.(?:jsx|tsx|js|ts)$",
    re.IGNORECASE,
)

FRONTEND_EXTS = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue", ".svelte"}
CODE_EXTS = FRONTEND_EXTS | {".py", ".rb", ".go", ".php", ".java", ".cs", ".rs"}
CONFIG_EXTS = {".json", ".yml", ".yaml", ".toml", ".ini", ".env", ".sql", ".rules", ".tf"}
ENV_FILENAME_RE = re.compile(r"^\.env(?:\.[^.]+)?$", re.IGNORECASE)
ENV_SAFE_SUFFIX_RE = re.compile(r"\.(?:example|sample|template|dist|schema)$", re.IGNORECASE)
SENSITIVE_FILE_RE = re.compile(
    r"(?:^|/)(?:\.env(?:\.(?!example$|sample$|template$)[^/]+)?|"
    r".*service[-_]?account.*\.json|.*firebase-adminsdk.*\.json|"
    r"credentials\.json|id_rsa|id_ed25519|.*\.(?:pem|key|p12|pfx))$",
    re.IGNORECASE,
)


@dataclasses.dataclass
class Finding:
    """Normalized representation of a security or internal audit finding."""

    rule_id: str
    title: str
    severity: str
    scope: str  # "External AppSec" | "Internal Security"
    category: str
    cwe: str
    file: str
    line: int
    evidence: str
    impact: str
    remediation: str
    confidence: str = "HIGH"  # HIGH | MEDIUM | LOW
    in_test_or_example: bool = False


@dataclasses.dataclass(frozen=True)
class LineRule:
    """Declarative regex rule evaluated against matching source lines."""

    rule_id: str
    title: str
    severity: str
    scope: str
    category: str
    cwe: str
    pattern: re.Pattern[str]
    impact: str
    remediation: str
    extensions: Optional[frozenset[str]] = None
    path_pattern: Optional[re.Pattern[str]] = None
    exclude_pattern: Optional[re.Pattern[str]] = None
    confidence: str = "HIGH"
    redact: bool = False
    skip_placeholders: bool = False


def redact_secret(text: str) -> str:
    """Mask potential tokens/secrets so reports never leak raw credentials."""

    def _mask(match: re.Match[str]) -> str:
        val = match.group(0)
        if len(val) <= 10:
            return "*" * len(val)
        return f"{val[:4]}...{val[-4:]}"

    masked = re.sub(
        r"(?:sk-proj-|sk-ant-api\d+-|sk_live_|rk_live_|whsec_|ghp_|gho_|github_pat_|"
        r"AKIA|ASIA|AIza|xox[baprs]-|SG\.)[A-Za-z0-9_.\-]{8,}",
        _mask,
        text,
    )
    masked = re.sub(
        r"(://[^:\s'\"]+:)([^@\s'\"]{4,})(@)",
        lambda m: f"{m.group(1)}****{m.group(3)}",
        masked,
    )
    masked = re.sub(
        r"((?:SECRET|PASSWORD|TOKEN|KEY|AUTH|CREDENTIAL)[A-Z0-9_]*\s*[:=]\s*['\"])([^'\"]{8,})(['\"])",
        lambda m: f"{m.group(1)}{m.group(2)[:3]}****{m.group(3)}",
        masked,
        flags=re.IGNORECASE,
    )
    return masked.strip()[:180]


def build_rules() -> list[LineRule]:
    """Return all declarative line-level External AppSec and Internal Security rules."""
    return [
        # --- SECRETS & CREDENTIALS (SEC) ---
        LineRule(
            rule_id="SEC-001",
            title="Hardcoded OpenAI API Key",
            severity="CRITICAL",
            scope="External AppSec",
            category="Secrets",
            cwe="CWE-798",
            pattern=re.compile(r"\b(?:sk-proj-[A-Za-z0-9_-]{20,}|sk-[A-Za-z0-9]{20,}T3BlbkFJ[A-Za-z0-9]{20,})\b"),
            impact="Anyone with repository or bundle access can drain your OpenAI quota and access fine-tuned models or files.",
            remediation="Revoke the key immediately in OpenAI dashboard, move it to a server-only .env file, and scrub git history.",
            redact=True,
            skip_placeholders=True,
        ),
        LineRule(
            rule_id="SEC-002",
            title="Hardcoded Anthropic API Key",
            severity="CRITICAL",
            scope="External AppSec",
            category="Secrets",
            cwe="CWE-798",
            pattern=re.compile(r"\bsk-ant-api\d{2}-[A-Za-z0-9_-]{20,}\b"),
            impact="Exposed Anthropic API keys allow unauthorized usage billed to your account.",
            remediation="Rotate the key in Anthropic Console and load it exclusively from server-side environment variables.",
            redact=True,
            skip_placeholders=True,
        ),
        LineRule(
            rule_id="SEC-003",
            title="Hardcoded Google / Gemini / Firebase API Key",
            severity="HIGH",
            scope="External AppSec",
            category="Secrets",
            cwe="CWE-798",
            pattern=re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
            impact="If unrestricted or tied to Gemini/Cloud APIs, attackers can abuse paid quotas or access enabled Google Cloud services.",
            remediation="Never commit Gemini server keys; move to .env. For public Firebase web keys, enforce HTTP referrer + API restrictions and Firebase App Check.",
            redact=True,
            skip_placeholders=True,
        ),
        LineRule(
            rule_id="SEC-004",
            title="Hardcoded AWS Access Key ID",
            severity="CRITICAL",
            scope="External AppSec",
            category="Secrets",
            cwe="CWE-798",
            pattern=re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
            impact="Exposes AWS infrastructure to unauthorized data access, resource provisioning, or account takeover.",
            remediation="Deactivate and rotate the IAM key immediately; use IAM roles or AWS Secrets Manager instead of static credentials.",
            redact=True,
            skip_placeholders=True,
        ),
        LineRule(
            rule_id="SEC-005",
            title="Hardcoded GitHub Personal Access Token",
            severity="CRITICAL",
            scope="External AppSec",
            category="Secrets",
            cwe="CWE-798",
            pattern=re.compile(r"\b(?:ghp_[A-Za-z0-9]{36}|gho_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{22,})\b"),
            impact="Grants attackers read/write access to private repositories, secrets, and CI/CD pipelines.",
            remediation="Revoke the token in GitHub Developer Settings and replace with short-lived GitHub App or Actions OIDC tokens.",
            redact=True,
            skip_placeholders=True,
        ),
        LineRule(
            rule_id="SEC-006",
            title="Hardcoded Stripe Live or Webhook Secret",
            severity="CRITICAL",
            scope="External AppSec",
            category="Secrets",
            cwe="CWE-798",
            pattern=re.compile(r"\b(?:(?:sk|rk)_live_[0-9A-Za-z]{20,}|whsec_[0-9A-Za-z]{24,})\b"),
            impact="Live Stripe keys allow issuing refunds, reading customer PII, and forging verified webhooks.",
            remediation="Roll the key immediately in Stripe Dashboard, store only in server-side env vars, and never commit live keys.",
            redact=True,
            skip_placeholders=True,
        ),
        LineRule(
            rule_id="SEC-007",
            title="Hardcoded Slack or SendGrid Token",
            severity="CRITICAL",
            scope="External AppSec",
            category="Secrets",
            cwe="CWE-798",
            pattern=re.compile(r"\b(?:xox[baprs]-[0-9A-Za-z-]{10,}|SG\.[0-9A-Za-z_-]{22}\.[0-9A-Za-z_-]{43})\b"),
            impact="Allows sending phishing emails from your domain or reading/posting in private Slack workspaces.",
            remediation="Revoke the token immediately and inject via runtime secrets management.",
            redact=True,
            skip_placeholders=True,
        ),
        LineRule(
            rule_id="SEC-008",
            title="Private Cryptographic Key Committed in Source",
            severity="CRITICAL",
            scope="Internal Security",
            category="Secrets",
            cwe="CWE-321",
            pattern=re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"),
            impact="Private keys in source allow impersonation, TLS MITM, or decrypting internal traffic.",
            remediation="Remove the private key from code and git history, rotate the keypair, and store keys in KMS/Vault.",
            redact=True,
        ),
        LineRule(
            rule_id="SEC-009",
            title="Database Connection URI with Embedded Password",
            severity="CRITICAL",
            scope="External AppSec",
            category="Secrets",
            cwe="CWE-798",
            pattern=re.compile(
                r"(?:postgres(?:ql)?|mongodb(?:\+srv)?|mysql|redis|rediss)://"
                r"[^:\s'\"]+:[^@\s'\"]{4,}@(?!localhost\b|127\.0\.0\.1\b|0\.0\.0\.0\b|db\b|postgres\b|example\.com\b)[^\s'\"]+",
                re.IGNORECASE,
            ),
            impact="Direct database credentials grant full read/write/drop access to production data.",
            remediation="Rotate the database password and inject DATABASE_URL via environment variables.",
            redact=True,
            skip_placeholders=True,
        ),
        LineRule(
            rule_id="SEC-010",
            title="Sensitive Secret Exposed via Client-Bundled Env Prefix",
            severity="CRITICAL",
            scope="Internal Security",
            category="Secrets",
            cwe="CWE-200",
            pattern=re.compile(
                r"\b(?:NEXT_PUBLIC|VITE|REACT_APP|NUXT_PUBLIC|EXPO_PUBLIC)_[A-Z0-9_]*"
                r"(?:SECRET|PRIVATE|SERVICE_ROLE|ADMIN_KEY|DB_PASS(?:WORD)?|JWT_SECRET|API_SECRET|OPENAI_API_KEY|ANTHROPIC_API_KEY|STRIPE_SECRET)[A-Z0-9_]*\b"
            ),
            impact="Public framework env prefixes inline the secret directly into browser JavaScript bundles visible to every user.",
            remediation="Remove the public prefix (e.g., drop NEXT_PUBLIC_/VITE_) and move all privileged calls behind server API routes.",
        ),
        LineRule(
            rule_id="SEC-011",
            title="Hardcoded Sensitive Credential Assignment",
            severity="HIGH",
            scope="External AppSec",
            category="Secrets",
            cwe="CWE-798",
            pattern=re.compile(
                r"\b(?:SUPABASE_SERVICE_ROLE_KEY|SERVICE_ROLE_KEY|JWT_SECRET|NEXTAUTH_SECRET|AUTH_SECRET|"
                r"SESSION_SECRET|STRIPE_SECRET_KEY|OPENAI_API_KEY|ANTHROPIC_API_KEY|GEMINI_API_KEY|"
                r"ADMIN_PASSWORD|MASTER_KEY|ENCRYPTION_KEY)\s*[:=]\s*['\"]([^'\"\n]{12,})['\"]",
                re.IGNORECASE,
            ),
            impact="Hardcoded secrets in code or committed configs can be extracted by anyone with code or build artifact access.",
            remediation="Move the credential to runtime environment variables (.env excluded from git) and rotate the exposed value.",
            redact=True,
            skip_placeholders=True,
        ),

        # --- INJECTION & UNSAFE CODE EXECUTION (INJ) ---
        LineRule(
            rule_id="INJ-001",
            title="Potential SQL Injection via Unsafe Query Interpolation",
            severity="CRITICAL",
            scope="External AppSec",
            category="Injection",
            cwe="CWE-89",
            pattern=re.compile(
                r"(?:\$queryRawUnsafe|\$executeRawUnsafe)\s*\(|"
                r"\.(?:query|execute|executemany|raw)\s*\(\s*(?:`[^`]*\$\{|f['\"]\s*(?:SELECT|INSERT|UPDATE|DELETE|WITH|DROP|ALTER)\b|"
                r"['\"]\s*(?:SELECT|INSERT|UPDATE|DELETE|WITH|DROP|ALTER)\b[^'\"]*['\"]\s*(?:\+|%\s|\.format\())",
                re.IGNORECASE,
            ),
            extensions=CODE_EXTS,
            impact="Attackers can manipulate SQL queries to dump, modify, or delete the entire database.",
            remediation="Use parameterized queries/prepared statements (e.g., Prisma `$queryRaw` tagged templates or `?`/`$1` placeholders).",
        ),
        LineRule(
            rule_id="INJ-002",
            title="Potential OS Command Injection",
            severity="CRITICAL",
            scope="External AppSec",
            category="Injection",
            cwe="CWE-78",
            pattern=re.compile(
                r"(?:\b(?:exec|execSync)\s*\(\s*(?:`[^`]*\$\{|[^'\")\n]+\+)|"
                r"\bos\.system\s*\(|subprocess\.(?:run|Popen|call|check_output|check_call)\s*\([^)]*shell\s*=\s*True)"
            ),
            extensions=CODE_EXTS,
            impact="If user-controlled input reaches shell execution, attackers gain full Remote Code Execution (RCE) on the server.",
            remediation="Use `execFile`/`spawn` with argument arrays (`shell: false`) or Python `subprocess.run([...], shell=False)`.",
        ),
        LineRule(
            rule_id="INJ-003",
            title="Cross-Site Scripting (XSS) Sink via Raw HTML Injection",
            severity="HIGH",
            scope="External AppSec",
            category="Injection",
            cwe="CWE-79",
            pattern=re.compile(
                r"dangerouslySetInnerHTML\s*=\s*\{\{\s*__html\s*:|"
                r"\.(?:innerHTML|outerHTML)\s*(?:=|\+=)|"
                r"\bdocument\.write\s*\(|v-html\s*=|\{@html\b|bypassSecurityTrustHtml\s*\("
            ),
            extensions=FRONTEND_EXTS | {".html"},
            impact="Unsanitized HTML lets attackers execute arbitrary JavaScript in victims' browsers and hijack sessions.",
            remediation="Render plain text/JSX instead, or sanitize strictly with DOMPurify before rendering trusted HTML.",
            confidence="MEDIUM",
        ),
        LineRule(
            rule_id="INJ-004",
            title="Dynamic Code Execution (`eval` / `new Function` / `vm`)",
            severity="HIGH",
            scope="External AppSec",
            category="Injection",
            cwe="CWE-95",
            pattern=re.compile(r"\b(?:eval|new\s+Function)\s*\(|vm\.runIn(?:New|This)?Context\s*\("),
            extensions=CODE_EXTS,
            impact="Evaluating dynamic strings risks XSS in browsers or full RCE on Node.js/Python servers.",
            remediation="Replace `eval`/`new Function` with `JSON.parse`, safe expression parsers, or explicit dispatch maps.",
            confidence="MEDIUM",
        ),
        LineRule(
            rule_id="INJ-005",
            title="Unsafe Deserialization or Server-Side Template Injection",
            severity="HIGH",
            scope="External AppSec",
            category="Injection",
            cwe="CWE-502",
            pattern=re.compile(
                r"\bpickle\.(?:loads|load)\s*\(|"
                r"\byaml\.load\s*\((?![^)]*(?:SafeLoader|CSafeLoader|BaseLoader))|"
                r"\brender_template_string\s*\("
            ),
            extensions=frozenset({".py"}),
            impact="Untrusted pickle/YAML deserialization or SSTI leads directly to arbitrary code execution.",
            remediation="Use `json` or `yaml.safe_load()` instead of `pickle`/`yaml.load()`, and use static template files with `render_template()`.",  # vibeguard-ignore
        ),

        # --- AUTHENTICATION, SESSION & CRYPTO (AUTH) ---
        LineRule(
            rule_id="AUTH-001",
            title="Hardcoded Fallback Signing / Auth Secret",
            severity="HIGH",
            scope="External AppSec",
            category="Auth/Session",
            cwe="CWE-798",
            pattern=re.compile(
                r"(?:JWT_SECRET|AUTH_SECRET|NEXTAUTH_SECRET|SESSION_SECRET|COOKIE_SECRET|TOKEN_SECRET|SECRET_KEY)"
                r"[^;\n]*(?:\|\||\?\?|\bor\b)\s*['\"][^'\"\n]+['\"]|"
                r"os\.(?:getenv|environ\.get)\s*\(\s*['\"](?:SECRET_KEY|JWT_SECRET|AUTH_SECRET|SESSION_SECRET)['\"]\s*,\s*['\"][^'\"]+['\"]\s*\)"
            ),
            extensions=CODE_EXTS,
            impact="If the environment variable is unset in production, attackers can forge valid session cookies or JWTs using the known fallback string.",
            remediation="Fail fast at startup when required auth secrets are missing instead of falling back to a literal string.",
        ),
        LineRule(
            rule_id="AUTH-002",
            title="JWT Signature Verification Bypassed",
            severity="CRITICAL",
            scope="External AppSec",
            category="Auth/Session",
            cwe="CWE-347",
            pattern=re.compile(
                r"\bjwt\.decode\s*\((?![^)]*(?:verify|algorithms))|"
                r"verify_signature['\"]?\s*:\s*False|"
                r"algorithms\s*[:=]\s*\[[^\]]*['\"]none['\"]",
                re.IGNORECASE,
            ),
            extensions=CODE_EXTS,
            impact="Accepting unverified JWT payloads lets any user forge arbitrary user IDs, emails, or admin claims.",
            remediation="Always use `jwt.verify()` (Node) or `jwt.decode(..., algorithms=['HS256'/'RS256'])` with signature verification enabled.",
            confidence="MEDIUM",
        ),
        LineRule(
            rule_id="AUTH-003",
            title="TLS Certificate Verification Disabled",
            severity="HIGH",
            scope="External AppSec",
            category="Auth/Session",
            cwe="CWE-295",
            pattern=re.compile(
                r"NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]0['\"]|"
                r"rejectUnauthorized\s*:\s*false|"
                r"\brequests\.(?:get|post|put|delete|patch|request)\s*\([^)]*verify\s*=\s*False"
            ),
            extensions=CODE_EXTS | CONFIG_EXTS,
            impact="Disabling TLS certificate checks exposes API calls and credentials to active Man-in-the-Middle attacks.",
            remediation="Remove `rejectUnauthorized: false` / `verify=False` and configure proper CA trust bundles if needed.",  # vibeguard-ignore
        ),
        LineRule(
            rule_id="AUTH-004",
            title="Weak Cryptographic Hash or Non-Cryptographic RNG for Security Value",
            severity="MEDIUM",
            scope="External AppSec",
            category="Auth/Session",
            cwe="CWE-328",
            pattern=re.compile(
                r"(?:hashlib\.(?:md5|sha1)\s*\([^)]*pass|createHash\s*\(\s*['\"](?:md5|sha1)['\"]\s*\).*pass|"
                r"(?:token|secret|otp|code|reset|session|nonce|apiKey)[^\n]{0,40}Math\.random\s*\(|"
                r"Math\.random\s*\([^\n]{0,40}(?:token|secret|otp|code|reset|session|nonce|apiKey))",
                re.IGNORECASE,
            ),
            extensions=CODE_EXTS,
            impact="Predictable RNG or fast hashes (MD5/SHA1) allow attackers to guess reset tokens/OTPs or crack passwords trivially.",
            remediation="Use `crypto.randomBytes` / `crypto.randomUUID` / Python `secrets` for tokens, and `argon2` or `bcrypt` for passwords.",
        ),
        LineRule(
            rule_id="AUTH-005",
            title="Cookie Security Flag Explicitly Disabled (`httpOnly: false`)",  # vibeguard-ignore
            severity="MEDIUM",
            scope="External AppSec",
            category="Auth/Session",
            cwe="CWE-1004",
            pattern=re.compile(r"\bhttpOnly\s*:\s*false\b|\bhttponly\s*=\s*False\b"),
            extensions=CODE_EXTS,
            impact="Cookies without `HttpOnly` can be stolen via `document.cookie` if any XSS exists.",
            remediation="Set `httpOnly: true`, `secure: true` (in production), and `sameSite: 'lax'` or `'strict'` on session cookies.",
        ),

        # --- API, CORS & HEADERS (API) ---
        LineRule(
            rule_id="API-001",
            title="Wildcard CORS Policy Configured",
            severity="MEDIUM",
            scope="External AppSec",
            category="API/CORS",
            cwe="CWE-942",
            pattern=re.compile(
                r"Access-Control-Allow-Origin['\"]?\s*[:=]\s*['\"]\*['\"]|"
                r"\borigin\s*:\s*['\"]\*['\"]|"
                r"allow_origins\s*=\s*\[\s*['\"]\*['\"]\s*\]"
            ),
            extensions=CODE_EXTS | CONFIG_EXTS,
            impact="Wildcard CORS allows any third-party site to query your API from users' browsers (critical if combined with credentials).",
            remediation="Restrict CORS origins to an explicit allowlist of your trusted frontend domains.",
        ),
        LineRule(
            rule_id="API-002",
            title="Framework Debug Mode Enabled in Code",
            severity="HIGH",
            scope="Internal Security",
            category="API/CORS",
            cwe="CWE-489",
            pattern=re.compile(r"^\s*DEBUG\s*=\s*True\b|app\.run\([^)]*debug\s*=\s*True"),
            extensions=frozenset({".py"}),
            impact="Production debug mode leaks interactive tracebacks, environment variables, and internal code paths (and Flask Werkzeug RCE).",
            remediation="Load `DEBUG` from environment variables defaulting to `False`.",
        ),

        # --- INTERNAL SECURITY: IAM, BaaS & ACCESS CONTROL (IAM) ---
        LineRule(
            rule_id="IAM-001",
            title="Admin / Service Role Database Key Referenced in Client Code",
            severity="CRITICAL",
            scope="Internal Security",
            category="Auth/IDOR",
            cwe="CWE-269",
            pattern=re.compile(
                r"\b(?:SUPABASE_SERVICE_ROLE(?:_KEY)?|firebase-admin|admin\.credential\.cert)\b"
            ),
            extensions=FRONTEND_EXTS,
            path_pattern=CLIENT_DIR_OR_FILE_RE,
            impact="Service-role / admin SDK credentials inside client routes or components bypass all Row-Level Security and expose the entire database.",
            remediation="Move privileged database operations to server-only route handlers or Server Actions and use the public anon key + RLS on the client.",
        ),
        LineRule(
            rule_id="IAM-002",
            title="Permissive Firebase Security Rule (`if true`)",
            severity="CRITICAL",
            scope="Internal Security",
            category="BaaS/DB",
            cwe="CWE-284",
            pattern=re.compile(
                r"allow\s+(?:read|write|get|list|create|update|delete)"
                r"(?:\s*,\s*(?:read|write|get|list|create|update|delete))*\s*:\s*if\s+true\b"
            ),
            path_pattern=re.compile(r"(?:firestore|storage).*\.rules$", re.IGNORECASE),
            impact="Anyone on the internet can read, overwrite, or wipe your entire Firestore/Storage database without signing in.",
            remediation="Replace `if true` with strict `request.auth != null` and document ownership checks (`request.auth.uid == resource.data.userId`).",
        ),
        LineRule(
            rule_id="IAM-003",
            title="Overly Permissive Supabase RLS Policy (`USING (true)` / `WITH CHECK (true)`)",
            severity="HIGH",
            scope="Internal Security",
            category="BaaS/DB",
            cwe="CWE-284",
            pattern=re.compile(
                r"CREATE\s+POLICY\b[^\n]*(?:USING|WITH\s+CHECK)\s*\(\s*true\s*\)",
                re.IGNORECASE,
            ),
            extensions=frozenset({".sql"}),
            impact="A policy with `USING (true)` or `WITH CHECK (true)` allows unauthenticated or cross-tenant reads/writes depending on the command.",
            remediation="Scope policies explicitly using `auth.uid() = user_id` or `auth.role() = 'service_role'` and restrict `TO authenticated`.",
            confidence="MEDIUM",
        ),
        LineRule(
            rule_id="IAM-004",
            title="Potential Mass Assignment via Unfiltered Request Body",
            severity="HIGH",
            scope="Internal Security",
            category="Auth/IDOR",
            cwe="CWE-915",
            pattern=re.compile(
                r"\.(?:create|update|upsert|insert|findByIdAndUpdate|updateOne|findOneAndUpdate)\s*\(\s*"
                r"(?:\{\s*data\s*:\s*(?:req\.body|body|await\s+req\.json\(\))|"
                r"(?:req\.body|await\s+req\.json\(\))\s*[,)]|"
                r"\{\s*\.\.\.(?:req\.body|body)\s*[,}])"
            ),
            extensions=CODE_EXTS,
            impact="Attackers can inject protected fields like `role: 'admin'`, `isPro: true`, `credits: 99999`, or overwrite `userId`.",
            remediation="Validate and whitelist explicit fields using Zod/Pydantic schemas before passing input to ORM write methods.",
        ),
        LineRule(
            rule_id="IAM-005",
            title="Auth Bypass Flag or Hardcoded Admin Email Backdoor",
            severity="HIGH",
            scope="Internal Security",
            category="Auth/IDOR",
            cwe="CWE-287",
            pattern=re.compile(
                r"\b(?:SKIP_AUTH|DISABLE_AUTH|BYPASS_AUTH|NO_AUTH)\s*[:=]\s*(?:true|['\"](?:1|true)['\"])|"
                r"(?:isAdmin|is_admin|adminEmails|ADMIN_EMAILS)[^\n]*@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
                re.IGNORECASE,
            ),
            extensions=CODE_EXTS | CONFIG_EXTS,
            impact="Auth bypass switches or hardcoded personal admin emails create hidden internal backdoors if deployed to production.",
            remediation="Remove auth bypass toggles completely and manage admin roles via database RBAC claims + audit logs.",
        ),

        # --- INTERNAL SECURITY: OPS, LOGGING, PII & BACKDOORS (OPS) ---
        LineRule(
            rule_id="OPS-001",
            title="Sensitive Credential or Header Logged to Console/Logs",
            severity="MEDIUM",
            scope="Internal Security",
            category="Internal Ops",
            cwe="CWE-532",
            pattern=re.compile(
                r"(?:console\.(?:log|debug|info|warn|error)|logger\.(?:info|debug|warn|error)|print)\s*\([^)]*\b"
                r"(?:password|passwd|secretKey|apiKey|api_key|accessToken|refreshToken|privateKey|"
                r"req\.headers(?:\.authorization|\[['\"]authorization['\"]\])?|process\.env)\b",
                re.IGNORECASE,
            ),
            extensions=CODE_EXTS,
            impact="Internal logs are often shipped to third-party log aggregators, exposing user passwords, tokens, and internal keys.",
            remediation="Strip or redact sensitive fields before logging and never dump raw `process.env` or Authorization headers.",
        ),
        LineRule(
            rule_id="OPS-002",
            title="Internal Stack Trace Returned in HTTP Response",
            severity="MEDIUM",
            scope="Internal Security",
            category="Internal Ops",
            cwe="CWE-209",
            pattern=re.compile(
                r"(?:res\.(?:status\([^)]+\)\.)?(?:json|send)|NextResponse\.json|Response\.json|jsonify)\s*\([^)]*"
                r"(?:err(?:or)?\.stack|traceback\.format_exc\(\))"
            ),
            extensions=CODE_EXTS,
            impact="Returning raw stack traces exposes internal file paths, library versions, SQL structures, and logic hints to attackers.",
            remediation="Log detailed errors server-side with a request ID and return a generic error message to clients.",
        ),

        # --- AI / LLM & AGENTIC SECURITY (AI) ---
        LineRule(
            rule_id="AI-001",
            title="Potential Prompt Injection via Interpolated Input in System Prompt",
            severity="HIGH",
            scope="External AppSec",
            category="AI/LLM",
            cwe="CWE-77",
            pattern=re.compile(
                r"(?:role\s*:\s*['\"]system['\"][^\n]*content\s*:\s*(?:`[^`]*\$\{|f['\"][^'\"]*\{)|"
                r"systemInstruction\s*:\s*(?:`[^`]*\$\{|f['\"][^'\"]*\{))",
                re.IGNORECASE,
            ),
            extensions=CODE_EXTS,
            impact="Interpolating untrusted input directly inside system instructions lets attackers override model rules and exfiltrate system prompts/tools.",
            remediation="Keep system prompts static and pass user-supplied content strictly in separate `user` messages or delimited data blocks.",
            confidence="MEDIUM",
        ),
        LineRule(
            rule_id="AI-002",
            title="Unvalidated LLM Output Passed Directly to Dangerous Sink",
            severity="CRITICAL",
            scope="External AppSec",
            category="AI/LLM",
            cwe="CWE-94",
            pattern=re.compile(
                r"(?:eval|exec|new\s+Function|dangerouslySetInnerHTML|\$queryRawUnsafe|subprocess\.run)\s*\([^)]*"
                r"(?:completion|choices\[0\]|message\.content|response\.text|llmOutput|aiResponse)",
                re.IGNORECASE,
            ),
            extensions=CODE_EXTS,
            impact="Prompt-injected users can trick the LLM into emitting malicious code, SQL, or HTML that your app executes directly.",
            remediation="Treat LLM responses as untrusted input: validate against strict JSON schemas, sanitize HTML, and never execute generated code unsandboxed.",
        ),

        # --- INFRASTRUCTURE, CI/CD & SUPPLY CHAIN (INFRA) ---
        LineRule(
            rule_id="INFRA-001",
            title="GitHub Actions Script Injection via Untrusted Event Expression",
            severity="CRITICAL",
            scope="Internal Security",
            category="CI/CD & Infra",
            cwe="CWE-94",
            pattern=re.compile(
                r"\$\{\{\s*github\.event\.(?:issue\.(?:title|body)|pull_request\.(?:title|body)|"
                r"comment\.body|review\.body|head_commit\.message|commits\[[^\]]+\]\.message|inputs\.[^\s}]+)\s*\}\}"
            ),
            path_pattern=re.compile(r"\.github/workflows/.*\.ya?ml$", re.IGNORECASE),
            impact="External contributors can open an issue/PR with shell metacharacters in the title/body to steal CI secrets and push malicious code.",
            remediation="Pass untrusted fields via intermediate `env:` variables and quote them safely (`\"$VAR\"`) instead of inline `${{ ... }}`.",
        ),
        LineRule(
            rule_id="INFRA-002",
            title="GitHub Actions Workflow Grants `write-all` Permissions",
            severity="HIGH",
            scope="Internal Security",
            category="CI/CD & Infra",
            cwe="CWE-250",
            pattern=re.compile(r"^\s*permissions\s*:\s*write-all\b"),
            path_pattern=re.compile(r"\.github/workflows/.*\.ya?ml$", re.IGNORECASE),
            impact="Violates least-privilege; any compromised action or step gets full repository write and package publishing access.",
            remediation="Set `permissions: read-all` at workflow level and grant minimal write scopes per job.",
        ),
        LineRule(
            rule_id="INFRA-003",
            title="Privileged Container or Docker Socket Mount in Compose",
            severity="CRITICAL",
            scope="Internal Security",
            category="CI/CD & Infra",
            cwe="CWE-250",
            pattern=re.compile(r"^\s*privileged\s*:\s*true\b|/var/run/docker\.sock"),
            path_pattern=re.compile(r"docker-compose.*\.ya?ml$|compose.*\.ya?ml$", re.IGNORECASE),
            impact="Gives containers full host root escape capability if the application is compromised.",
            remediation="Remove `privileged: true` and avoid mounting the Docker daemon socket into application containers.",
        ),
        LineRule(
            rule_id="INFRA-004",
            title="Remote Script Piped Directly into Shell (`curl | sh`)",
            severity="MEDIUM",
            scope="Internal Security",
            category="Supply Chain",
            cwe="CWE-829",
            pattern=re.compile(r"\b(?:curl|wget)\s+[^\n|]+\|\s*(?:sudo\s+)?(?:bash|sh|zsh)\b"),
            impact="Executes unverified remote scripts without checksum verification; supply-chain compromise of the remote URL compromises builds.",
            remediation="Pin release versions, download artifacts explicitly, verify SHA256 checksums, or install via signed package managers.",
        ),
        LineRule(
            rule_id="INFRA-005",
            title="Secret Embedded in Dockerfile `ENV` or `ARG`",
            severity="HIGH",
            scope="Internal Security",
            category="Secrets",
            cwe="CWE-798",
            pattern=re.compile(
                r"^\s*(?:ENV|ARG)\s+[A-Z0-9_]*(?:SECRET|PASSWORD|TOKEN|API_KEY|PRIVATE_KEY)\s*[=\s]+\S+",
                re.IGNORECASE,
            ),
            path_pattern=re.compile(r"(?:^|/)Dockerfile(?:\.[^/]+)?$", re.IGNORECASE),
            impact="Dockerfile `ENV`/`ARG` values persist permanently inside image layers and `docker history`.",
            remediation="Use runtime env injection or Docker BuildKit secrets (`--mount=type=secret`) instead of `ENV`/`ARG`.",
            redact=True,
            skip_placeholders=True,
        ),
    ]


def load_ignore_patterns(root: Path) -> list[str]:
    """Read optional .vibeguardignore patterns from the target repository root."""
    ignore_file = root / ".vibeguardignore"
    if not ignore_file.is_file():
        return []
    patterns: list[str] = []
    for raw in ignore_file.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if line and not line.startswith("#"):
            patterns.append(line)
    return patterns


def is_ignored(rel_path: str, patterns: Iterable[str]) -> bool:
    """Return True if relative path matches any ignore glob pattern."""
    for pat in patterns:
        if fnmatch.fnmatch(rel_path, pat) or fnmatch.fnmatch(Path(rel_path).name, pat):
            return True
    return False


def is_binary_file(path: Path) -> bool:
    """Heuristically identify binary files by extension and null-byte probe."""
    if path.suffix.lower() in BINARY_EXTENSIONS:
        return True
    try:
        with path.open("rb") as fh:
            chunk = fh.read(1024)
        return b"\x00" in chunk
    except OSError:
        return True


def collect_files(root: Path, extra_excludes: list[str]) -> list[Path]:
    """Walk target repository while skipping build artifacts and excluded paths."""
    ignore_patterns = load_ignore_patterns(root) + extra_excludes
    files: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(
            d for d in dirnames
            if d not in SKIP_DIRS
            and not is_ignored(Path(dirpath, d).relative_to(root).as_posix(), ignore_patterns)
        )
        for name in sorted(filenames):
            full = Path(dirpath) / name
            rel = full.relative_to(root).as_posix()
            if is_ignored(rel, ignore_patterns):
                continue
            try:
                if full.stat().st_size > MAX_FILE_BYTES:
                    continue
            except OSError:
                continue
            files.append(full)
    return files


def detect_stack(root: Path, files: list[Path]) -> list[str]:
    """Identify frameworks, databases, AI SDKs, and infrastructure in the repo."""
    rel_paths = [f.relative_to(root).as_posix() for f in files]
    stack: set[str] = set()

    pkg_json = root / "package.json"
    pkg_text = ""
    if pkg_json.is_file():
        stack.add("Node.js")
        pkg_text = pkg_json.read_text(encoding="utf-8", errors="replace").lower()
        dep_map = {
            '"next"': "Next.js",
            '"react"': "React",
            '"vite"': "Vite",
            '"express"': "Express",
            '"fastify"': "Fastify",
            '"hono"': "Hono",
            '"@nestjs/core"': "NestJS",
            '"@supabase/': "Supabase",
            '"firebase': "Firebase",
            '"prisma"': "Prisma",
            '"drizzle-orm"': "Drizzle",
            '"stripe"': "Stripe",
            '"openai"': "AI/LLM (OpenAI)",
            '"@anthropic-ai/sdk"': "AI/LLM (Anthropic)",
            '"@google/genai"': "AI/LLM (Gemini)",
            '"@google/generative-ai"': "AI/LLM (Gemini)",
            '"langchain"': "AI/LLM (LangChain)",
            '"@modelcontextprotocol/': "MCP",
        }
        for needle, label in dep_map.items():
            if needle in pkg_text:
                stack.add(label)

    for rel in rel_paths:
        lower = rel.lower()
        if lower.endswith(("requirements.txt", "pyproject.toml", "pipfile")):
            stack.add("Python")
        if "supabase" in lower:
            stack.add("Supabase")
        if lower.endswith(("firebase.json", "firestore.rules", "storage.rules")):
            stack.add("Firebase")
        if Path(lower).name.startswith("dockerfile") or "docker-compose" in lower:
            stack.add("Docker")
        if lower.startswith(".github/workflows/") and lower.endswith((".yml", ".yaml")):
            stack.add("GitHub Actions")

    py_reqs = ""
    for candidate in ("pyproject.toml", "requirements.txt"):
        p = root / candidate
        if p.is_file():
            py_reqs += p.read_text(encoding="utf-8", errors="replace").lower()
    for needle, label in {
        "fastapi": "FastAPI",
        "django": "Django",
        "flask": "Flask",
        "openai": "AI/LLM (OpenAI)",
        "anthropic": "AI/LLM (Anthropic)",
        "google-genai": "AI/LLM (Gemini)",
        "langchain": "AI/LLM (LangChain)",
        "stripe": "Stripe",
        "supabase": "Supabase",
    }.items():
        if needle in py_reqs:
            stack.add(label)

    return sorted(stack)


def check_repo_and_git_hygiene(root: Path, files: list[Path]) -> list[Finding]:
    """Check git-tracked secrets, .gitignore coverage, and lockfile presence."""
    findings: list[Finding] = []
    rel_paths = [f.relative_to(root).as_posix() for f in files]

    # 1. Check tracked sensitive files if inside a git repository
    tracked_files: set[str] = set()
    if (root / ".git").exists() and shutil.which("git"):
        try:
            res = subprocess.run(
                ["git", "-C", str(root), "ls-files"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            if res.returncode == 0:
                tracked_files = {line.strip() for line in res.stdout.splitlines() if line.strip()}
        except (OSError, subprocess.SubprocessError):
            pass

    for rel in sorted(tracked_files):
        if SENSITIVE_FILE_RE.search(rel) and not TEST_OR_EXAMPLE_PATH_RE.search(rel):
            findings.append(
                Finding(
                    rule_id="SEC-020",
                    title="Sensitive Environment or Key File Tracked by Git",
                    severity="CRITICAL",
                    scope="Internal Security",
                    category="Secrets",
                    cwe="CWE-312",
                    file=rel,
                    line=1,
                    evidence=f"Git tracks sensitive file: {rel}",
                    impact="Everyone who clones or reads the repository (and full git history) obtains these credentials.",
                    remediation="Remove with `git rm --cached`, add to `.gitignore`, rotate all secrets inside, and purge git history.",
                )
            )

    # 2. Check .env presence vs .gitignore protection
    gitignore_path = root / ".gitignore"
    gitignore_text = gitignore_path.read_text(encoding="utf-8", errors="replace") if gitignore_path.is_file() else ""
    env_ignored = bool(re.search(r"^\s*/?\.env(?:\*|\.\*)?\s*$", gitignore_text, re.MULTILINE))
    for rel in rel_paths:
        name = Path(rel).name
        if ENV_FILENAME_RE.match(name) and not ENV_SAFE_SUFFIX_RE.search(name):
            if rel not in tracked_files and not env_ignored:
                findings.append(
                    Finding(
                        rule_id="SEC-021",
                        title="Local `.env` File Exists Without `.gitignore` Rule",
                        severity="HIGH",
                        scope="Internal Security",
                        category="Secrets",
                        cwe="CWE-538",
                        file=rel,
                        line=1,
                        evidence=f"Found `{rel}` while `.gitignore` lacks `.env` protection",
                        impact="One accidental `git add .` will commit all local and production secrets into version control.",
                        remediation="Add `.env` and `.env.*` (with `!.env.example`) to `.gitignore` immediately.",
                    )
                )

    # 3. Check lockfile presence for reproducible supply chain
    names = {Path(r).name for r in rel_paths}
    if "package.json" in names and not (names & {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "bun.lockb", "bun.lock"}):
        findings.append(
            Finding(
                rule_id="INFRA-010",
                title="Missing JavaScript Dependency Lockfile",
                severity="LOW",
                scope="Internal Security",
                category="Supply Chain",
                cwe="CWE-829",
                file="package.json",
                line=1,
                evidence="Found package.json without package-lock.json, pnpm-lock.yaml, yarn.lock, or bun.lock",
                impact="Builds resolve floating dependency versions, making the project vulnerable to unreviewed upstream updates or dependency hijacking.",
                remediation="Generate and commit a lockfile (`npm install` / `pnpm install`) and use `npm ci` in CI/CD.",
            )
        )

    # 4. Flag unprotected debug/seed/test-auth route filenames
    debug_route_re = re.compile(r"(?:^|/)(?:api|routes?)/(?:.*[/._-])?(?:debug|seed|reset[-_]?db|test[-_]?auth|dev[-_]?login)\b", re.IGNORECASE)
    for rel in rel_paths:
        if debug_route_re.search(rel) and not TEST_OR_EXAMPLE_PATH_RE.search(rel):
            findings.append(
                Finding(
                    rule_id="OPS-003",
                    title="Potential Debug, Seed, or Dev-Login Endpoint Found",
                    severity="HIGH",
                    scope="Internal Security",
                    category="Internal Ops",
                    cwe="CWE-489",
                    file=rel,
                    line=1,
                    evidence=f"Route path suggests internal debug/seed handler: {rel}",
                    impact="Vibe-coded debug or DB-reset endpoints left exposed in production let attackers wipe data or bypass auth.",
                    remediation="Delete debug/seed routes before shipping, or hard-block them when `NODE_ENV === 'production'` plus strict admin auth.",
                    confidence="MEDIUM",
                )
            )

    return findings


def check_file_level_rules(root: Path, files: list[Path]) -> list[Finding]:
    """Run multi-line structural checks (Docker USER, Supabase RLS, CORS+Credentials, PR target)."""
    findings: list[Finding] = []
    sql_created_tables: list[tuple[str, int, str]] = []
    sql_rls_enabled: set[str] = set()

    for path in files:
        rel = path.relative_to(root).as_posix()
        name = path.name.lower()
        if name in LOCKFILES or is_binary_file(path):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        # Dockerfile: missing USER directive
        if name == "dockerfile" or name.startswith("dockerfile."):
            if re.search(r"^\s*FROM\s+", text, re.MULTILINE) and not re.search(r"^\s*USER\s+(?!root\b)\S+", text, re.MULTILINE):
                findings.append(
                    Finding(
                        rule_id="INFRA-006",
                        title="Dockerfile Runs Container as `root` User",
                        severity="MEDIUM",
                        scope="Internal Security",
                        category="CI/CD & Infra",
                        cwe="CWE-250",
                        file=rel,
                        line=1,
                        evidence="No non-root `USER` instruction found in Dockerfile",
                        impact="If an attacker exploits an app flaw, running as root makes container breakout and host persistence easier.",
                        remediation="Create a non-root user and add `USER node` (or a dedicated app user) before `CMD`/`ENTRYPOINT`.",
                    )
                )

        # GitHub Actions: pull_request_target + PR head checkout
        if rel.lower().startswith(".github/workflows/") and rel.lower().endswith((".yml", ".yaml")):
            if "pull_request_target" in text and re.search(r"github\.event\.pull_request\.head", text):
                findings.append(
                    Finding(
                        rule_id="INFRA-007",
                        title="Dangerous `pull_request_target` Checking Out Untrusted PR Code",
                        severity="CRITICAL",
                        scope="Internal Security",
                        category="CI/CD & Infra",
                        cwe="CWE-829",
                        file=rel,
                        line=1,
                        evidence="Workflow combines `pull_request_target` with `pull_request.head` checkout",
                        impact="Untrusted fork PRs run with full repository secrets and write permissions.",
                        remediation="Use standard `pull_request` trigger for untrusted code builds, or split secret-requiring steps into a separate workflow.",
                    )
                )

        # CORS wildcard + credentials in same file
        if re.search(r"(?:origin\s*:\s*(?:true|['\"]\*['\"])|allow_origins\s*=\s*\[\s*['\"]\*['\"]\s*\])", text) and re.search(
            r"(?:credentials\s*:\s*true|allow_credentials\s*=\s*True)", text
        ):
            findings.append(
                Finding(
                    rule_id="API-003",
                    title="Wildcard CORS Combined with `credentials: true`",
                    severity="HIGH",
                    scope="External AppSec",
                    category="API/CORS",
                    cwe="CWE-942",
                    file=rel,
                    line=1,
                    evidence="File configures permissive CORS origin alongside `credentials: true`",
                    impact="Allows malicious external websites to make authenticated cross-origin requests on behalf of logged-in users.",
                    remediation="Replace wildcard/reflected origin with a strict allowlist of trusted origins.",
                )
            )

        # Supabase / Postgres SQL migration RLS check
        if path.suffix.lower() == ".sql" and "supabase" in rel.lower():
            for idx, line in enumerate(text.splitlines(), start=1):
                m_create = re.search(r"CREATE\s+TABLE(?:\s+IF\s+NOT\s+EXISTS)?\s+(?:public\.)?\"?([A-Za-z0-9_]+)\"?", line, re.IGNORECASE)
                if m_create:
                    sql_created_tables.append((rel, idx, m_create.group(1).lower()))
                m_rls = re.search(r"ALTER\s+TABLE\s+(?:public\.)?\"?([A-Za-z0-9_]+)\"?\s+ENABLE\s+ROW\s+LEVEL\s+SECURITY", line, re.IGNORECASE)
                if m_rls:
                    sql_rls_enabled.add(m_rls.group(1).lower())

    for rel, idx, table_name in sql_created_tables:
        if table_name not in sql_rls_enabled:
            findings.append(
                Finding(
                    rule_id="IAM-006",
                    title=f"Supabase Table `{table_name}` Missing `ENABLE ROW LEVEL SECURITY`",
                    severity="HIGH",
                    scope="Internal Security",
                    category="BaaS/DB",
                    cwe="CWE-284",
                    file=rel,
                    line=idx,
                    evidence=f"CREATE TABLE {table_name} found without matching ENABLE ROW LEVEL SECURITY",
                    impact="Without RLS enabled, anyone with the public Supabase `anon` key can query or modify all rows directly via PostgREST.",
                    remediation=f"Add `ALTER TABLE public.{table_name} ENABLE ROW LEVEL SECURITY;` and define explicit least-privilege policies.",
                )
            )

    return findings


def scan_lines(root: Path, files: list[Path], rules: list[LineRule]) -> tuple[list[Finding], int, int]:
    """Evaluate all declarative LineRules across discovered text files."""
    findings: list[Finding] = []
    scanned_files = 0
    suppressed = 0

    for path in files:
        rel = path.relative_to(root).as_posix()
        name = path.name
        if name in LOCKFILES or path.suffix.lower() in {".md", ".mdx", ".txt", ".rst"}:
            continue
        if is_binary_file(path):
            continue

        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        scanned_files += 1
        ext = path.suffix.lower()
        in_test = bool(TEST_OR_EXAMPLE_PATH_RE.search(rel))
        lines = content.splitlines()

        applicable_rules = [
            r for r in rules
            if (r.extensions is None or ext in r.extensions)
            and (r.path_pattern is None or r.path_pattern.search(rel))
            and (r.exclude_pattern is None or not r.exclude_pattern.search(rel))
        ]
        if not applicable_rules:
            continue

        for line_no, line in enumerate(lines, start=1):
            stripped = line.lstrip()
            if not stripped:
                continue
            is_comment = stripped.startswith(("#", "//", "/*", "*"))
            prev_line = lines[line_no - 2] if line_no >= 2 else ""
            line_suppressed = bool(
                re.search(r"\bvibeguard-ignore(?!-next-line)\b", line)
                or re.search(r"\bvibeguard-ignore-next-line\b", prev_line)
            )

            matched_on_line = False
            for rule in applicable_rules:
                if is_comment and rule.category != "Secrets":
                    continue
                match = rule.pattern.search(line)
                if not match:
                    continue
                if rule.skip_placeholders and PLACEHOLDER_VALUE_RE.search(line):
                    continue
                if line_suppressed:
                    matched_on_line = True
                    continue

                severity = rule.severity
                if in_test and severity in {"CRITICAL", "HIGH"}:
                    severity = "LOW" if rule.category != "Secrets" else "MEDIUM"

                evidence = redact_secret(line) if rule.redact else line.strip()[:180]
                findings.append(
                    Finding(
                        rule_id=rule.rule_id,
                        title=rule.title,
                        severity=severity,
                        scope=rule.scope,
                        category=rule.category,
                        cwe=rule.cwe,
                        file=rel,
                        line=line_no,
                        evidence=evidence,
                        impact=rule.impact,
                        remediation=rule.remediation,
                        confidence=rule.confidence,
                        in_test_or_example=in_test,
                    )
                )
            if line_suppressed and matched_on_line:
                suppressed += 1

    return findings, scanned_files, suppressed


def discover_audit_surfaces(root: Path, files: list[Path]) -> dict[str, list[str]]:
    """Index high-risk files for Phase 2 AI contextual auditing (auth, IDOR, AI, BaaS)."""
    surfaces: dict[str, list[str]] = {
        "api_and_server_routes": [],
        "auth_and_middleware": [],
        "baas_and_db": [],
        "payments_and_webhooks": [],
        "ai_and_agentic": [],
        "ci_and_containers": [],
    }
    api_re = re.compile(r"(?:^|/)(?:app/api|src/app/api|pages/api|src/pages/api|api|routes|controllers|actions|trpc)/", re.IGNORECASE)
    auth_re = re.compile(r"(?:^|/)(?:middleware|auth|session|rbac|permissions|guard)[^/]*\.(?:js|jsx|ts|tsx|py|go|rb)$", re.IGNORECASE)
    baas_re = re.compile(r"(?:firestore\.rules|storage\.rules|schema\.prisma|drizzle|supabase/.*\.sql)$", re.IGNORECASE)
    pay_re = re.compile(r"(?:stripe|webhook|billing|checkout|payment|subscription)", re.IGNORECASE)
    ai_re = re.compile(r"(?:chat|ai|llm|agent|prompt|mcp|openai|anthropic|gemini)", re.IGNORECASE)
    infra_re = re.compile(r"(?:^\.github/workflows/.*\.ya?ml$|dockerfile|docker-compose.*\.ya?ml$)", re.IGNORECASE)

    for path in files:
        rel = path.relative_to(root).as_posix()
        if TEST_OR_EXAMPLE_PATH_RE.search(rel):
            continue
        if api_re.search(rel) or rel.endswith(("route.ts", "route.js", "views.py", "router.py")):
            surfaces["api_and_server_routes"].append(rel)
        if auth_re.search(rel):
            surfaces["auth_and_middleware"].append(rel)
        if baas_re.search(rel):
            surfaces["baas_and_db"].append(rel)
        if pay_re.search(rel):
            surfaces["payments_and_webhooks"].append(rel)
        if ai_re.search(rel) and path.suffix.lower() in CODE_EXTS:
            surfaces["ai_and_agentic"].append(rel)
        if infra_re.search(rel):
            surfaces["ci_and_containers"].append(rel)

    return {k: v[:50] for k, v in surfaces.items()}


def run_ecosystem_audits(root: Path) -> list[Finding]:
    """Optionally run npm/pip dependency audits if tools are installed."""
    findings: list[Finding] = []
    if (root / "package-lock.json").is_file() and shutil.which("npm"):
        try:
            proc = subprocess.run(
                ["npm", "audit", "--json"],
                cwd=str(root),
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            data = json.loads(proc.stdout or "{}")
            vulns = data.get("vulnerabilities", {})
            for pkg_name, meta in list(vulns.items())[:25]:
                sev = str(meta.get("severity", "medium")).upper()
                if sev == "MODERATE":
                    sev = "MEDIUM"
                if sev not in SEVERITY_ORDER:
                    sev = "MEDIUM"
                findings.append(
                    Finding(
                        rule_id="DEP-NPM",
                        title=f"Vulnerable npm Dependency `{pkg_name}`",
                        severity=sev,
                        scope="External AppSec",
                        category="Supply Chain",
                        cwe="CWE-1395",
                        file="package.json",
                        line=1,
                        evidence=f"npm audit reported {sev} vulnerability in {pkg_name}",
                        impact="Known vulnerabilities in transitive or direct dependencies can expose the app to RCE, prototype pollution, or DoS.",
                        remediation=f"Run `npm audit fix` or upgrade `{pkg_name}` to a patched version.",
                    )
                )
        except (OSError, subprocess.SubprocessError, json.JSONDecodeError):
            pass

    if (root / "requirements.txt").is_file() and shutil.which("pip-audit"):
        try:
            proc = subprocess.run(
                ["pip-audit", "-r", "requirements.txt", "-f", "json"],
                cwd=str(root),
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            data = json.loads(proc.stdout or "{}")
            for dep in data.get("dependencies", [])[:25]:
                for vuln in dep.get("vulns", [])[:2]:
                    findings.append(
                        Finding(
                            rule_id="DEP-PIP",
                            title=f"Vulnerable Python Package `{dep.get('name')}` ({vuln.get('id', 'CVE')})",
                            severity="HIGH",
                            scope="External AppSec",
                            category="Supply Chain",
                            cwe="CWE-1395",
                            file="requirements.txt",
                            line=1,
                            evidence=f"pip-audit reported {vuln.get('id')} in {dep.get('name')}=={dep.get('version')}",
                            impact="Known Python package vulnerability can expose the backend to security exploits.",
                            remediation=f"Upgrade `{dep.get('name')}` to a fixed version: {', '.join(vuln.get('fix_versions', []) or ['latest'])}.",
                        )
                    )
        except (OSError, subprocess.SubprocessError, json.JSONDecodeError):
            pass
    return findings


def compute_score(findings: list[Finding]) -> tuple[int, str]:
    """Compute a 0-100 Security Posture Score and Risk Rating."""
    penalty = 0
    for f in findings:
        weight = SEVERITY_WEIGHTS.get(f.severity, 0)
        if f.in_test_or_example:
            weight = max(1, weight // 4)
        penalty += weight
    score = max(0, 100 - min(100, penalty))
    if any(f.severity == "CRITICAL" and not f.in_test_or_example for f in findings) or score < 40:
        grade = "CRITICAL RISK"
    elif any(f.severity == "HIGH" and not f.in_test_or_example for f in findings) or score < 70:
        grade = "HIGH RISK"
    elif score < 88:
        grade = "MODERATE RISK"
    elif findings:
        grade = "LOW RISK"
    else:
        grade = "HARDENED"
    return score, grade


def dedup_and_sort(findings: list[Finding], min_severity: str) -> list[Finding]:
    """Deduplicate identical rule+location matches and sort by severity then location."""
    min_rank = SEVERITY_ORDER[min_severity]
    seen: set[tuple[str, str, int]] = set()
    unique: list[Finding] = []
    for f in findings:
        if SEVERITY_ORDER.get(f.severity, 4) > min_rank:
            continue
        key = (f.rule_id, f.file, f.line)
        if key in seen:
            continue
        seen.add(key)
        unique.append(f)

    unique.sort(key=lambda x: (SEVERITY_ORDER.get(x.severity, 99), x.file, x.line, x.rule_id))
    return unique


def _md_cell(value: str) -> str:
    """Escape pipe characters and normalize whitespace for Markdown table cells."""
    return " ".join(value.replace("|", "\\|").splitlines()).strip()


def render_markdown(report: dict) -> str:
    """Render a clean Executive Scorecard and unified Markdown Vulnerability Table."""
    summary = report["summary"]
    counts = summary["counts_by_severity"]
    lines = [
        "# VibeGuard Security & Internal Audit Report",
        "",
        f"- **Target**: `{report['target']}`",
        f"- **Detected Stack**: {', '.join(report['stack']) if report['stack'] else 'Generic / Unclassified'}",
        f"- **Files Scanned**: {summary['files_scanned']} (Suppressed via inline ignore: {summary['suppressed_count']})",
        f"- **Security Score**: **{summary['score']}/100** ({summary['risk_rating']})",
        f"- **Findings**: CRITICAL `{counts['CRITICAL']}` | HIGH `{counts['HIGH']}` | MEDIUM `{counts['MEDIUM']}` | LOW `{counts['LOW']}` | INFO `{counts['INFO']}`",
        f"- **Audit Breakdown**: External AppSec `{summary['counts_by_scope']['External AppSec']}` | Internal Security `{summary['counts_by_scope']['Internal Security']}`",
        "",
        "## Vulnerability & Internal Security Table",
        "",
    ]
    if not report["findings"]:
        lines.append("No static security issues detected by the automated scanner. Proceed to Phase 2 manual contextual review (auth, IDOR, business logic).")
        return "\n".join(lines)

    lines.extend([
        "| ID | Severity | Audit Scope | Category | CWE | Location | Finding & Impact | Recommended Fix |",
        "| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |",
    ])
    for idx, f in enumerate(report["findings"], start=1):
        vid = f"VG-{idx:03d}"
        loc = f"`{f['file']}:{f['line']}`"
        test_tag = " *(test/example)*" if f["in_test_or_example"] else ""
        finding_col = f"**{_md_cell(f['title'])}**{test_tag} — {_md_cell(f['impact'])}"
        lines.append(
            f"| {vid} | **{f['severity']}** | {f['scope']} | {f['category']} | {f['cwe']} | {loc} | {finding_col} | {_md_cell(f['remediation'])} |"
        )
    return "\n".join(lines)


def scan_repository(
    target_path: Path,
    min_severity: str = "INFO",
    extra_excludes: Optional[list[str]] = None,
    ecosystem_audits: bool = False,
) -> dict:
    """Execute complete deterministic scan and return structured report dictionary."""
    root = target_path.resolve()
    files = collect_files(root, extra_excludes or [])
    stack = detect_stack(root, files)
    audit_surfaces = discover_audit_surfaces(root, files)
    rules = build_rules()

    findings: list[Finding] = []
    findings.extend(check_repo_and_git_hygiene(root, files))
    findings.extend(check_file_level_rules(root, files))
    line_findings, scanned_count, suppressed_count = scan_lines(root, files, rules)
    findings.extend(line_findings)
    if ecosystem_audits:
        findings.extend(run_ecosystem_audits(root))

    final_findings = dedup_and_sort(findings, min_severity)
    score, grade = compute_score(final_findings)

    counts_sev = {k: 0 for k in SEVERITY_ORDER}
    counts_scope = {"External AppSec": 0, "Internal Security": 0}
    for f in final_findings:
        counts_sev[f.severity] = counts_sev.get(f.severity, 0) + 1
        counts_scope[f.scope] = counts_scope.get(f.scope, 0) + 1

    return {
        "target": str(root),
        "stack": stack,
        "audit_surfaces": audit_surfaces,
        "summary": {
            "files_scanned": scanned_count,
            "total_discovered_files": len(files),
            "suppressed_count": suppressed_count,
            "total_findings": len(final_findings),
            "score": score,
            "risk_rating": grade,
            "counts_by_severity": counts_sev,
            "counts_by_scope": counts_scope,
        },
        "findings": [dataclasses.asdict(f) for f in final_findings],
    }


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="VibeGuard Security & Internal Audit Scanner")
    parser.add_argument("--path", default=".", help="Target repository path (default: current directory)")
    parser.add_argument("--format", choices=["json", "markdown", "both"], default="json", help="Output format")
    parser.add_argument("--severity", choices=list(SEVERITY_ORDER.keys()), default="INFO", help="Minimum severity to report")
    parser.add_argument("--exclude", action="append", default=[], help="Extra glob patterns to exclude")
    parser.add_argument("--run-ecosystem-audits", action="store_true", help="Also run npm audit if lockfile & tool exist")
    parser.add_argument("--fail-on", choices=list(SEVERITY_ORDER.keys()), default=None, help="Exit with code 1 if any finding meets or exceeds severity")
    args = parser.parse_args(argv)

    target = Path(args.path)
    if not target.exists():
        print(f"Error: target path does not exist: {target}", file=sys.stderr)
        return 2

    report = scan_repository(
        target_path=target,
        min_severity=args.severity,
        extra_excludes=args.exclude,
        ecosystem_audits=args.run_ecosystem_audits,
    )

    if args.format in {"json", "both"}:
        print(json.dumps(report, indent=2))
    if args.format == "both":
        print("\n---\n")
    if args.format in {"markdown", "both"}:
        print(render_markdown(report))

    if args.fail_on:
        threshold = SEVERITY_ORDER[args.fail_on]
        if any(SEVERITY_ORDER[f["severity"]] <= threshold and not f["in_test_or_example"] for f in report["findings"]):
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
