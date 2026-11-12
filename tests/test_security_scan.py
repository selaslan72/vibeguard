#!/usr/bin/env python3
"""Unit and integration tests for VibeGuard security_scan.py."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SCANNER_PATH = REPO_ROOT / "skills" / "vibeguard" / "scripts" / "security_scan.py"
sys.path.insert(0, str(SCANNER_PATH.parent))

import security_scan  # noqa: E402


class SecurityScanTests(unittest.TestCase):
    """Test suite covering External AppSec, Internal Security, redaction, and CLI behavior."""

    def _write(self, root: Path, rel: str, content: str) -> Path:
        target = root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
        return target

    def test_detects_secrets_and_redacts_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            # Construct synthetic secret tokens dynamically so no raw tokens sit in git source.
            fake_openai = "sk-proj-" + "AbCdEfGhIjKlMnOpQrStUvWxYz123456"
            fake_stripe = "sk_live_" + "9876543210ZyXwVuTsRqPoNmLk"
            fake_gh = "ghp_" + "A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q7R8"
            fake_db = "postgresql://admin:Sup3rS3cretP@ss@prod-db.internal:5432/app"

            self._write(
                root,
                "src/config.ts",
                "\n".join([
                    f'export const openaiKey = "{fake_openai}";',
                    f'export const stripeKey = "{fake_stripe}";',
                    f'export const ghToken = "{fake_gh}";',
                    f'export const dbUrl = "{fake_db}";',
                ]),
            )
            self._write(
                root,
                ".env.local",
                "NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9_dummy_payload\n",
            )

            report = security_scan.scan_repository(root)
            rule_ids = {f["rule_id"] for f in report["findings"]}

            self.assertIn("SEC-001", rule_ids)
            self.assertIn("SEC-006", rule_ids)
            self.assertIn("SEC-005", rule_ids)
            self.assertIn("SEC-009", rule_ids)
            self.assertIn("SEC-010", rule_ids)
            self.assertIn("SEC-021", rule_ids)  # .env.local without .gitignore

            serialized = json.dumps(report)
            self.assertNotIn(fake_openai, serialized)
            self.assertNotIn(fake_stripe, serialized)
            self.assertNotIn(fake_gh, serialized)
            self.assertNotIn("Sup3rS3cretP@ss", serialized)

    def test_detects_injection_auth_and_cors(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._write(
                root,
                "package.json",
                json.dumps({"name": "demo", "dependencies": {"next": "15.0.0", "openai": "4.0.0"}}),
            )
            self._write(
                root,
                "app/api/users/route.ts",
                """
import jwt from "jsonwebtoken";
const SECRET = process.env.JWT_SECRET || "dev-fallback-secret";

export async function POST(req: Request) {
  const body = await req.json();
  const payload = jwt.decode(body.token);
  const rows = await prisma.$queryRawUnsafe(`SELECT * FROM users WHERE email = '${body.email}'`);
  await prisma.user.create({ data: req.body });
  return Response.json({ rows, payload });
}
""",
            )
            self._write(
                root,
                "server/cors.ts",
                """
export const corsOptions = {
  origin: "*",
  credentials: true,
};
""",
            )
            self._write(
                root,
                "backend/app.py",
                """
import subprocess, yaml
DEBUG = True
def run_cmd(user_arg):
    yaml.load(user_arg)
    return subprocess.run(f"ls {user_arg}", shell=True)
""",
            )

            report = security_scan.scan_repository(root)
            rule_ids = {f["rule_id"] for f in report["findings"]}

            self.assertIn("AUTH-001", rule_ids)
            self.assertIn("AUTH-002", rule_ids)
            self.assertIn("INJ-001", rule_ids)
            self.assertIn("INJ-002", rule_ids)
            self.assertIn("INJ-005", rule_ids)
            self.assertIn("IAM-004", rule_ids)
            self.assertIn("API-001", rule_ids)
            self.assertIn("API-002", rule_ids)
            self.assertIn("API-003", rule_ids)
            self.assertIn("INFRA-010", rule_ids)  # package.json without lockfile
            self.assertIn("Next.js", report["stack"])
            self.assertIn("app/api/users/route.ts", report["audit_surfaces"]["api_and_server_routes"])

    def test_detects_internal_security_baas_ai_and_infra(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._write(
                root,
                "src/components/AdminPanel.tsx",
                """
"use client";
import { createClient } from "@supabase/supabase-js";
const key = process.env.SUPABASE_SERVICE_ROLE_KEY;
export function AdminPanel({ bio, llmOutput }: { bio: string; llmOutput: string }) {
  console.log("Auth header:", req.headers.authorization);
  eval(llmOutput);
  return <div dangerouslySetInnerHTML={{ __html: bio }} />;
}
""",
            )
            self._write(
                root,
                "app/api/chat/route.ts",
                """
export async function POST(req: Request) {
  const { prompt } = await req.json();
  const messages = [{ role: "system", content: `Follow instructions for ${prompt}` }];
  return Response.json(messages);
}
""",
            )
            self._write(root, "app/api/debug/route.ts", "export async function GET() { return Response.json({ ok: true }); }\n")
            self._write(root, "firestore.rules", "rules_version = '2';\nservice cloud.firestore {\n  match /databases/{d}/documents {\n    match /{doc=**} { allow read, write: if true; }\n  }\n}\n")
            self._write(
                root,
                "supabase/migrations/001_init.sql",
                """
CREATE TABLE public.invoices (id uuid primary key, total int);
CREATE TABLE public.profiles (id uuid primary key);
ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;
CREATE POLICY "open" ON public.profiles FOR ALL USING (true);
""",
            )
            self._write(
                root,
                ".github/workflows/ci.yml",
                """
on: pull_request_target
permissions: write-all
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: echo "${{ github.event.issue.title }}"
""",
            )
            self._write(root, "Dockerfile", "FROM node:20-alpine\nRUN curl -sSL https://example.com/install.sh | bash\nCMD [\"node\", \"index.js\"]\n")
            self._write(root, "docker-compose.yml", "services:\n  web:\n    privileged: true\n")

            report = security_scan.scan_repository(root)
            rule_ids = {f["rule_id"] for f in report["findings"]}

            self.assertIn("IAM-001", rule_ids)
            self.assertIn("IAM-002", rule_ids)
            self.assertIn("IAM-003", rule_ids)
            self.assertIn("IAM-006", rule_ids)
            self.assertIn("OPS-001", rule_ids)
            self.assertIn("OPS-003", rule_ids)
            self.assertIn("INJ-003", rule_ids)
            self.assertIn("AI-001", rule_ids)
            self.assertIn("AI-002", rule_ids)
            self.assertIn("INFRA-001", rule_ids)
            self.assertIn("INFRA-002", rule_ids)
            self.assertIn("INFRA-003", rule_ids)
            self.assertIn("INFRA-004", rule_ids)
            self.assertIn("INFRA-006", rule_ids)
            self.assertIn("INFRA-007", rule_ids)
            self.assertEqual(report["summary"]["risk_rating"], "CRITICAL RISK")

    def test_clean_hardened_project_and_suppressions(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._write(root, ".gitignore", ".env\n.env.*\n!.env.example\n")
            self._write(root, ".env.example", "OPENAI_API_KEY=your-openai-api-key-placeholder\n")
            self._write(root, "package.json", '{"name":"clean-app","dependencies":{"next":"15.0.0"}}')
            self._write(root, "package-lock.json", "{}")
            self._write(
                root,
                "src/app/api/items/route.ts",
                """
import { auth } from "@/lib/auth";
export async function GET() {
  const session = await auth();
  if (!session) return Response.json({ error: "Unauthorized" }, { status: 401 });
  const items = await prisma.item.findMany({ where: { userId: session.user.id } });
  return Response.json({ items });
}
""",
            )
            self._write(
                root,
                "src/lib/legacy.ts",
                """
// Note: never call eval(userInput) here in production
// vibeguard-ignore-next-line
export const legacyHtml = (el: HTMLElement, safeStatic: string) => { el.innerHTML = safeStatic; };
""",
            )
            self._write(
                root,
                "Dockerfile",
                "FROM node:20-alpine\nUSER node\nCMD [\"node\", \"server.js\"]\n",
            )

            report = security_scan.scan_repository(root)
            self.assertEqual(report["summary"]["total_findings"], 0)
            self.assertEqual(report["summary"]["score"], 100)
            self.assertEqual(report["summary"]["risk_rating"], "HARDENED")
            self.assertEqual(report["summary"]["suppressed_count"], 1)

    def test_commented_secrets_still_detected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fake_aws = "AKIA" + "9876543210ABCDEF"
            self._write(root, "src/index.ts", f"// old key: {fake_aws}\n// eval(x)\n")

            report = security_scan.scan_repository(root)
            rule_ids = {f["rule_id"] for f in report["findings"]}
            self.assertIn("SEC-004", rule_ids)
            self.assertNotIn("INJ-004", rule_ids)

    def test_cli_markdown_output_and_fail_on_exit_code(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._write(root, "app.py", "DEBUG = True\n")

            proc = subprocess.run(
                [sys.executable, str(SCANNER_PATH), "--path", str(root), "--format", "markdown", "--fail-on", "HIGH"],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 1)
            self.assertIn("| ID | Severity | Audit Scope |", proc.stdout)
            self.assertIn("VG-001", proc.stdout)
            self.assertIn("API-002" if "API-002" in proc.stdout else "Framework Debug Mode Enabled in Code", proc.stdout)


if __name__ == "__main__":
    unittest.main()
