"""Regression tests for the stale audit exemption check (no network required)."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "contrib/check-stale-audit-ignores.sh"
ADVISORY = "RUSTSEC-2026-0001"


class AuditExemptionTests(unittest.TestCase):
    def run_check(self, report, status=0, provider_failure=False):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(["git", "init", "-q", directory], check=True)
            (root / ".cargo").mkdir()
            (root / ".cargo/audit.toml").write_text(f'ignore = ["{ADVISORY}"]\n')
            (root / ".github/workflows").mkdir(parents=True)
            (root / ".github/workflows/audit.yml").write_text("")
            (root / "Cargo.lock").touch()
            if provider_failure:
                (root / "rosec-bitwarden-pm").mkdir()
                (root / "rosec-bitwarden-pm/Cargo.lock").touch()
            (root / "cargo").write_text(
                '#!/usr/bin/env python3\nimport os, sys\n'
                'if os.environ["PROVIDER_FAILURE"] == "1" and "rosec-bitwarden-pm" in sys.argv[3]:\n'
                '    print("provider audit failed", file=sys.stderr)\n    sys.exit(2)\n'
                'print(os.environ["AUDIT_REPORT"])\n'
                'sys.exit(int(os.environ["AUDIT_STATUS"]))\n'
            )
            (root / "cargo").chmod(0o755)
            env = dict(os.environ, PATH=f"{root}:{os.environ['PATH']}",
                       AUDIT_REPORT=report, AUDIT_STATUS=str(status),
                       PROVIDER_FAILURE=str(int(provider_failure)))
            return subprocess.run(["bash", str(SCRIPT)], cwd=root, env=env,
                                  text=True, capture_output=True)

    def matching_report(self):
        return json.dumps({"vulnerabilities": {"list": [{"advisory": {"id": ADVISORY}}]}})

    def test_matching_advisory_accepts_audit_vulnerability_exit(self):
        result = self.run_check(self.matching_report(), status=1)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("All audit exemptions still apply", result.stdout)

    def test_stale_advisory_fails(self):
        result = self.run_check('{"vulnerabilities": {"list": []}}')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("STALE:", result.stdout)

    def test_invalid_json_reports_error_not_stale_exemption(self):
        result = self.run_check("invalid JSON", status=1)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("invalid cargo audit report", result.stderr)
        self.assertNotIn("STALE:", result.stdout)

    def test_missing_results_reports_error(self):
        result = self.run_check("{}", status=1)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("missing vulnerability results", result.stderr)

    def test_audit_execution_failure_propagates(self):
        result = self.run_check(self.matching_report(), status=2)
        self.assertEqual(result.returncode, 2)
        self.assertIn("cargo audit failed", result.stderr)

    def test_provider_audit_execution_failure_propagates(self):
        result = self.run_check(self.matching_report(), provider_failure=True)
        self.assertEqual(result.returncode, 2)
        self.assertIn("provider audit failed", result.stderr)
        self.assertNotIn("All audit exemptions still apply", result.stdout)


if __name__ == "__main__":
    unittest.main()
