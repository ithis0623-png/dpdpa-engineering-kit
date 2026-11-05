"""Runs the workflow's own shell steps against small fixture repositories.

The step scripts are read from the workflow file, so the tests cover exactly
what CI would run. Needs bash and GNU grep (Git Bash on Windows works).
"""
import subprocess
from pathlib import Path

import pytest
import yaml
from conftest import find_bash

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = yaml.safe_load((ROOT / "github" / "dpdpa-privacy-checks.yml").read_text(encoding="utf-8"))
BASH = find_bash()

pytestmark = pytest.mark.skipif(BASH is None, reason="bash is not installed")


def step(job: str, name: str) -> str:
    return next(s["run"] for s in WORKFLOW["jobs"][job]["steps"] if s.get("name") == name)


def run_step(script: str, files: dict[str, str], tmp_path: Path) -> subprocess.CompletedProcess:
    for rel, content in files.items():
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    return subprocess.run([BASH, "-c", script], cwd=tmp_path, capture_output=True, text=True, check=False)  # noqa: S603


PII_LOG = step("sast-privacy-scan", "Detect PII in log statements")
PII_FIXTURES = step("sast-privacy-scan", "Scan for hardcoded test data with real PII patterns")


@pytest.mark.parametrize(
    "line",
    [
        'logger.info("user %s", user.aadhaar)',
        'logger.debug(f"sent OTP to {phone}")',
        'print("pan", pan_number)',
    ],
)
def test_pii_in_logs_fails_the_gate(line, tmp_path):
    result = run_step(PII_LOG, {"src/app.py": line + "\n"}, tmp_path)
    assert result.returncode == 1
    assert "DPDPA Gate 1 FAILED" in result.stdout


def test_clean_logging_passes_the_gate(tmp_path):
    result = run_step(PII_LOG, {"src/app.py": 'logger.info("order %s shipped", order_id)\n'}, tmp_path)
    assert result.returncode == 0, result.stdout


@pytest.mark.parametrize("number", ["2345 6789 0123", "2345-6789-0123"])
def test_aadhaar_shaped_fixtures_are_flagged(number, tmp_path):
    result = run_step(PII_FIXTURES, {"tests/fixtures.json": f'{{"aadhaar": "{number}"}}\n'}, tmp_path)
    assert result.returncode == 0  # a warning, not a failure
    assert "Potential real PII" in result.stdout


def test_pan_shaped_fixture_is_flagged(tmp_path):
    result = run_step(PII_FIXTURES, {"src/seed.py": 'PAN = "ABCDE1234F"\n'}, tmp_path)
    assert "Potential real PII" in result.stdout


def test_synthetic_fixtures_are_not_flagged(tmp_path):
    files = {"tests/fixtures.json": '{"aadhaar": "XXXX XXXX 0123", "order": 123456789012345}\n'}
    result = run_step(PII_FIXTURES, files, tmp_path)
    assert "Potential real PII" not in result.stdout


def test_article_regex_missed_space_separated_aadhaar(tmp_path):
    """The published pattern put \\s inside [...], where it is a literal backslash or 's'."""
    original = PII_FIXTURES.replace("[[:space:]-]", r"[\s-]")
    result = run_step(original, {"tests/fixtures.json": '{"aadhaar": "2345 6789 0123"}\n'}, tmp_path)
    assert "Potential real PII" not in result.stdout


def test_gate3_runs_the_kits_erasure_script():
    script = step("privacy-deployment-gate", "Verify erasure capability exists (Section 8(7))")
    assert "scripts/check_erasure_support.py" in script
    assert (ROOT / "scripts" / "check_erasure_support.py").exists()


def test_every_action_is_pinned_to_a_commit():
    uses = [s["uses"] for job in WORKFLOW["jobs"].values() for s in job.get("steps", []) if "uses" in s]
    assert uses
    for ref in uses:
        sha = ref.partition("@")[2]
        assert len(sha) == 40 and all(c in "0123456789abcdef" for c in sha), ref
