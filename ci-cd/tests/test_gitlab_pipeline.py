"""Checks the GitLab pipeline. GitLab's own linter needs a GitLab instance, so this covers
structure and runs the PII grep step the same way test_workflow_gates.py does."""
import subprocess
from pathlib import Path

import pytest
import yaml
from bash_helper import find_bash

ROOT = Path(__file__).resolve().parents[1]
PIPELINE = yaml.safe_load((ROOT / "gitlab" / "gitlab-ci.yml").read_text(encoding="utf-8"))
JOB = PIPELINE["dpdpa-sast-scan"]
BASH = find_bash()


def test_job_uses_a_declared_stage():
    assert JOB["stage"] in PIPELINE["stages"]


def test_sast_report_is_in_gitlab_format():
    semgrep = JOB["script"][0]
    assert "--gitlab-sast" in semgrep
    assert "--json" not in semgrep
    assert semgrep.split("--output")[1].split()[0] == JOB["artifacts"]["reports"]["sast"]


def test_image_is_pinned():
    assert ":" in JOB["image"] and not JOB["image"].endswith(":latest")


@pytest.mark.skipif(BASH is None, reason="bash is not installed")
@pytest.mark.parametrize(
    "line, should_fail",
    [
        ('logger.info("user %s", user.aadhaar)', True),
        ('logger.debug(f"otp for {phone}")', True),
        ('ADDRESS_FIELDS = ["aadhar_masked", "phone"]  # not a log call', False),
        ('logger.info("order %s shipped", order_id)', False),
    ],
)
def test_pii_grep_step(line, should_fail, tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.py").write_text(line + "\n", encoding="utf-8")
    result = subprocess.run([BASH, "-c", JOB["script"][1]], cwd=tmp_path,  # noqa: S603
                            capture_output=True, text=True, check=False)
    assert (result.returncode == 1) is should_fail, result.stdout
