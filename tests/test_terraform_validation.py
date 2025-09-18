#!/usr/bin/env python3
"""Lightweight infrastructure validation executed during the test suite."""

import os
import shutil
import subprocess
from pathlib import Path

import pytest


TERRAFORM_ROOT = Path(__file__).resolve().parents[1] / "terraform" / "iam"


def _run_terraform_command(work_dir: Path, *args: str) -> subprocess.CompletedProcess:
    env = os.environ.copy()
    env.setdefault("TF_IN_AUTOMATION", "1")

    result = subprocess.run(
        ["terraform", *args],
        cwd=work_dir,
        check=False,
        capture_output=True,
        text=True,
        env=env,
    )

    if result.returncode != 0:
        stderr = result.stderr or ""
        provider_errors = (
            "Failed to query available provider packages" in stderr
            or "Failed to install provider" in stderr
            or "Could not connect to" in stderr
        )
        if provider_errors:
            pytest.skip("Terraform providers are unavailable in the test environment")

    return result


@pytest.mark.integration
def test_terraform_configuration_validates(tmp_path):
    """Copy the Terraform configuration and ensure it validates cleanly."""

    if shutil.which("terraform") is None:
        pytest.skip("Terraform CLI is not installed")

    work_dir = tmp_path / "terraform" / "iam"
    shutil.copytree(TERRAFORM_ROOT, work_dir)

    init_result = _run_terraform_command(
        work_dir, "init", "-backend=false", "-input=false"
    )
    if init_result.returncode != 0:
        pytest.fail(f"terraform init failed: {init_result.stderr}")

    validate_result = _run_terraform_command(work_dir, "validate", "-no-color")
    if validate_result.returncode != 0:
        pytest.fail(f"terraform validate failed: {validate_result.stderr}")
