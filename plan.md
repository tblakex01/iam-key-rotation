# Production Remediation Plan

This checklist is the working backlog for getting this repository to a production-ready state.

## Phase 1: Restore A Safe Engineering Baseline

- [x] Fix Lambda runtime blockers in the primary codepath.
- [x] Make the automated test suite hermetic and runnable in CI without live AWS profiles.
- [x] Get `pytest` green at the repository default entrypoint.
- [x] Restore the `--cov-fail-under=85` gate.
- [x] Remove or quarantine operational/manual scripts from the automated test path.

## Phase 2: Eliminate Unsafe Infrastructure Defaults

- [x] Remove default IAM users from Terraform module inputs.
- [x] Stop creating IAM access keys from Terraform in the production module path.
- [x] Remove sensitive access-key secret outputs from Terraform outputs.
- [x] Make Terragrunt the documented deployment entrypoint for environments.
- [x] Require explicit environment configuration for all deploys.

## Phase 3: Harden Secrets Handling

- [x] Stop storing active pre-signed URLs in DynamoDB.
- [x] Correlate download tracking by exact `s3_key` rather than “latest rotation for user”.
- [x] Rework S3 object handling so “one-time download” is irrecoverable, not version-recoverable.
- [x] Review IAM/S3/DynamoDB permissions for least privilege.
- [x] Remove hardcoded account- or org-specific values from Terraform and Lambda defaults.

## Phase 4: Strengthen Runtime Correctness

- [x] Define one canonical rotation workflow and delete legacy/duplicate behavior.
- [x] Make notification payloads and business rules a single source of truth.
- [x] Validate required runtime configuration up front and fail fast on invalid deploys.
- [x] Add idempotency protections for rotation, reminder, cleanup, and download-tracking flows.
- [x] Tighten error handling around destructive actions so state transitions stay consistent.

## Phase 5: Production Observability And Operations

- [x] Add CloudWatch alarms for Lambda errors, throttles, and DLQ/failure paths.
- [x] Add explicit alarm routing instead of relying on undocumented defaults.
- [x] Add dashboards or metrics for rotation lifecycle health.
- [x] Document operational runbooks for incident response and manual recovery.
- [x] Add staged rollout guidance for dev, non-prod, and prod.

## Phase 6: CI/CD And Release Controls

- [x] Enforce `black`, `flake8`, `mypy`, `bandit`, `pytest`, and Terraform validation in CI.
- [x] Add `tflint` and `tfsec` or `checkov` to CI.
- [x] Add a Terraform plan step for deployable environments.
- [x] Keep docs, runbooks, and architecture diagrams aligned with shipped behavior.
- [x] Cut a production-readiness review before first rollout.

## Current Focus

- [x] Repair `lambda/access_key_enforcement`.
- [x] Repair `lambda/cleanup`.
- [x] Make `scripts/aws_iam_user_cleanup.py` safe to import in tests.
- [x] Convert `tests/test_rotation_workflow.py` into an opt-in operational workflow script.
- [x] Re-run the full validation suite and update this backlog from actual results.
