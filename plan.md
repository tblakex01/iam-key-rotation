# Production Remediation Plan

This checklist is the working backlog for getting this repository to a production-ready state.

## Phase 1: Restore A Safe Engineering Baseline

- [x] Fix Lambda runtime blockers in the primary codepath.
- [x] Make the automated test suite hermetic and runnable in CI without live AWS profiles.
- [x] Get `pytest` green at the repository default entrypoint.
- [x] Restore the `--cov-fail-under=85` gate.
- [x] Remove or quarantine operational/manual scripts from the automated test path.

## Phase 2: Eliminate Unsafe Infrastructure Defaults

- [ ] Remove default IAM users from Terraform module inputs.
- [ ] Stop creating IAM access keys from Terraform in the production module path.
- [ ] Remove sensitive access-key secret outputs from Terraform outputs.
- [ ] Make Terragrunt the documented deployment entrypoint for environments.
- [ ] Require explicit environment configuration for all deploys.

## Phase 3: Harden Secrets Handling

- [ ] Stop storing active pre-signed URLs in DynamoDB.
- [ ] Correlate download tracking by exact `s3_key` rather than “latest rotation for user”.
- [ ] Rework S3 object handling so “one-time download” is irrecoverable, not version-recoverable.
- [ ] Review IAM/S3/DynamoDB permissions for least privilege.
- [ ] Remove hardcoded account- or org-specific values from Terraform and Lambda defaults.

## Phase 4: Strengthen Runtime Correctness

- [ ] Define one canonical rotation workflow and delete legacy/duplicate behavior.
- [ ] Make notification payloads and business rules a single source of truth.
- [ ] Validate required runtime configuration up front and fail fast on invalid deploys.
- [ ] Add idempotency protections for rotation, reminder, cleanup, and download-tracking flows.
- [ ] Tighten error handling around destructive actions so state transitions stay consistent.

## Phase 5: Production Observability And Operations

- [ ] Add CloudWatch alarms for Lambda errors, throttles, and DLQ/failure paths.
- [ ] Add explicit alarm routing instead of relying on undocumented defaults.
- [ ] Add dashboards or metrics for rotation lifecycle health.
- [ ] Document operational runbooks for incident response and manual recovery.
- [ ] Add staged rollout guidance for dev, non-prod, and prod.

## Phase 6: CI/CD And Release Controls

- [ ] Enforce `black`, `flake8`, `mypy`, `bandit`, `pytest`, and Terraform validation in CI.
- [ ] Add `tflint` and `tfsec` or `checkov` to CI.
- [ ] Add a Terraform plan step for deployable environments.
- [ ] Keep docs, runbooks, and architecture diagrams aligned with shipped behavior.
- [ ] Cut a production-readiness review before first rollout.

## Current Focus

- [x] Repair `lambda/access_key_enforcement`.
- [x] Repair `lambda/cleanup`.
- [x] Make `scripts/aws_iam_user_cleanup.py` safe to import in tests.
- [x] Convert `tests/test_rotation_workflow.py` into an opt-in operational workflow script.
- [x] Re-run the full validation suite and update this backlog from actual results.
