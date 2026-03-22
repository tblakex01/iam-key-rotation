# Terragrunt Layout

Terragrunt is the environment deployment entrypoint for this repository.

## Structure

```text
terragrunt/
├── root.terragrunt.hcl
└── mvw-dw-nonprod/
    ├── account.hcl.example
    └── us-east-1/
        ├── region.hcl
        └── dev/
            ├── env.hcl
            └── iam-key-rotation/
                ├── config.hcl.example
                └── terragrunt.hcl
```

## Responsibilities

- `root.terragrunt.hcl`
  - provider configuration
  - remote state configuration
  - global tagging
- `account.hcl`
  - account name, account ID, AWS profile
- `region.hcl`
  - AWS region
- `env.hcl`
  - environment label such as `dev` or `prod`
- `iam-key-rotation/config.hcl`
  - explicit application configuration for that environment

## Required Service Inputs

The service config must set:

- `sender_email`
- `alarm_sns_topic`
- `managed_user_info` if the environment should manage IAM users
- any environment-specific threshold overrides

The service config should also set or review:

- `support_email`
- `access_key_recovery_request_cooldown_minutes`
- `access_key_recovery_max_requests_per_day`
- `ses_configuration_set` if the environment uses one

The Terragrunt service configuration passes:

- `name_prefix = "iam-key-rotation"`
- `environment_name = <env>`
- shared Lambda source directory rooted at [`lambda`](/Users/nizda/Dev/cc/iam-key-rotation/lambda)
- the self-service access-key recovery Lambda source directory rooted at [`lambda`](/Users/nizda/Dev/cc/iam-key-rotation/lambda)

## Commands

```bash
cd terragrunt/mvw-dw-nonprod/us-east-1/dev/iam-key-rotation

terragrunt hclfmt
terragrunt init
terragrunt plan
terragrunt apply
terragrunt output
```

## Notes

- Commit only `.example` files. Do not commit real `account.hcl` or `config.hcl`.
- Resource names are environment-scoped by `${name_prefix}-${environment_name}`.
- The Terraform module is shared across environments; environment behavior comes from Terragrunt inputs.
