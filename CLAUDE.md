# AWS IAM Key Rotation Project Development Guide

## Project Overview
This project provides AWS security tools for IAM user management, including:
- Self-service API access key rotation
- Self-service password reset
- Admin user password reset and profile management
- User cleanup utilities
- Automated password expiry notifications via Lambda

## Prerequisites

### AWS Configuration
- AWS CLI installed and configured with appropriate credentials
- IAM permissions required:
  - For self-service scripts: Basic IAM user permissions (change own password, manage own access keys)
  - For admin scripts: IAM user administration permissions
  - For Lambda: IAM read permissions, SES send permissions

### Python Environment
1. Python 3.x installed
2. Create and activate virtual environment:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```
3. Install dependencies:
   ```bash
   cd scripts
   pip install -r requirements.txt
   ```

## Script Usage

### 1. Self-Service Access Key Rotation (`aws_iam_self_service_key_rotation.py`)
**Purpose**: Allows IAM users to rotate their own access keys

**Usage**:
```bash
# List current access keys
python3 scripts/aws_iam_self_service_key_rotation.py -l

# Create new access key
python3 scripts/aws_iam_self_service_key_rotation.py -c

# Update key status (active/inactive)
python3 scripts/aws_iam_self_service_key_rotation.py -u <KEY_ID> <active|inactive>

# Delete access key
python3 scripts/aws_iam_self_service_key_rotation.py -d <KEY_ID>
```

**Key Features**:
- Automatically updates `~/.aws/credentials` if requested
- Enforces AWS key limit (max 2 keys per user)

### 2. Self-Service Password Reset (`aws_iam_self_service_password_reset.py`)
**Purpose**: Allows IAM users to reset their own password

**Usage**:
```bash
python3 scripts/aws_iam_self_service_password_reset.py
```

**Process**:
1. Enter current password when prompted
2. Script generates secure 20-character password
3. New password is displayed (save immediately!)

### 3. Admin User Management (`aws_iam_user_password_reset.py`)
**Purpose**: Admin tool for managing other users' passwords and login profiles

**Usage**:
```bash
# List all IAM users
python3 scripts/aws_iam_user_password_reset.py list-users

# Reset existing user's password
python3 scripts/aws_iam_user_password_reset.py reset -u <USERNAME>

# Create new login profile for user
python3 scripts/aws_iam_user_password_reset.py profile -u <USERNAME>
```

**Notes**:
- Generates temporary password that must be changed on first login
- Requires IAM admin permissions

### 4. User Cleanup (`aws_iam_user_cleanup.py`)
**Purpose**: Remove user's MFA devices, access keys, and login profile before deletion

**Usage**:
```bash
python3 scripts/aws_iam_user_cleanup.py <USERNAME>
```

**What it removes**:
- Login profile (console access)
- All MFA devices
- All access keys

**Use case**: Run before deleting user via Terraform or console

## Lambda Function Deployment

### Password Notification Lambda
**Location**: `lambda/password_notification/password_notification.py`

**Purpose**: Sends email notifications for expiring passwords (>78 days old)

**Requirements**:
- SES configured with verified sender domain
- IAM users must have 'email' tag set
- Lambda needs IAM role with:
  - `iam:GenerateCredentialReport`
  - `iam:GetCredentialReport`
  - `iam:ListUserTags`
  - `ses:SendEmail`

**Deployment**:
1. Package the Lambda function
2. Deploy with appropriate IAM role
3. Set up CloudWatch Events trigger (recommended: daily)

## Terraform Infrastructure

**Location**: `terraform/iam/`

**Components**:
- `provider.tf`: AWS provider configuration (v5.16.2)
- `users.tf`: IAM user definitions
- `variables.tf`: Input variables

**Usage**:
```bash
cd terraform/iam
terraform init
terraform plan
terraform apply
```

## Development Workflow

1. **Always activate virtual environment** before development:
   ```bash
   source venv/bin/activate
   ```

2. **Test scripts locally** with appropriate AWS credentials

3. **Security considerations**:
   - Never commit AWS credentials
   - Test with limited permissions first
   - Use MFA for production accounts

4. **Common issues**:
   - Ensure AWS CLI is configured: `aws configure`
   - Check IAM permissions if scripts fail
   - Verify boto3 version compatibility

## Notes for Python Testing, formatting, and code quality checks.
- All scripts use boto3 for AWS API interactions
- Password generation uses Python's `secrets` module for cryptographic security
- Scripts follow AWS best practices for key rotation- Always use Flake8 for linting the application. E501 errors can be ignored up to 120 lines.
- Always use Black for formatting the application.
- Always use Pyright or mypy for type checking the application.

 ### Code Quality
```bash
# Format code with Black
black .

# Type checking
mypy .
```

# Notes for Terraform validation, formatting, plan
 ### Terraform Workflow
```bash
# Initialize Terraform (required after cloning or adding providers)
terraform init

# Validate configuration syntax
terraform validate

# Format Terraform files
terraform fmt -recursive

# Plan infrastructure changes
terraform plan
```
