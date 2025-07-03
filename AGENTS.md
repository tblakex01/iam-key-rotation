# Repository Contribution Guidelines

This repository hosts enterprise-grade AWS IAM security tools. To maintain high code quality and security standards, follow these guidelines for all changes in this repo.

## General Workflow
- Create feature branches from `main` for all work.
- All code changes must go through pull requests.
- Pull requests must receive at least one approval before merging.
- Keep commits focused and write clear messages describing the change.

## Testing and Quality Gates
For any pull request that modifies application code (Python or Terraform), run the full suite of checks before merging:

### Python
1. **Install dependencies**
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install -r scripts/requirements.txt -r tests/requirements.txt
   ```
2. **Formatting** – ensure code is formatted with Black
   ```bash
   black .
   ```
3. **Linting** – run Flake8 allowing lines up to 120 characters
   ```bash
   flake8 scripts/ lambda/ tests/ --max-line-length=120 --ignore=E501,W503,E203
   ```
4. **Type checking** – run mypy (or pyright) on the codebase
   ```bash
   mypy scripts/ lambda/
   ```
5. **Security scanning** – use Bandit to check for common Python security issues
   ```bash
   bandit -r scripts/ lambda/
   ```
6. **Unit tests** – execute the test suite with `pytest`
   ```bash
   pytest
   ```
7. **Integration tests** – when applicable, run tests in the integration folder
   ```bash
   pytest tests/integration
   ```

### Terraform
1. **Initialize and validate**
   ```bash
   cd terraform/iam
   terraform init -backend=false
   terraform validate
   ```
2. **Formatting** – check formatting for all Terraform files
   ```bash
   terraform fmt -recursive
   ```
3. **Linting** – run tflint on the Terraform directory
   ```bash
   tflint
   ```
4. **Security scanning** – run tfsec or checkov for security best practices
   ```bash
   tfsec .
   ```
5. **Plan** – generate and review a Terraform plan
   ```bash
   terraform plan
   ```

### When Tests Are Not Required
If a pull request only updates comments or documentation (e.g., changes under `README.md` or other `.md` files) and does not modify any executable code, these checks may be skipped. All other changes require the full test suite and quality gates above.

## Best Practices
- Do not commit AWS credentials or other secrets.
- Use descriptive variables and function names.
- Keep modules small and focused.
- Write docstrings for all functions and modules.
- Prefer dependency injection and configuration via environment variables or files rather than hardcoding values.
- Review Terraform plans carefully before applying infrastructure changes.

## Pull Request Checklist
Before requesting review, ensure that:
- [ ] Code is formatted and linted.
- [ ] Type checking passes.
- [ ] Unit and integration tests pass.
- [ ] Terraform validation, formatting, linting, and security checks pass.
- [ ] Any relevant documentation is updated.

These guidelines help maintain a high-quality, secure codebase and must be followed for all substantive code changes.
