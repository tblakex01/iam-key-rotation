#!/usr/bin/env python3
"""
Jenna Sprattler | SRE Kentik | 2023-04-13
Simple self service password reset tool for clients
To be run by any AWS IAM user to reset their own password
"""

import secrets
import string
import logging
import getpass
import sys
from datetime import datetime
import boto3
from botocore.exceptions import ClientError, NoCredentialsError, PartialCredentialsError
from rich.console import Console
from rich.prompt import Prompt
from rich import print as rprint

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("iam_password_reset.log"),
        logging.StreamHandler(sys.stdout),
    ],
)
logger = logging.getLogger(__name__)

console = Console()


def validate_aws_connection():
    """Validate AWS credentials and connection"""
    try:
        # Try to get current user info to validate credentials
        sts_client = boto3.client("sts")
        identity = sts_client.get_caller_identity()
        logger.info(
            f"AWS connection validated for user: {identity.get('Arn', 'Unknown')}"
        )
        return True
    except NoCredentialsError:
        rprint(
            "[red]Error:[/red] AWS credentials not found. Please run 'aws configure' or set environment variables."
        )
        return False
    except PartialCredentialsError:
        rprint(
            "[red]Error:[/red] Incomplete AWS credentials. Please check your configuration."
        )
        return False
    except ClientError as e:
        rprint(f"[red]Error:[/red] AWS connection failed: {e}")
        return False


def get_current_user():
    """Get current IAM user information"""
    try:
        client = boto3.client("iam")
        response = client.get_user()
        return response["User"]
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchEntity":
            rprint(
                "[red]Error:[/red] Could not find current IAM user. Are you using root credentials?"
            )
        else:
            rprint(f"[red]Error:[/red] Failed to get user information: {e}")
        return None


def validate_password_policy(password):
    """Validate password against AWS password policy"""
    try:
        client = boto3.client("iam")
        response = client.get_account_password_policy()
        policy = response["PasswordPolicy"]

        errors = []

        # Check minimum length
        min_length = policy.get("MinimumPasswordLength", 8)
        if len(password) < min_length:
            errors.append(f"Password must be at least {min_length} characters long")

        # Check character requirements
        if policy.get("RequireUppercaseCharacters", False):
            if not any(c.isupper() for c in password):
                errors.append("Password must contain uppercase letters")

        if policy.get("RequireLowercaseCharacters", False):
            if not any(c.islower() for c in password):
                errors.append("Password must contain lowercase letters")

        if policy.get("RequireNumbers", False):
            if not any(c.isdigit() for c in password):
                errors.append("Password must contain numbers")

        if policy.get("RequireSymbols", False):
            if not any(c in string.punctuation for c in password):
                errors.append("Password must contain symbols")

        return errors

    except ClientError:
        # If we can't get the password policy, assume basic requirements
        logger.warning("Could not retrieve password policy, using default validation")
        errors = []
        if len(password) < 8:
            errors.append("Password must be at least 8 characters long")
        return errors


def passwordgen(length=20, exclude_ambiguous=True):
    """
    Generate a secure password that meets AWS password policy requirements
    """
    # Character sets
    uppercase = string.ascii_uppercase
    lowercase = string.ascii_lowercase
    digits = string.digits
    symbols = "!@#$%^&*()_+-=[]{}|;:,.<>?"

    # Remove ambiguous characters if requested
    if exclude_ambiguous:
        ambiguous = "0O1lI"
        uppercase = "".join(c for c in uppercase if c not in ambiguous)
        lowercase = "".join(c for c in lowercase if c not in ambiguous)
        digits = "".join(c for c in digits if c not in ambiguous)

    # Ensure password has at least one character from each required set
    password_chars = [
        secrets.choice(uppercase),
        secrets.choice(lowercase),
        secrets.choice(digits),
        secrets.choice(symbols),
    ]

    # Fill the rest of the password length
    all_chars = uppercase + lowercase + digits + symbols
    for _ in range(length - 4):
        password_chars.append(secrets.choice(all_chars))

    # Shuffle the password characters
    secrets.SystemRandom().shuffle(password_chars)
    password = "".join(password_chars)

    # Validate the generated password
    validation_errors = validate_password_policy(password)
    if validation_errors:
        logger.warning(f"Generated password failed validation: {validation_errors}")
        # Retry with a longer password
        return passwordgen(length + 5, exclude_ambiguous)

    return password


def secure_password_display(password):
    """Display password securely with copy instructions"""
    rprint("\n[green]✓ Password reset successful![/green]")
    rprint("\n[bold yellow]Your new password:[/bold yellow]")
    console.print(f"[bold cyan]{password}[/bold cyan]")

    rprint("\n[yellow]⚠️  Important Security Notes:[/yellow]")
    rprint("• Copy this password immediately - it will not be shown again")
    rprint("• Store it securely in a password manager")
    rprint("• You will be required to change it on first login")
    rprint("• This password expires in 90 days")

    # Ask if user wants to see password again
    show_again = Prompt.ask(
        "\nDo you need to see the password again", choices=["y", "n"], default="n"
    )
    if show_again.lower() == "y":
        console.print(f"\n[bold cyan]{password}[/bold cyan]")


def log_password_reset(username):
    """Log password reset event"""
    logger.info(f"Password reset completed for user: {username}")

    # Log to file with timestamp for audit purposes
    with open("password_reset_audit.log", "a", encoding="utf-8") as audit_file:
        audit_file.write(
            f"{datetime.now().isoformat()},{username},password_reset,success\n"
        )


def main():
    """Reset your IAM user password with enhanced security and error handling"""
    rprint("[bold blue]AWS IAM Self-Service Password Reset Tool[/bold blue]")

    # Validate AWS connection
    if not validate_aws_connection():
        sys.exit(1)

    # Get current user information
    current_user = get_current_user()
    if not current_user:
        sys.exit(1)

    username = current_user["UserName"]
    rprint(f"\n[blue]Current user:[/blue] {username}")

    # Check if user has a login profile
    try:
        client = boto3.client("iam")
        client.get_login_profile(UserName=username)
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchEntity":
            rprint(
                "[red]Error:[/red] No login profile found. Contact your administrator to create one."
            )
            sys.exit(1)
        else:
            rprint(f"[red]Error:[/red] Could not check login profile: {e}")
            sys.exit(1)

    try:
        # Generate new password
        rprint("\n[blue]Generating new password...[/blue]")
        new_password = passwordgen()

        # Get current password securely
        rprint("\n[yellow]Please enter your current password:[/yellow]")
        current_password = getpass.getpass("Current password: ")

        if not current_password.strip():
            rprint("[red]Error:[/red] Current password cannot be empty.")
            sys.exit(1)

        # Attempt password change
        rprint("\n[blue]Changing password...[/blue]")
        client.change_password(
            OldPassword=current_password, NewPassword=new_password
        )

        # Success! Display new password securely
        secure_password_display(new_password)

        # Log the successful reset
        log_password_reset(username)

        # Additional security recommendations
        rprint("\n[yellow]Security Recommendations:[/yellow]")
        rprint("• Enable MFA if not already active")
        rprint("• Review your access keys and rotate if needed")
        rprint("• Update any stored passwords in applications")

        logger.info("Password reset completed successfully")

    except ClientError as error:
        error_code = error.response.get("Error", {}).get("Code", "Unknown")
        error_message = error.response.get("Error", {}).get("Message", str(error))

        logger.error(f"Password reset failed: {error_code} - {error_message}")

        if error_code == "InvalidUserPassword":
            rprint("[red]Error:[/red] Current password is incorrect.")
        elif error_code == "PasswordPolicyViolation":
            rprint(
                f"[red]Error:[/red] New password violates password policy: {error_message}"
            )
        elif error_code == "EntityTemporarilyUnmodifiable":
            rprint(
                "[red]Error:[/red] Password was recently changed. Please wait before trying again."
            )
        elif error_code == "LimitExceeded":
            rprint(
                "[red]Error:[/red] Password change limit exceeded. Please try again later."
            )
        elif error_code == "AccessDenied":
            rprint(
                "[red]Error:[/red] Access denied. You may not have permission to change your password."
            )
        else:
            rprint(f"[red]Error:[/red] Unexpected AWS error: {error_message}")

        # Log the failed attempt
        with open("password_reset_audit.log", "a", encoding="utf-8") as audit_file:
            audit_file.write(
                f"{datetime.now().isoformat()},{username},password_reset,failed,{error_code}\n"
            )

        sys.exit(1)

    except KeyboardInterrupt:
        rprint("\n[yellow]Password reset cancelled by user.[/yellow]")
        sys.exit(130)

    except Exception as error:
        logger.error(f"Unexpected error during password reset: {error}")
        rprint(f"[red]Error:[/red] Unexpected error: {error}")

        # Log the failed attempt
        with open("password_reset_audit.log", "a", encoding="utf-8") as audit_file:
            audit_file.write(
                f"{datetime.now().isoformat()},{username},password_reset,failed,unexpected_error\n"
            )

        sys.exit(1)


if __name__ == "__main__":
    main()
