#!/usr/bin/env python3
"""
Jenna Sprattler | SRE Kentik | 2023-02-14
Simple AWS IAM user account password reset script using boto3
Options include: list all existing AWS IAM users, Reset a user's
password and create a login profile for Console UI access
To be run by an AWS user w/ User Admin privileges
"""

import argparse
import secrets
import string
import sys
import os
import boto3
from botocore.exceptions import ClientError


def get_iam_client(profile=None, region=None):
    """
    Return a boto3 IAM client with optional profile and region configuration.
    
    Args:
        profile: AWS profile name (defaults to environment/default)
        region: AWS region (defaults to environment/default)
    
    Returns:
        boto3 IAM client
    """
    session_kwargs = {}
    if profile:
        session_kwargs['profile_name'] = profile
    if region:
        session_kwargs['region_name'] = region
    
    session = boto3.Session(**session_kwargs)
    
    # IAM is a global service, but we still respect region for STS endpoint
    client_kwargs = {}
    if region:
        client_kwargs['region_name'] = region
    
    return session.client('iam', **client_kwargs)


def passwordgen():
    """
    Generate temporary strict password that meets AWS password policy requirements
    """
    # Define character classes
    uppercase = string.ascii_uppercase
    lowercase = string.ascii_lowercase
    digits = string.digits
    special_chars = string.punctuation

    # Password length
    pwd_length = 20

    # Ensure at least one character from each required class
    password = [
        secrets.choice(uppercase),
        secrets.choice(lowercase),
        secrets.choice(digits),
        secrets.choice(special_chars),
    ]

    # Fill the rest of the password
    alphabet = uppercase + lowercase + digits + special_chars
    for _ in range(pwd_length - 4):
        password.append(secrets.choice(alphabet))

    # Shuffle to avoid predictable character positions
    secrets.SystemRandom().shuffle(password)

    return "".join(password)


def parse_args():
    """Define cli args to be parsed into main()"""
    parser = argparse.ArgumentParser(
        description="List/Reset/Create profiles for user accounts, output temp password"
    )
    
    # Global options
    parser.add_argument(
        "--profile", type=str, help="AWS profile name to use"
    )
    parser.add_argument(
        "--region", type=str, help="AWS region to use"
    )
    
    subparser = parser.add_subparsers(dest="command", help="Available commands")
    
    # List users command
    subparser.add_parser("list-users", help="List AWS IAM users")
    
    # Reset password command
    reset = subparser.add_parser("reset", help="Reset a user password")
    reset.add_argument(
        "-u", "--username", type=str, required=True, help="AWS IAM Username"
    )
    
    # Create profile command
    profile = subparser.add_parser("profile", help="Create user login profile")
    profile.add_argument(
        "-u", "--username", type=str, required=True, help="AWS IAM Username"
    )
    
    return parser.parse_args()


def main():
    """List, reset or create login profiles for user accounts and output temp password"""
    args = parse_args()
    
    # Initialize IAM client with optional profile and region
    try:
        client = get_iam_client(profile=args.profile, region=args.region)
    except Exception as exc:
        print(f"Error initializing AWS client: {exc}")
        print("Check your AWS credentials and configuration.")
        sys.exit(1)

    if args.command == "list-users":
        try:
            response = client.list_users()
            users = response.get("Users", [])
            if not users:
                print("No IAM users found.")
                return

            print(f"Found {len(users)} IAM users:")
            for user in users:
                print(f"  - {user['UserName']}")
        except ClientError as exc:
            error_code = exc.response.get("Error", {}).get("Code", "Unknown")
            error_msg = exc.response.get("Error", {}).get("Message", str(exc))
            print(f"Error listing users: {error_code} - {error_msg}")
            sys.exit(1)

    elif args.command == "reset":
        pwd = passwordgen()
        try:
            # First check if user exists
            client.get_user(UserName=args.username)

            # Check if login profile exists
            try:
                client.get_login_profile(UserName=args.username)
            except ClientError as exc:
                if exc.response["Error"]["Code"] == "NoSuchEntity":
                    print(
                        f"Error: User '{args.username}' does not have a login profile."
                    )
                    print("Use 'profile' command to create a login profile first.")
                    sys.exit(1)
                else:
                    raise

            # Update the password
            client.update_login_profile(
                UserName=args.username, Password=pwd, PasswordResetRequired=True
            )
            print(f"✓ Password has been reset for: {args.username}")
            print("\nLogin with temporary password:")
            print(f"  {pwd}")
            print("\n⚠️  Password reset will be enforced upon initial login")

        except ClientError as exc:
            error_code = exc.response.get("Error", {}).get("Code", "Unknown")
            error_msg = exc.response.get("Error", {}).get("Message", str(exc))

            if error_code == "NoSuchEntity":
                print(f"Error: User '{args.username}' does not exist.")
            elif error_code == "PasswordPolicyViolation":
                print("Error: Generated password violates account password policy.")
                print(f"Details: {error_msg}")
            elif error_code == "AccessDenied":
                print(
                    "Error: Access denied. You need IAM user administration permissions."
                )
            elif error_code == "LimitExceeded":
                print("Error: Password change limit exceeded. Try again later.")
            else:
                print(
                    f"Error resetting password for {args.username}: {error_code} - {error_msg}"
                )

            sys.exit(1)

    elif args.command == "profile":
        pwd = passwordgen()
        try:
            # First check if user exists
            client.get_user(UserName=args.username)

            # Check if login profile already exists
            try:
                client.get_login_profile(UserName=args.username)
                print(f"Error: Login profile already exists for '{args.username}'.")
                print("Use 'reset' command to reset an existing password.")
                sys.exit(1)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise

            # Create the login profile
            client.create_login_profile(
                UserName=args.username, Password=pwd, PasswordResetRequired=True
            )
            print(f"✓ New login profile has been created for: {args.username}")
            print("\nLogin with temporary password:")
            print(f"  {pwd}")
            print("\n⚠️  Password reset will be enforced upon initial login")

        except ClientError as exc:
            error_code = exc.response.get("Error", {}).get("Code", "Unknown")
            error_msg = exc.response.get("Error", {}).get("Message", str(exc))

            if error_code == "NoSuchEntity":
                print(f"Error: User '{args.username}' does not exist.")
            elif error_code == "EntityAlreadyExists":
                print(f"Error: Login profile already exists for '{args.username}'.")
                print("Use 'reset' command instead.")
            elif error_code == "PasswordPolicyViolation":
                print("Error: Generated password violates account password policy.")
                print(f"Details: {error_msg}")
            elif error_code == "AccessDenied":
                print(
                    "Error: Access denied. You need IAM user administration permissions."
                )
            elif error_code == "LimitExceeded":
                print("Error: Account limit exceeded for login profiles.")
            else:
                print(
                    f"Error creating profile for {args.username}: {error_code} - {error_msg}"
                )

            sys.exit(1)
    else:
        parser = argparse.ArgumentParser()
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
