#!/usr/bin/env python3
"""
Jenna Sprattler | SRE Kentik | 2023-04-13
Self service API access key rotation tool for IAM users
New users need to create initial keys via Web UI and run `aws configure` locally
Ref https://aws.amazon.com/blogs/security/how-to-rotate-access-keys-for-iam-users/
To rotate access keys, you should follow these steps:
1. Create a second access key in addition to the one in use.
2. Update all your applications to use the new access key and validate applications are working.
3. Change the state of the previous access key to inactive.
4. Validate that your applications are still working as expected.
5. Delete the inactive access key.
"""

import argparse
import configparser
import json
import logging
from datetime import datetime
from pathlib import Path
import boto3
from botocore.exceptions import ClientError
from rich.console import Console
from rich.table import Table
from rich import print as rprint

path = Path.home().joinpath(".aws/credentials")
console = Console()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Session cache for performance
_session = None


def get_iam_client():
    """Get or create IAM client"""
    global _session
    if _session is None:
        _session = boto3.Session()
    return _session.client("iam")


def parse_args():
    """Define cli args to be parsed into main()"""
    parser = argparse.ArgumentParser(
        description="AWS IAM Self-Service Access Key Rotation Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -l                          # List all access keys with ages
  %(prog)s -c                          # Create new access key
  %(prog)s -u AKIAEXAMPLE active       # Activate an access key
  %(prog)s -d AKIAEXAMPLE              # Delete an access key
  %(prog)s -l --json                   # List keys in JSON format
        """,
    )
    parser.add_argument(
        "-c", "--create", action="store_true", help="Create a new access key"
    )
    parser.add_argument(
        "-u",
        "--update",
        type=str,
        nargs=2,
        metavar=("KEY_ID", "STATUS"),
        help="Update access key status (active|inactive)",
    )
    parser.add_argument(
        "-d",
        "--delete",
        type=str,
        nargs=1,
        metavar="KEY_ID",
        help="Delete an access key",
    )
    parser.add_argument(
        "-l",
        "--list",
        action="store_true",
        help="List access keys with creation dates and ages",
    )
    parser.add_argument(
        "--json", action="store_true", help="Output in JSON format (use with --list)"
    )
    parser.add_argument(
        "--backup",
        action="store_true",
        help="Backup existing credentials before update (use with --create)",
    )
    return parser.parse_args()


def calculate_key_age(create_date):
    """Calculate the age of a key in days"""
    if isinstance(create_date, str):
        return "N/A"
    key_age = (datetime.now(create_date.tzinfo) - create_date).days
    return key_age


def get_age_color(age):
    """Get color based on key age"""
    if isinstance(age, str):
        return "white"
    if age >= 90:
        return "red"
    elif age >= 75:
        return "yellow"
    elif age >= 60:
        return "orange"
    else:
        return "green"


def backup_credentials():
    """Backup existing credentials file"""
    if path.exists():
        backup_path = path.with_suffix(
            f".backup.{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        )
        backup_path.write_text(path.read_text())
        rprint(f"[green]✓[/green] Credentials backed up to: {backup_path}")
        return backup_path
    return None


def list_keys_json():
    """List keys in JSON format"""
    try:
        client = get_iam_client()
        response = client.list_access_keys()
        keys_data = []

        for key in response["AccessKeyMetadata"]:
            age = calculate_key_age(key["CreateDate"])
            keys_data.append(
                {
                    "AccessKeyId": key["AccessKeyId"],
                    "Status": key["Status"],
                    "CreateDate": (
                        key["CreateDate"].isoformat()
                        if hasattr(key["CreateDate"], "isoformat")
                        else str(key["CreateDate"])
                    ),
                    "Age": age,
                }
            )

        print(json.dumps({"AccessKeys": keys_data}, indent=2, default=str))
    except ClientError as e:
        logger.error(f"Error listing access keys: {e}")
        rprint(f"[red]Error:[/red] {e}")


def list_keys_table():
    """List keys in a formatted table"""
    try:
        client = get_iam_client()
        response = client.list_access_keys()

        if not response["AccessKeyMetadata"]:
            rprint("[yellow]No access keys found.[/yellow]")
            return

        table = Table(title="AWS Access Keys")
        table.add_column("Key ID", style="cyan")
        table.add_column("Status", style="magenta")
        table.add_column("Created", style="blue")
        table.add_column("Age (days)", style="bold")

        for key in response["AccessKeyMetadata"]:
            age = calculate_key_age(key["CreateDate"])
            age_color = get_age_color(age)

            table.add_row(
                key["AccessKeyId"],
                key["Status"],
                (
                    key["CreateDate"].strftime("%Y-%m-%d %H:%M:%S")
                    if hasattr(key["CreateDate"], "strftime")
                    else str(key["CreateDate"])
                ),
                f"[{age_color}]{age}[/{age_color}]",
            )

        console.print(table)

        # Show warnings for old keys
        for key in response["AccessKeyMetadata"]:
            age = calculate_key_age(key["CreateDate"])
            if isinstance(age, int):
                if age >= 90:
                    rprint(
                        f"[red]⚠️  Key {key['AccessKeyId']} is {age} days old and should be rotated immediately![/red]"
                    )
                elif age >= 75:
                    rprint(
                        f"[yellow]⚠️  Key {key['AccessKeyId']} is {age} days old and should be rotated soon.[/yellow]"
                    )

    except ClientError as e:
        logger.error(f"Error listing access keys: {e}")
        rprint(f"[red]Error:[/red] {e}")


def main():
    """API access key rotation"""
    args = parse_args()
    if args.create:
        try:
            # Show current keys first
            rprint("\n[blue]Current access keys:[/blue]")
            list_keys_table()

            # Create new key
            rprint("\n[green]Creating new access key...[/green]")
            client = get_iam_client()
            response = client.create_access_key()
            new_key = response["AccessKey"]["AccessKeyId"]
            new_secret = response["AccessKey"]["SecretAccessKey"]

            rprint("\n[green]✓ New access key created successfully![/green]")
            rprint(f"[cyan]Access Key ID:[/cyan] {new_key}")
            rprint(f"[cyan]Secret Access Key:[/cyan] {new_secret}")
            rprint(
                "\n[yellow]⚠️  Save these credentials immediately! They will not be shown again.[/yellow]"
            )

            # Option to update credentials file
            rprint(f"\n[blue]Credentials file location:[/blue] {str(path)}")
            update_creds = input("Update credentials file with new key? (y/n): ")

            if update_creds.lower() == "y":
                # Backup existing credentials if requested
                if args.backup:
                    backup_credentials()

                try:
                    config = configparser.ConfigParser()

                    # Read existing config
                    if path.exists():
                        config.read(path)

                    # Update default profile
                    if "default" not in config:
                        config["default"] = {}
                    config["default"]["aws_access_key_id"] = new_key
                    config["default"]["aws_secret_access_key"] = new_secret

                    # Write back preserving other profiles
                    with open(path, "w", encoding="utf-8") as configfile:
                        config.write(configfile)

                    rprint("[green]✓[/green] Credentials file updated successfully!")
                    rprint("\n[yellow]Next steps:[/yellow]")
                    rprint("1. Test your applications with the new key")
                    rprint("2. Once verified, deactivate the old key:")
                    rprint(f"   python3 {__file__} -u OLD_KEY_ID inactive")
                    rprint("3. After confirming everything works, delete the old key:")
                    rprint(f"   python3 {__file__} -d OLD_KEY_ID")

                except IOError as e:
                    rprint(f"[red]Error updating credentials file: {e}[/red]")
            else:
                rprint(
                    "\n[yellow]Credentials file not updated. Manual configuration required.[/yellow]"
                )

        except ClientError as e:
            if e.response["Error"]["Code"] == "LimitExceeded":
                rprint(
                    "[red]Error:[/red] Access key limit exceeded (maximum 2 keys per user)"
                )
                rprint("Delete an existing key before creating a new one:")
                list_keys_table()
            else:
                logger.error(f"Error creating access key: {e}")
                rprint(f"[red]Error:[/red] {e}")
        except Exception as e:
            logger.error(f"Error creating access key: {e}")
            rprint(f"[red]Error:[/red] {e}")
    elif args.update:
        key_id = args.update[0]
        status = args.update[1].lower()

        if status in ["active", "inactive"]:
            try:
                rprint(
                    f"\n[blue]Updating access key {key_id} to {status.upper()}...[/blue]"
                )

                client = get_iam_client()
                response = client.update_access_key(
                    AccessKeyId=key_id, Status=status.capitalize()
                )

                rprint(f"[green]✓[/green] Access key {key_id} is now {status.upper()}")

                # Show updated key list
                rprint("\n[blue]Updated access keys:[/blue]")
                list_keys_table()

            except ClientError as e:
                logger.error(f"Error updating access key: {e}")
                rprint(f"[red]Error:[/red] {e}")
        else:
            rprint(
                f"[red]Error:[/red] Status '{args.update[1]}' is not valid. Use 'active' or 'inactive'."
            )
    elif args.delete:
        key_id = args.delete[0]

        try:
            # Show current keys first
            rprint("\n[blue]Current access keys:[/blue]")
            list_keys_table()

            # Confirmation prompt
            confirm = input(
                f"\nAre you sure you want to delete access key {key_id}? (yes/no): "
            )

            if confirm.lower() == "yes":
                rprint(f"\n[blue]Deleting access key {key_id}...[/blue]")

                client = get_iam_client()
                response = client.delete_access_key(AccessKeyId=key_id)

                rprint(
                    f"[green]✓[/green] Access key {key_id} has been deleted successfully!"
                )

                # Show updated key list
                rprint("\n[blue]Remaining access keys:[/blue]")
                list_keys_table()

            else:
                rprint("[yellow]Delete operation cancelled.[/yellow]")

        except ClientError as e:
            logger.error(f"Error deleting access key: {e}")
            rprint(f"[red]Error:[/red] {e}")
    elif args.list:
        if args.json:
            list_keys_json()
        else:
            list_keys_table()


if __name__ == "__main__":
    main()
