#!/usr/bin/env python3
"""
AWS IAM Compliance Report Generator
Generates comprehensive reports on IAM user compliance including:
- Access key ages and rotation status
- Password ages and policy compliance
- MFA status
- Login activity
- Non-compliant resources
"""

import argparse
import csv
import io
import json
import logging
import os
import time
from datetime import datetime
from pathlib import Path
import boto3
from botocore.exceptions import ClientError
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, TextColumn, BarColumn, TaskProgressColumn
from rich import print as rprint

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize AWS clients
iam_client = boto3.client("iam")
console = Console()


class IAMComplianceReport:
    """IAM Compliance Report Generator"""

    # Configurable compliance thresholds via environment variables
    KEY_WARNING_THRESHOLD = int(os.environ.get("KEY_WARNING_THRESHOLD", "75"))
    KEY_NON_COMPLIANT_THRESHOLD = int(
        os.environ.get("KEY_NON_COMPLIANT_THRESHOLD", "90")
    )
    PASSWORD_WARNING_THRESHOLD = int(os.environ.get("PASSWORD_WARNING_THRESHOLD", "75"))
    PASSWORD_NON_COMPLIANT_THRESHOLD = int(
        os.environ.get("PASSWORD_NON_COMPLIANT_THRESHOLD", "90")
    )

    def __init__(self):
        self.users_data = []
        self.summary_stats = {
            "total_users": 0,
            "users_with_keys": 0,
            "users_with_passwords": 0,
            "users_with_mfa": 0,
            "expired_keys": 0,
            "expired_passwords": 0,
            "compliant_users": 0,
        }

    def generate_credential_report(self):
        """Generate and retrieve IAM credential report"""
        rprint("[blue]Generating IAM credential report...[/blue]")

        try:
            # Generate credential report
            iam_client.generate_credential_report()

            # Wait for report generation with progress bar
            max_attempts = 30  # 60 seconds timeout
            attempt = 0

            with Progress(
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TaskProgressColumn(),
                console=console,
            ) as progress:
                task = progress.add_task(
                    "Waiting for report generation...", total=max_attempts
                )

                while attempt < max_attempts:
                    attempt += 1
                    time.sleep(2)
                    progress.update(task, advance=1)

                    try:
                        response = iam_client.get_credential_report()
                        if "Content" in response:
                            progress.update(task, completed=max_attempts)
                            break
                    except ClientError:
                        continue
                else:
                    raise TimeoutError(
                        "Credential report generation timed out after 60 seconds"
                    )

            return response["Content"].decode("utf-8")

        except ClientError as e:
            logger.error(f"Error generating credential report: {e}")
            raise

    def parse_credential_report(self, report_csv):
        """Parse credential report and extract user data"""
        rprint("[blue]Parsing credential report...[/blue]")

        csv_reader = csv.reader(io.StringIO(report_csv))
        next(csv_reader)  # Skip header

        for fields in csv_reader:
            if len(fields) < 18:  # Ensure we have enough fields
                continue

            user_data = self.parse_user_data(fields)
            if user_data:
                self.users_data.append(user_data)
                self.update_summary_stats(user_data)

    def parse_user_data(self, fields):
        """Parse individual user data from credential report"""
        try:
            username = fields[0]

            # Skip service accounts and system users
            if username in ["<root_account>", "<bucket_reports>"]:
                return None

            user_data = {
                "username": username,
                "arn": fields[1],
                "user_creation_time": self.parse_date(fields[2]),
                "password_enabled": fields[3] == "true",
                "password_last_used": self.parse_date(fields[4]),
                "password_last_changed": self.parse_date(fields[5]),
                "password_next_rotation": self.parse_date(fields[6]),
                "mfa_active": fields[7] == "true",
                "access_key_1_active": fields[8] == "true",
                "access_key_1_last_rotated": self.parse_date(fields[9]),
                "access_key_1_last_used_date": self.parse_date(fields[10]),
                "access_key_1_last_used_region": fields[11],
                "access_key_1_last_used_service": fields[12],
                "access_key_2_active": fields[13] == "true",
                "access_key_2_last_rotated": self.parse_date(fields[14]),
                "access_key_2_last_used_date": (
                    self.parse_date(fields[15]) if len(fields) > 15 else None
                ),
                "access_key_2_last_used_region": (
                    fields[16] if len(fields) > 16 else None
                ),
                "access_key_2_last_used_service": (
                    fields[17] if len(fields) > 17 else None
                ),
            }

            # Calculate ages and compliance
            user_data.update(self.calculate_compliance_metrics(user_data))

            # Get additional user info
            user_data.update(self.get_user_additional_info(username))

            return user_data

        except Exception as e:
            logger.error(
                f"Error parsing user data for {fields[0] if fields else 'unknown'}: {e}"
            )
            return None

    def parse_date(self, date_str):
        """Parse date string, return None if invalid"""
        if date_str in ["N/A", "not_supported", "no_information"]:
            return None
        try:
            return datetime.fromisoformat(date_str.replace("Z", "+00:00"))
        except (ValueError, TypeError):
            return None

    def calculate_compliance_metrics(self, user_data):
        """Calculate compliance metrics for a user"""
        now = datetime.now(datetime.now().astimezone().tzinfo)

        metrics = {
            "key_1_age": None,
            "key_2_age": None,
            "password_age": None,
            "key_1_compliance": "N/A",
            "key_2_compliance": "N/A",
            "password_compliance": "N/A",
            "overall_compliance": "UNKNOWN",
        }

        # Calculate key ages and compliance
        if user_data["access_key_1_active"] and user_data["access_key_1_last_rotated"]:
            metrics["key_1_age"] = (now - user_data["access_key_1_last_rotated"]).days
            metrics["key_1_compliance"] = self.get_key_compliance_status(
                metrics["key_1_age"]
            )

        if user_data["access_key_2_active"] and user_data["access_key_2_last_rotated"]:
            metrics["key_2_age"] = (now - user_data["access_key_2_last_rotated"]).days
            metrics["key_2_compliance"] = self.get_key_compliance_status(
                metrics["key_2_age"]
            )

        # Calculate password age and compliance
        if user_data["password_enabled"] and user_data["password_last_changed"]:
            metrics["password_age"] = (now - user_data["password_last_changed"]).days
            metrics["password_compliance"] = self.get_password_compliance_status(
                metrics["password_age"]
            )

        # Overall compliance
        metrics["overall_compliance"] = self.get_overall_compliance(metrics)

        return metrics

    def get_key_compliance_status(self, age):
        """Get compliance status for access key based on age"""
        if age is None:
            return "N/A"
        elif age >= self.KEY_NON_COMPLIANT_THRESHOLD:
            return "NON_COMPLIANT"
        elif age >= self.KEY_WARNING_THRESHOLD:
            return "WARNING"
        else:
            return "COMPLIANT"

    def get_password_compliance_status(self, age):
        """Get compliance status for password based on age"""
        if age is None:
            return "N/A"
        elif age >= self.PASSWORD_NON_COMPLIANT_THRESHOLD:
            return "NON_COMPLIANT"
        elif age >= self.PASSWORD_WARNING_THRESHOLD:
            return "WARNING"
        else:
            return "COMPLIANT"

    def get_overall_compliance(self, metrics):
        """Determine overall compliance status"""
        statuses = [
            metrics["key_1_compliance"],
            metrics["key_2_compliance"],
            metrics["password_compliance"],
        ]

        # Remove N/A entries
        active_statuses = [s for s in statuses if s != "N/A"]

        if not active_statuses:
            return "NO_CREDENTIALS"
        elif "NON_COMPLIANT" in active_statuses:
            return "NON_COMPLIANT"
        elif "WARNING" in active_statuses:
            return "WARNING"
        else:
            return "COMPLIANT"

    def get_user_additional_info(self, username):
        """Get additional user information from IAM"""
        try:
            # Get user tags
            tags_response = iam_client.list_user_tags(UserName=username)
            tags = {tag["Key"]: tag["Value"] for tag in tags_response.get("Tags", [])}

            # Get user's access keys for more details
            keys_response = iam_client.list_access_keys(UserName=username)
            access_keys = keys_response.get("AccessKeyMetadata", [])

            return {
                "email": tags.get("email", ""),
                "department": tags.get("department", ""),
                "manager": tags.get("manager", ""),
                "key_rotation_exempt": tags.get("key-rotation-exempt", "false").lower()
                == "true",
                "total_access_keys": len(access_keys),
            }

        except ClientError as e:
            logger.warning(f"Could not get additional info for {username}: {e}")
            return {
                "email": "",
                "department": "",
                "manager": "",
                "key_rotation_exempt": False,
                "total_access_keys": 0,
            }

    def update_summary_stats(self, user_data):
        """Update summary statistics"""
        self.summary_stats["total_users"] += 1

        if user_data.get("total_access_keys", 0) > 0:
            self.summary_stats["users_with_keys"] += 1

        if user_data.get("password_enabled", False):
            self.summary_stats["users_with_passwords"] += 1

        if user_data.get("mfa_active", False):
            self.summary_stats["users_with_mfa"] += 1

        # Check for expired credentials
        if (
            user_data.get("key_1_compliance") == "NON_COMPLIANT"
            or user_data.get("key_2_compliance") == "NON_COMPLIANT"
        ):
            self.summary_stats["expired_keys"] += 1

        if user_data.get("password_compliance") == "NON_COMPLIANT":
            self.summary_stats["expired_passwords"] += 1

        if user_data.get("overall_compliance") == "COMPLIANT":
            self.summary_stats["compliant_users"] += 1

    def display_summary(self):
        """Display summary statistics"""
        rprint("\n[bold blue]IAM Compliance Summary[/bold blue]")

        table = Table(title="Compliance Overview")
        table.add_column("Metric", style="cyan")
        table.add_column("Count", style="magenta")
        table.add_column("Percentage", style="yellow")

        total = self.summary_stats["total_users"]
        if total > 0:
            table.add_row("Total Users", str(total), "100%")
            table.add_row(
                "Users with Access Keys",
                str(self.summary_stats["users_with_keys"]),
                f"{(self.summary_stats['users_with_keys'] / total) * 100:.1f}%",
            )
            table.add_row(
                "Users with Passwords",
                str(self.summary_stats["users_with_passwords"]),
                f"{(self.summary_stats['users_with_passwords'] / total) * 100:.1f}%",
            )
            table.add_row(
                "Users with MFA",
                str(self.summary_stats["users_with_mfa"]),
                f"{(self.summary_stats['users_with_mfa'] / total) * 100:.1f}%",
            )
            table.add_row(
                "Compliant Users",
                str(self.summary_stats["compliant_users"]),
                f"{(self.summary_stats['compliant_users'] / total) * 100:.1f}%",
            )

            # Risk metrics
            table.add_row("", "", "", style="dim")
            table.add_row(
                "Users with Expired Keys",
                str(self.summary_stats["expired_keys"]),
                f"{(self.summary_stats['expired_keys'] / total) * 100:.1f}%",
                style="red",
            )
            table.add_row(
                "Users with Expired Passwords",
                str(self.summary_stats["expired_passwords"]),
                f"{(self.summary_stats['expired_passwords'] / total) * 100:.1f}%",
                style="red",
            )

        console.print(table)

    def display_detailed_report(self):
        """Display detailed compliance report"""
        rprint("\n[bold blue]Detailed IAM Compliance Report[/bold blue]")

        # Sort users by compliance status (non-compliant first)
        sorted_users = sorted(
            self.users_data,
            key=lambda x: (
                0
                if x["overall_compliance"] == "NON_COMPLIANT"
                else 1 if x["overall_compliance"] == "WARNING" else 2
            ),
        )

        table = Table(title="User Compliance Details")
        table.add_column("Username", style="cyan")
        table.add_column("Email", style="blue")
        table.add_column("Key 1 Age", style="yellow")
        table.add_column("Key 2 Age", style="yellow")
        table.add_column("Password Age", style="yellow")
        table.add_column("MFA", style="magenta")
        table.add_column("Status", style="bold")

        for user in sorted_users:
            # Format ages
            key1_age = (
                f"{user['key_1_age']}d" if user["key_1_age"] is not None else "N/A"
            )
            key2_age = (
                f"{user['key_2_age']}d" if user["key_2_age"] is not None else "N/A"
            )
            pwd_age = (
                f"{user['password_age']}d"
                if user["password_age"] is not None
                else "N/A"
            )

            # Color coding based on compliance
            status_color = {
                "NON_COMPLIANT": "red",
                "WARNING": "yellow",
                "COMPLIANT": "green",
                "NO_CREDENTIALS": "dim",
            }.get(user["overall_compliance"], "white")

            table.add_row(
                user["username"],
                (
                    user["email"][:30] + "..."
                    if len(user["email"]) > 30
                    else user["email"]
                ),
                key1_age,
                key2_age,
                pwd_age,
                "✓" if user["mfa_active"] else "✗",
                f"[{status_color}]{user['overall_compliance']}[/{status_color}]",
            )

        console.print(table)

    def export_csv(self, filename):
        """Export report to CSV file"""
        filepath = Path(filename)

        with open(filepath, "w", newline="", encoding="utf-8") as csvfile:
            fieldnames = [
                "username",
                "email",
                "department",
                "arn",
                "user_creation_time",
                "password_enabled",
                "password_age",
                "password_compliance",
                "mfa_active",
                "access_key_1_active",
                "key_1_age",
                "key_1_compliance",
                "access_key_2_active",
                "key_2_age",
                "key_2_compliance",
                "overall_compliance",
                "key_rotation_exempt",
            ]

            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()

            for user in self.users_data:
                # Flatten the data for CSV export
                row = {
                    "username": user["username"],
                    "email": user["email"],
                    "department": user["department"],
                    "arn": user["arn"],
                    "user_creation_time": (
                        user["user_creation_time"].isoformat()
                        if user["user_creation_time"]
                        else ""
                    ),
                    "password_enabled": user["password_enabled"],
                    "password_age": user["password_age"],
                    "password_compliance": user["password_compliance"],
                    "mfa_active": user["mfa_active"],
                    "access_key_1_active": user["access_key_1_active"],
                    "key_1_age": user["key_1_age"],
                    "key_1_compliance": user["key_1_compliance"],
                    "access_key_2_active": user["access_key_2_active"],
                    "key_2_age": user["key_2_age"],
                    "key_2_compliance": user["key_2_compliance"],
                    "overall_compliance": user["overall_compliance"],
                    "key_rotation_exempt": user["key_rotation_exempt"],
                }
                writer.writerow(row)

        rprint(f"[green]✓[/green] Report exported to: {filepath}")

    def export_json(self, filename):
        """Export report to JSON file"""
        filepath = Path(filename)

        report_data = {
            "generated_at": datetime.now().isoformat(),
            "summary": self.summary_stats,
            "users": self.users_data,
        }

        with open(filepath, "w", encoding="utf-8") as jsonfile:
            json.dump(report_data, jsonfile, indent=2, default=str)

        rprint(f"[green]✓[/green] Report exported to: {filepath}")


def parse_args():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description="Generate IAM compliance reports",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                              # Display summary and detailed report
  %(prog)s --csv iam_report.csv         # Export to CSV
  %(prog)s --json iam_report.json       # Export to JSON
  %(prog)s --summary-only               # Show only summary
        """,
    )

    parser.add_argument("--csv", metavar="FILENAME", help="Export report to CSV file")
    parser.add_argument("--json", metavar="FILENAME", help="Export report to JSON file")
    parser.add_argument(
        "--summary-only", action="store_true", help="Show only summary statistics"
    )
    parser.add_argument("--quiet", action="store_true", help="Suppress console output")

    return parser.parse_args()


def main():
    """Main function"""
    args = parse_args()

    try:
        # Initialize report generator
        report = IAMComplianceReport()

        # Generate and parse credential report
        credential_report = report.generate_credential_report()
        report.parse_credential_report(credential_report)

        # Display results
        if not args.quiet:
            report.display_summary()

            if not args.summary_only:
                report.display_detailed_report()

        # Export to files
        if args.csv:
            report.export_csv(args.csv)

        if args.json:
            report.export_json(args.json)

        # Exit with error code if there are non-compliant users
        if (
            report.summary_stats["expired_keys"] > 0
            or report.summary_stats["expired_passwords"] > 0
        ):
            if not args.quiet:
                rprint(
                    "\n[red]⚠️  Found compliance issues! Exiting with error code 1[/red]"
                )
            exit(1)
        else:
            if not args.quiet:
                rprint("\n[green]✓ All users are compliant![/green]")
            exit(0)

    except KeyboardInterrupt:
        rprint("\n[yellow]Report generation cancelled.[/yellow]")
        exit(130)
    except Exception as e:
        logger.error(f"Error generating compliance report: {e}")
        rprint(f"[red]Error:[/red] {e}")
        exit(1)


if __name__ == "__main__":
    main()
