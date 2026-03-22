#!/usr/bin/env python3
# flake8: noqa
"""
Test script for IAM key rotation workflow
Tests all phases: dynamic 7-day reminders, day 23 warning, day 30 deletion, day 45 cleanup
Dynamically reads retention periods from deployed Lambda configuration
"""

import boto3
import json
import time
from datetime import datetime, timedelta
import pytest
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()
pytestmark = pytest.mark.skip(
    reason="Operational workflow script; run manually against a configured AWS environment."
)

# Configuration
REGION = "us-east-1"
PROFILE = "dw-nonprod"
DYNAMODB_TABLE = "iam-key-rotation-tracking"
TEST_USERNAME = "iam-test-user-dev-1"

# Lazily initialized AWS clients for manual runs.
session = None
dynamodb = None
lambda_client = None
iam_client = None
s3_client = None
table = None

# Global config - loaded dynamically
CONFIG = {}


def ensure_clients():
    """Initialize AWS clients only for manual workflow runs."""
    global session, dynamodb, lambda_client, iam_client, s3_client, table
    if session is not None:
        return
    session = boto3.Session(profile_name=PROFILE, region_name=REGION)
    dynamodb = session.resource("dynamodb")
    lambda_client = session.client("lambda")
    iam_client = session.client("iam")
    s3_client = session.client("s3")
    table = dynamodb.Table(DYNAMODB_TABLE)


def load_config():
    """Load retention configuration from deployed Lambda"""
    global CONFIG
    ensure_clients()

    try:
        response = lambda_client.get_function_configuration(
            FunctionName="iam-access-key-enforcement"
        )
        env_vars = response.get("Environment", {}).get("Variables", {})

        CONFIG["NEW_KEY_RETENTION_DAYS"] = int(
            env_vars.get("NEW_KEY_RETENTION_DAYS", 45)
        )
        CONFIG["OLD_KEY_RETENTION_DAYS"] = int(
            env_vars.get("OLD_KEY_RETENTION_DAYS", 30)
        )
        CONFIG["S3_BUCKET"] = env_vars.get("S3_BUCKET")

        console.print(f"\n[green]✅ Configuration loaded from Lambda:[/green]")
        console.print(f"  • New Key Retention: {CONFIG['NEW_KEY_RETENTION_DAYS']} days")
        console.print(f"  • Old Key Retention: {CONFIG['OLD_KEY_RETENTION_DAYS']} days")
        console.print(f"  • S3 Bucket: {CONFIG['S3_BUCKET']}")

        # Calculate reminder days
        reminder_days = [d for d in range(7, CONFIG["NEW_KEY_RETENTION_DAYS"], 7)]
        console.print(f"  • Reminder Days: {reminder_days}")
        console.print(f"  • Warning Day: {CONFIG['OLD_KEY_RETENTION_DAYS'] - 7}")

    except Exception as e:
        console.print(f"[red]❌ Error loading config: {e}[/red]")
        console.print("[yellow]Using defaults: 45/30 days[/yellow]")
        CONFIG["NEW_KEY_RETENTION_DAYS"] = 45
        CONFIG["OLD_KEY_RETENTION_DAYS"] = 30


def get_test_record():
    """Get the most recent rotation record for test user"""
    ensure_clients()
    response = table.query(
        KeyConditionExpression="PK = :pk",
        ExpressionAttributeValues={":pk": f"USER#{TEST_USERNAME}"},
        ScanIndexForward=False,
        Limit=1,
    )
    if response["Items"]:
        return response["Items"][0]
    return None


def display_record(record, title="Current Record"):
    """Display DynamoDB record in a nice format"""
    table_display = Table(title=title)
    table_display.add_column("Field", style="cyan")
    table_display.add_column("Value", style="green")

    key_fields = [
        "PK",
        "SK",
        "username",
        "old_key_id",
        "new_key_id",
        "downloaded",
        "status",
        "url_expires_at",
        "old_key_deletion_date",
        "old_key_deleted",
    ]

    for field in key_fields:
        if field in record:
            value = str(record[field])
            if field in ["url_expires_at", "old_key_deletion_date"]:
                try:
                    ts = int(record[field])
                    dt = datetime.fromtimestamp(ts)
                    value = f"{value} ({dt.strftime('%Y-%m-%d %H:%M:%S')})"
                except:
                    pass
            table_display.add_row(field, value)

    console.print(table_display)


def run_reminder_test(day_number):
    """Test URL regenerator for any 7-day reminder (dynamically calculated)"""
    console.print("\n")
    console.print(
        Panel.fit(
            f"🔄 Testing Day {day_number} Reminder (URL Regenerator)",
            style="bold yellow",
        )
    )

    # Get current record
    record = get_test_record()
    if not record:
        console.print("[red]❌ No test record found![/red]")
        return

    console.print("\n[cyan]📋 Original Record:[/cyan]")
    display_record(record, f"Before Day {day_number} Test")

    # Backdate rotation_initiated to simulate the specified day
    target_date = datetime.now() - timedelta(days=day_number)

    console.print(
        f"\n[yellow]⏰ Backdating rotation to {day_number} days ago to trigger reminder...[/yellow]"
    )

    # Update record to simulate the target day
    table.update_item(
        Key={"PK": record["PK"], "SK": record["SK"]},
        UpdateExpression="SET downloaded = :false, rotation_initiated = :rotation_date, #st = :status",
        ExpressionAttributeNames={"#st": "status"},
        ExpressionAttributeValues={
            ":false": False,
            ":rotation_date": target_date.isoformat(),
            ":status": "pending_download",
        },
    )

    console.print(f"[green]✅ Record updated to simulate day {day_number}[/green]")

    # Invoke url_regenerator Lambda
    console.print("\n[yellow]🚀 Invoking url_regenerator Lambda...[/yellow]")

    response = lambda_client.invoke(
        FunctionName="iam-key-url-regenerator", InvocationType="RequestResponse"
    )

    result = json.loads(response["Payload"].read())
    console.print(f"\n[cyan]Lambda Response:[/cyan]")
    console.print(json.dumps(result, indent=2))

    # Wait a moment for DynamoDB update
    time.sleep(2)

    # Get updated record
    updated_record = get_test_record()
    console.print("\n[cyan]📋 Updated Record:[/cyan]")
    display_record(updated_record, f"After Day {day_number} Reminder")

    console.print(f"\n[green]✅ Day {day_number} reminder test complete![/green]")
    console.print("[yellow]Check your email for the reminder message![/yellow]")


def run_old_key_warning_test():
    """Test day 23 old key deletion warning"""
    warning_day = CONFIG["OLD_KEY_RETENTION_DAYS"] - 7

    console.print("\n")
    console.print(
        Panel.fit(
            f"⚠️  Testing Day {warning_day} Warning (Old Key Deletion in 7 Days)",
            style="bold yellow",
        )
    )

    # Get current record
    record = get_test_record()
    if not record:
        console.print("[red]❌ No test record found![/red]")
        return

    console.print("\n[cyan]📋 Original Record:[/cyan]")
    display_record(record, f"Before Day {warning_day} Test")

    # Backdate rotation to simulate warning day
    target_date = datetime.now() - timedelta(days=warning_day)

    console.print(
        f"\n[yellow]⏰ Backdating rotation to {warning_day} days ago...[/yellow]"
    )

    table.update_item(
        Key={"PK": record["PK"], "SK": record["SK"]},
        UpdateExpression="SET rotation_initiated = :rotation_date, old_key_deleted = :false",
        ExpressionAttributeValues={
            ":rotation_date": target_date.isoformat(),
            ":false": False,
        },
    )

    console.print("[green]✅ Record updated[/green]")

    # Invoke cleanup Lambda
    console.print("\n[yellow]🚀 Invoking cleanup Lambda...[/yellow]")

    response = lambda_client.invoke(
        FunctionName="iam-key-cleanup", InvocationType="RequestResponse"
    )

    result = json.loads(response["Payload"].read())
    console.print(f"\n[cyan]Lambda Response:[/cyan]")
    console.print(json.dumps(result, indent=2))

    time.sleep(2)

    console.print(f"\n[green]✅ Day {warning_day} warning test complete![/green]")
    console.print("[yellow]Check your email for the 7-day deletion warning![/yellow]")


def run_old_key_deletion_test():
    """Test day 30 old key deletion with conditional email"""
    deletion_day = CONFIG["OLD_KEY_RETENTION_DAYS"]

    console.print("\n")
    console.print(
        Panel.fit(
            f"🗑️  Testing Day {deletion_day} Cleanup (Old Key Deletion)",
            style="bold red",
        )
    )

    # Get current record
    record = get_test_record()
    if not record:
        console.print("[red]❌ No test record found![/red]")
        return

    console.print("\n[cyan]📋 Original Record:[/cyan]")
    display_record(record, f"Before Day {deletion_day} Test")

    # Check if old key exists
    old_key_id = record.get("old_key_id")
    if not old_key_id:
        console.print("[red]❌ No old_key_id in record![/red]")
        return

    try:
        keys = iam_client.list_access_keys(UserName=TEST_USERNAME)
        old_key_exists = any(
            k["AccessKeyId"] == old_key_id for k in keys["AccessKeyMetadata"]
        )
        console.print(f"\n[cyan]Old key {old_key_id} exists: {old_key_exists}[/cyan]")
    except Exception as e:
        console.print(f"[yellow]Warning: Could not check old key: {e}[/yellow]")

    # Backdate rotation to simulate deletion day
    target_date = datetime.now() - timedelta(days=deletion_day)

    console.print(
        f"\n[yellow]⏰ Backdating rotation to {deletion_day} days ago...[/yellow]"
    )

    # Update record to simulate deletion day
    table.update_item(
        Key={"PK": record["PK"], "SK": record["SK"]},
        UpdateExpression="SET rotation_initiated = :rotation_date, old_key_deleted = :false",
        ExpressionAttributeValues={
            ":rotation_date": target_date.isoformat(),
            ":false": False,
        },
    )

    console.print(f"[green]✅ Record updated to simulate day {deletion_day}[/green]")

    # Invoke cleanup Lambda
    console.print("\n[yellow]🚀 Invoking cleanup Lambda...[/yellow]")

    response = lambda_client.invoke(
        FunctionName="iam-key-cleanup", InvocationType="RequestResponse"
    )

    result = json.loads(response["Payload"].read())
    console.print(f"\n[cyan]Lambda Response:[/cyan]")
    console.print(json.dumps(result, indent=2))

    # Wait a moment for updates
    time.sleep(2)

    # Get updated record
    updated_record = get_test_record()
    console.print("\n[cyan]📋 Updated Record:[/cyan]")
    display_record(updated_record, f"After Day {deletion_day} Cleanup")

    # Check if old key was deleted
    try:
        keys = iam_client.list_access_keys(UserName=TEST_USERNAME)
        old_key_exists = any(
            k["AccessKeyId"] == old_key_id for k in keys["AccessKeyMetadata"]
        )
        if old_key_exists:
            console.print(f"\n[yellow]⚠️  Old key {old_key_id} still exists[/yellow]")
        else:
            console.print(
                f"\n[green]✅ Old key {old_key_id} was successfully deleted![/green]"
            )
    except Exception as e:
        console.print(f"[yellow]Warning: Could not verify key deletion: {e}[/yellow]")

    console.print(f"\n[green]✅ Day {deletion_day} cleanup test complete![/green]")
    console.print(
        "[yellow]Check your email - message depends on if you downloaded![/yellow]"
    )


def run_s3_cleanup_test():
    """Test day 45 S3 credentials cleanup"""
    cleanup_day = CONFIG["NEW_KEY_RETENTION_DAYS"]

    console.print("\n")
    console.print(
        Panel.fit(
            f"🗑️  Testing Day {cleanup_day} S3 Cleanup (Expired Credentials)",
            style="bold red",
        )
    )

    # Get current record
    record = get_test_record()
    if not record:
        console.print("[red]❌ No test record found![/red]")
        return

    console.print("\n[cyan]📋 Original Record:[/cyan]")
    display_record(record, f"Before Day {cleanup_day} Test")

    s3_key = record.get("s3_key")
    if s3_key:
        console.print(f"\n[cyan]S3 File: {s3_key}[/cyan]")

    # Backdate rotation to simulate expiration day
    target_date = datetime.now() - timedelta(days=cleanup_day)

    console.print(
        f"\n[yellow]⏰ Backdating rotation to {cleanup_day} days ago (credentials expired)...[/yellow]"
    )

    table.update_item(
        Key={"PK": record["PK"], "SK": record["SK"]},
        UpdateExpression="SET rotation_initiated = :rotation_date, downloaded = :false, s3_file_deleted = :false",
        ExpressionAttributeValues={
            ":rotation_date": target_date.isoformat(),
            ":false": False,
        },
    )

    console.print("[green]✅ Record updated[/green]")

    # Invoke S3 cleanup Lambda
    console.print("\n[yellow]🚀 Invoking S3 cleanup Lambda...[/yellow]")

    response = lambda_client.invoke(
        FunctionName="iam-s3-credentials-cleanup", InvocationType="RequestResponse"
    )

    result = json.loads(response["Payload"].read())
    console.print(f"\n[cyan]Lambda Response:[/cyan]")
    console.print(json.dumps(result, indent=2))

    time.sleep(2)

    # Check if S3 file was deleted
    if s3_key and CONFIG.get("S3_BUCKET"):
        try:
            s3_client.head_object(Bucket=CONFIG["S3_BUCKET"], Key=s3_key)
            console.print(f"\n[yellow]⚠️  S3 file still exists[/yellow]")
        except:
            console.print(f"\n[green]✅ S3 file was deleted![/green]")

    updated_record = get_test_record()
    console.print("\n[cyan]📋 Updated Record:[/cyan]")
    display_record(updated_record, f"After Day {cleanup_day} Cleanup")

    console.print(f"\n[green]✅ Day {cleanup_day} S3 cleanup test complete![/green]")
    console.print(
        "[yellow]Check your email for the expiration notice (if not downloaded)![/yellow]"
    )


def main():
    """Main test runner"""
    console.print(
        Panel.fit(
            "🧪 IAM Key Rotation Workflow Tester\n"
            "Tests all workflow phases with dynamic retention periods",
            style="bold blue",
        )
    )

    # Load configuration from Lambda
    load_config()

    # Calculate available reminder days
    reminder_days = [d for d in range(7, CONFIG["NEW_KEY_RETENTION_DAYS"], 7)]
    warning_day = CONFIG["OLD_KEY_RETENTION_DAYS"] - 7
    deletion_day = CONFIG["OLD_KEY_RETENTION_DAYS"]
    cleanup_day = CONFIG["NEW_KEY_RETENTION_DAYS"]

    console.print("\n[cyan]Select test to run:[/cyan]")
    console.print("\n[bold]7-Day Reminders (Dynamic):[/bold]")
    for i, day in enumerate(reminder_days, 1):
        console.print(f"{i}. Day {day} Reminder (URL regeneration)")

    console.print(f"\n[bold]Old Key Lifecycle:[/bold]")
    console.print(f"{len(reminder_days) + 1}. Day {warning_day} Warning (7-day notice)")
    console.print(
        f"{len(reminder_days) + 2}. Day {deletion_day} Deletion (Old key removed)"
    )

    console.print(f"\n[bold]Credential Expiration:[/bold]")
    console.print(
        f"{len(reminder_days) + 3}. Day {cleanup_day} S3 Cleanup (Expired credentials)"
    )

    console.print(f"\n[bold]Other Options:[/bold]")
    console.print(f"{len(reminder_days) + 4}. Run All Tests (in sequence)")
    console.print(f"{len(reminder_days) + 5}. Exit")

    choice = input("\nEnter choice: ").strip()

    try:
        choice_num = int(choice)

        # Handle reminder day tests
        if 1 <= choice_num <= len(reminder_days):
            run_reminder_test(reminder_days[choice_num - 1])

        # Old key warning
        elif choice_num == len(reminder_days) + 1:
            run_old_key_warning_test()

        # Old key deletion
        elif choice_num == len(reminder_days) + 2:
            run_old_key_deletion_test()

        # S3 cleanup
        elif choice_num == len(reminder_days) + 3:
            run_s3_cleanup_test()

        # Run all
        elif choice_num == len(reminder_days) + 4:
            for day in reminder_days:
                run_reminder_test(day)
                console.print("\n" + "=" * 80 + "\n")
                input("Press Enter to continue...")

            run_old_key_warning_test()
            console.print("\n" + "=" * 80 + "\n")
            input("Press Enter to continue...")

            run_old_key_deletion_test()
            console.print("\n" + "=" * 80 + "\n")
            input("Press Enter to continue...")

            run_s3_cleanup_test()

        # Exit
        elif choice_num == len(reminder_days) + 5:
            console.print("[yellow]Exiting...[/yellow]")

        else:
            console.print("[red]Invalid choice![/red]")

    except ValueError:
        console.print("[red]Invalid input![/red]")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[yellow]Test interrupted by user[/yellow]")
    except Exception as e:
        console.print(f"\n[red]Error: {e}[/red]")
        import traceback

        traceback.print_exc()
