#!/usr/bin/env python3
"""
Test script for IAM key rotation workflow
Tests day 7 reminder and day 14 cleanup without waiting
"""

import boto3
import json
import time
from datetime import datetime, timedelta
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()

# Configuration
REGION = "us-east-1"
PROFILE = "dw-nonprod"
DYNAMODB_TABLE = "iam-key-rotation-tracking"
TEST_USERNAME = "iam-test-user-dev-1"

# Initialize AWS clients
session = boto3.Session(profile_name=PROFILE, region_name=REGION)
dynamodb = session.resource("dynamodb")
lambda_client = session.client("lambda")
iam_client = session.client("iam")
table = dynamodb.Table(DYNAMODB_TABLE)


def get_test_record():
    """Get the most recent rotation record for test user"""
    response = table.query(
        KeyConditionExpression="PK = :pk",
        ExpressionAttributeValues={":pk": f"USER#{TEST_USERNAME}"},
        ScanIndexForward=False,
        Limit=1
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
        "PK", "SK", "username", "old_key_id", "new_key_id",
        "downloaded", "status", "url_expires_at", 
        "old_key_deletion_date", "old_key_deleted"
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


def test_day_7_reminder():
    """Test URL regenerator (day 7 reminder)"""
    console.print("\n")
    console.print(Panel.fit("🔄 Testing Day 7 Reminder (URL Regenerator)", style="bold yellow"))
    
    # Get current record
    record = get_test_record()
    if not record:
        console.print("[red]❌ No test record found![/red]")
        return
    
    console.print("\n[cyan]📋 Original Record:[/cyan]")
    display_record(record, "Before Day 7 Test")
    
    # Calculate date for today (Lambda queries by date, not timestamp)
    today_date = datetime.now().date().isoformat()
    
    console.print(f"\n[yellow]⏰ Setting current_url_expires to today ({today_date}) to trigger reminder...[/yellow]")
    
    # Update record to simulate day 7 (URL expiring today, not downloaded)
    table.update_item(
        Key={"PK": record["PK"], "SK": record["SK"]},
        UpdateExpression="SET downloaded = :false, current_url_expires = :today, #st = :status",
        ExpressionAttributeNames={"#st": "status"},
        ExpressionAttributeValues={
            ":false": False,
            ":today": today_date,
            ":status": "pending_download"
        }
    )
    
    console.print("[green]✅ Record updated to simulate day 7[/green]")
    
    # Invoke url_regenerator Lambda
    console.print("\n[yellow]🚀 Invoking url_regenerator Lambda...[/yellow]")
    
    response = lambda_client.invoke(
        FunctionName="iam-key-url-regenerator",
        InvocationType="RequestResponse"
    )
    
    result = json.loads(response["Payload"].read())
    console.print(f"\n[cyan]Lambda Response:[/cyan]")
    console.print(json.dumps(result, indent=2))
    
    # Wait a moment for DynamoDB update
    time.sleep(2)
    
    # Get updated record
    updated_record = get_test_record()
    console.print("\n[cyan]📋 Updated Record:[/cyan]")
    display_record(updated_record, "After Day 7 Reminder")
    
    console.print("\n[green]✅ Day 7 reminder test complete![/green]")
    console.print("[yellow]Check your email for the reminder message![/yellow]")


def test_day_14_cleanup():
    """Test cleanup Lambda (day 14 old key deletion)"""
    console.print("\n")
    console.print(Panel.fit("🗑️  Testing Day 14 Cleanup (Old Key Deletion)", style="bold red"))
    
    # Get current record
    record = get_test_record()
    if not record:
        console.print("[red]❌ No test record found![/red]")
        return
    
    console.print("\n[cyan]📋 Original Record:[/cyan]")
    display_record(record, "Before Day 14 Test")
    
    # Check if old key exists
    old_key_id = record.get("old_key_id")
    if not old_key_id:
        console.print("[red]❌ No old_key_id in record![/red]")
        return
    
    try:
        keys = iam_client.list_access_keys(UserName=TEST_USERNAME)
        old_key_exists = any(k["AccessKeyId"] == old_key_id for k in keys["AccessKeyMetadata"])
        console.print(f"\n[cyan]Old key {old_key_id} exists: {old_key_exists}[/cyan]")
    except Exception as e:
        console.print(f"[yellow]Warning: Could not check old key: {e}[/yellow]")
    
    # Calculate timestamp for 14+ days ago
    fourteen_days_ago = int((datetime.now() - timedelta(days=14)).timestamp())
    
    console.print(f"\n[yellow]⏰ Backdating deletion date to simulate day 14...[/yellow]")
    
    # Update record to simulate day 14 (old key should be deleted)
    table.update_item(
        Key={"PK": record["PK"], "SK": record["SK"]},
        UpdateExpression="SET old_key_deletion_date = :deletion_date",
        ExpressionAttributeValues={
            ":deletion_date": fourteen_days_ago
        }
    )
    
    console.print("[green]✅ Record updated to simulate day 14[/green]")
    
    # Invoke cleanup Lambda
    console.print("\n[yellow]🚀 Invoking cleanup Lambda...[/yellow]")
    
    response = lambda_client.invoke(
        FunctionName="iam-key-cleanup",
        InvocationType="RequestResponse"
    )
    
    result = json.loads(response["Payload"].read())
    console.print(f"\n[cyan]Lambda Response:[/cyan]")
    console.print(json.dumps(result, indent=2))
    
    # Wait a moment for updates
    time.sleep(2)
    
    # Get updated record
    updated_record = get_test_record()
    console.print("\n[cyan]📋 Updated Record:[/cyan]")
    display_record(updated_record, "After Day 14 Cleanup")
    
    # Check if old key was deleted
    try:
        keys = iam_client.list_access_keys(UserName=TEST_USERNAME)
        old_key_exists = any(k["AccessKeyId"] == old_key_id for k in keys["AccessKeyMetadata"])
        if old_key_exists:
            console.print(f"\n[yellow]⚠️  Old key {old_key_id} still exists[/yellow]")
        else:
            console.print(f"\n[green]✅ Old key {old_key_id} was successfully deleted![/green]")
    except Exception as e:
        console.print(f"[yellow]Warning: Could not verify key deletion: {e}[/yellow]")
    
    console.print("\n[green]✅ Day 14 cleanup test complete![/green]")


def main():
    """Main test runner"""
    console.print(Panel.fit(
        "🧪 IAM Key Rotation Workflow Tester\n"
        "Tests day 7 reminder and day 14 cleanup without waiting",
        style="bold blue"
    ))
    
    console.print("\n[cyan]Select test to run:[/cyan]")
    console.print("1. Day 7 Reminder (URL regeneration)")
    console.print("2. Day 14 Cleanup (Old key deletion)")
    console.print("3. Both (in sequence)")
    console.print("4. Exit")
    
    choice = input("\nEnter choice (1-4): ").strip()
    
    if choice == "1":
        test_day_7_reminder()
    elif choice == "2":
        test_day_14_cleanup()
    elif choice == "3":
        test_day_7_reminder()
        console.print("\n" + "="*80 + "\n")
        input("Press Enter to continue to Day 14 test...")
        test_day_14_cleanup()
    elif choice == "4":
        console.print("[yellow]Exiting...[/yellow]")
    else:
        console.print("[red]Invalid choice![/red]")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[yellow]Test interrupted by user[/yellow]")
    except Exception as e:
        console.print(f"\n[red]Error: {e}[/red]")
        import traceback
        traceback.print_exc()
