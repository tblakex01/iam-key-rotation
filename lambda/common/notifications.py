"""Shared notification rendering for IAM key rotation emails."""

from __future__ import annotations

from datetime import datetime

from .rotation_common import RuntimeConfig


def render_enforcement_email(
    notification: dict[str, str | int], config: RuntimeConfig
) -> tuple[str, str]:
    action = str(notification["action"])
    username = str(notification["username"])
    key_id = str(
        notification.get("old_key_id") or notification.get("key_id") or "unknown"
    )
    age = int(notification["age"])

    if action == "rotated":
        deletion_date = datetime.fromtimestamp(
            int(notification["old_key_deletion_date"])
        ).strftime("%B %d, %Y")
        subject = "[AWS-IAM-CREDS] Action Required: Download Your New Access Key"
        html = f"""<!DOCTYPE html>
<html><body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
<div style="max-width: 600px; margin: 0 auto; padding: 20px;">
<h2 style="color: #232f3e;">AWS Access Key Rotation Required</h2>
<p>Hello <strong>{username}</strong>,</p>
<p>Your AWS access key has been rotated for security compliance. Download your new credentials using the link below.</p>
<div style="background-color: #fff3cd; border-left: 4px solid #ff9900; padding: 15px; margin: 20px 0;">
<p style="margin: 0;"><strong>Old Key ID:</strong> <code>{key_id}</code></p>
<p style="margin: 5px 0;"><strong>Key Age:</strong> {age} days</p>
<p style="margin: 5px 0;"><strong>Link Expires:</strong> {notification["url_expires"]}</p>
<p style="margin: 5px 0;"><strong>Old Key Deletion Date:</strong> {deletion_date}</p>
</div>
<div style="text-align: center; margin: 30px 0;">
<a href="{notification["download_url"]}" style="background-color: #ff9900; color: white; padding: 15px 30px; text-decoration: none; border-radius: 4px; font-weight: bold;">
Download New Credentials
</a>
</div>
<p>If you need help, contact <a href="mailto:{config.support_email}">{config.support_email}</a>.</p>
</div></body></html>"""
        return subject, html

    subject_map = {
        "warning": "[AWS-IAM-CREDS] Warning: Access Key Rotation Required Soon",
        "urgent": "[AWS-IAM-CREDS] Critical: Access Key Rotation Required Immediately",
        "expired": "[AWS-IAM-CREDS] Critical: Access Key Rotation Overdue",
        "disabled": "[AWS-IAM-CREDS] Critical: Access Key Disabled",
    }
    subject = subject_map.get(action, "[AWS-IAM-CREDS] Access Key Rotation Notice")
    html = f"""<!DOCTYPE html>
<html><body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
<div style="max-width: 600px; margin: 0 auto; padding: 20px;">
<h2 style="color: #232f3e;">Access Key Rotation Notice</h2>
<p>Hello <strong>{username}</strong>,</p>
<p>Your AWS access key <code>{key_id}</code> is {age} days old and requires action.</p>
<div style="background-color: #f8f9fa; border-left: 4px solid #232f3e; padding: 15px; margin: 20px 0;">
<p style="margin: 0;"><strong>Status:</strong> {action.upper()}</p>
<p style="margin: 5px 0;"><strong>Support:</strong> <a href="mailto:{config.support_email}">{config.support_email}</a></p>
</div>
</div></body></html>"""
    return subject, html


def render_reminder_email(
    *,
    username: str,
    old_key_id: str,
    presigned_url: str,
    url_expires: str,
    old_key_deleted: bool,
    support_email: str,
    reminder_day: int,
) -> tuple[str, str]:
    status_line = (
        "Your old key has already been deleted. Download your new credentials immediately."
        if old_key_deleted
        else "Your old key will be deleted automatically if you do not complete the rotation."
    )
    subject = (
        f"[AWS-IAM-CREDS] Reminder Day {reminder_day}: Download Your New Access Key"
    )
    html = f"""<!DOCTYPE html>
<html><body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
<div style="max-width: 600px; margin: 0 auto; padding: 20px;">
<h2 style="color: #cc0000;">Credentials Not Yet Downloaded</h2>
<p>Hello <strong>{username}</strong>,</p>
<p>{status_line}</p>
<div style="background-color: #ffe6e6; border-left: 4px solid #cc0000; padding: 15px; margin: 20px 0;">
<p style="margin: 0;"><strong>Old Key ID:</strong> <code>{old_key_id}</code></p>
<p style="margin: 5px 0;"><strong>Reminder Day:</strong> {reminder_day}</p>
<p style="margin: 5px 0;"><strong>Link Expires:</strong> {url_expires}</p>
</div>
<div style="text-align: center; margin: 30px 0;">
<a href="{presigned_url}" style="background-color: #cc0000; color: white; padding: 15px 30px; text-decoration: none; border-radius: 4px; font-weight: bold;">
Download Credentials
</a>
</div>
<p>Need help? Contact <a href="mailto:{support_email}">{support_email}</a>.</p>
</div></body></html>"""
    return subject, html


def render_old_key_warning_email(
    *, username: str, old_key_id: str, deletion_date: str, support_email: str
) -> tuple[str, str]:
    subject = "[AWS-IAM-CREDS] Warning: Old Access Key Will Be Deleted in 7 Days"
    html = f"""<!DOCTYPE html>
<html><body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
<div style="max-width: 600px; margin: 0 auto; padding: 20px;">
<h2 style="color: #ff9900;">Old Access Key Deletion Scheduled</h2>
<p>Hello <strong>{username}</strong>,</p>
<p>Your old AWS access key will be deleted in 7 days.</p>
<div style="background-color: #fff3cd; border-left: 4px solid #ff9900; padding: 15px; margin: 20px 0;">
<p style="margin: 0;"><strong>Old Key ID:</strong> <code>{old_key_id}</code></p>
<p style="margin: 5px 0;"><strong>Deletion Date:</strong> {deletion_date}</p>
</div>
<p>Need help? Contact <a href="mailto:{support_email}">{support_email}</a>.</p>
</div></body></html>"""
    return subject, html


def render_old_key_deleted_email(
    *,
    username: str,
    old_key_id: str,
    downloaded: bool,
    support_email: str,
    presigned_url: str | None = None,
    url_expires: str | None = None,
) -> tuple[str, str]:
    if downloaded:
        subject = "[AWS-IAM-CREDS] Old Access Key Successfully Deleted"
        html = f"""<!DOCTYPE html>
<html><body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
<div style="max-width: 600px; margin: 0 auto; padding: 20px;">
<h2 style="color: #28a745;">Old Access Key Deleted</h2>
<p>Hello <strong>{username}</strong>,</p>
<p>Your old AWS access key <code>{old_key_id}</code> has been deleted. Your rotation is complete.</p>
</div></body></html>"""
        return subject, html

    subject = "[AWS-IAM-CREDS] Urgent: Old Access Key Deleted, New Credentials Pending"
    button = ""
    if presigned_url and url_expires:
        button = f"""
<div style="text-align: center; margin: 30px 0;">
<a href="{presigned_url}" style="background-color: #cc0000; color: white; padding: 15px 30px; text-decoration: none; border-radius: 4px; font-weight: bold;">
Download Credentials
</a>
</div>
<p style="text-align: center;"><strong>Link Expires:</strong> {url_expires}</p>
"""
    html = f"""<!DOCTYPE html>
<html><body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
<div style="max-width: 600px; margin: 0 auto; padding: 20px;">
<h2 style="color: #cc0000;">Urgent Action Required</h2>
<p>Hello <strong>{username}</strong>,</p>
<p>Your old AWS access key <code>{old_key_id}</code> has been deleted, but our records show your new credentials are still pending download.</p>
{button}
<p>Need help? Contact <a href="mailto:{support_email}">{support_email}</a>.</p>
</div></body></html>"""
    return subject, html


def render_credentials_expired_email(
    *, username: str, old_key_id: str, support_email: str
) -> tuple[str, str]:
    subject = "[AWS-IAM-CREDS] Critical: Your New Credentials Have Expired"
    html = f"""<!DOCTYPE html>
<html><body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
<div style="max-width: 600px; margin: 0 auto; padding: 20px;">
<h2 style="color: #cc0000;">Credentials Expired</h2>
<p>Hello <strong>{username}</strong>,</p>
<p>Your new credentials for old key <code>{old_key_id}</code> expired before they were downloaded.</p>
<p>Contact <a href="mailto:{support_email}">{support_email}</a> for manual recovery.</p>
</div></body></html>"""
    return subject, html
