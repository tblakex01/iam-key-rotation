"""
Jenna Sprattler | SRE Kentik | 2023-06-07
Script to cleanup hardware/virtual MFA devices, access keys and
login profiles prior to deleting user programmatically from e.g.
Terraform where these settings are managed outside of the code.
"""

import sys
import boto3

client = boto3.client("iam")


def check_username():
    """Check if username argument is provided and the user exists"""
    if len(sys.argv) < 2 or sys.argv[1] == "--help":
        print("Usage: python aws_iam_user_cleanup.py <username>")
        return None

    user_name = sys.argv[1]

    # Use paginator to handle accounts with many users
    paginator = client.get_paginator("list_users")
    existing_users = []
    for page in paginator.paginate():
        existing_users.extend([user["UserName"] for user in page["Users"]])

    if user_name not in existing_users:
        print(f"The user '{user_name}' does not exist.")
        return None

    return user_name


def delete_login_profile(user_name):
    """Delete the login profile for the user"""
    try:
        client.delete_login_profile(UserName=user_name)
        print(f"Deleting login profile for {user_name}")
        return True
    except client.exceptions.NoSuchEntityException:
        print(f"No login profile found for {user_name}")
        return True  # Not an error if profile doesn't exist
    except Exception as e:
        print(f"Error deleting login profile for {user_name}: {e}")
        return False


def delete_mfa_devices(user_name):
    """Get the list of MFA devices for the user and delete each MFA device"""
    try:
        # Use paginator for MFA devices
        paginator = client.get_paginator("list_mfa_devices")
        mfa_devices = []
        for page in paginator.paginate(UserName=user_name):
            mfa_devices.extend(page.get("MFADevices", []))

        if not mfa_devices:
            print(f"No MFA devices found for {user_name}")
            return True

        success = True
        for device in mfa_devices:
            device_name = device["SerialNumber"]
            try:
                print(f"Deleting MFA device for {user_name}: {device_name}")
                client.deactivate_mfa_device(
                    UserName=user_name, SerialNumber=device_name
                )
            except Exception as e:
                print(f"Error deleting MFA device {device_name}: {e}")
                success = False

        return success
    except Exception as e:
        print(f"Error listing MFA devices for {user_name}: {e}")
        return False


def delete_access_keys(user_name):
    """Delete all access keys associated with user"""
    try:
        # Use paginator to handle users with many keys
        paginator = client.get_paginator("list_access_keys")
        access_keys = []
        for page in paginator.paginate(UserName=user_name):
            access_keys.extend(page["AccessKeyMetadata"])

        if not access_keys:
            print(f"No access keys found for {user_name}")
            return True

        success = True
        # Delete each access key
        for key in access_keys:
            access_key_id = key["AccessKeyId"]
            try:
                client.delete_access_key(UserName=user_name, AccessKeyId=access_key_id)
                print(f"Deleted access key: {access_key_id} for {user_name}")
            except Exception as e:
                print(f"Error deleting access key {access_key_id}: {e}")
                success = False

        return success
    except Exception as e:
        print(f"Error listing access keys for {user_name}: {e}")
        return False


def main():
    """Get the IAM username argument and proceed with cleanup only if username is valid"""
    if user_name := check_username():
        # Track success of each operation
        success = True

        # Delete each component, tracking failures
        if not delete_login_profile(user_name):
            success = False

        if not delete_mfa_devices(user_name):
            success = False

        if not delete_access_keys(user_name):
            success = False

        # Exit with appropriate code
        if success:
            print(f"Successfully cleaned up all resources for {user_name}")
            sys.exit(0)
        else:
            print(f"Some cleanup operations failed for {user_name}")
            sys.exit(1)


if __name__ == "__main__":
    main()
