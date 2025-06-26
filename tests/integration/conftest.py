"""
Pytest configuration and fixtures for integration tests
"""

import os
import sys
import pytest
from unittest.mock import MagicMock

# Add scripts directory to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "scripts"))


@pytest.fixture
def mock_iam_client():
    """Mock IAM client for testing"""
    client = MagicMock()

    # Set up common mock responses
    client.get_caller_identity.return_value = {
        "UserId": "AIDAI23456789012EXAMPLE",
        "Account": "000000000000",
        "Arn": "arn:aws:iam::000000000000:user/testuser",
    }

    return client


@pytest.fixture
def mock_boto3_client(monkeypatch, mock_iam_client):
    """Mock boto3.client to return our mock IAM client"""

    def mock_client(service_name):
        if service_name == "iam":
            return mock_iam_client
        return MagicMock()

    monkeypatch.setattr("boto3.client", mock_client)
    return mock_iam_client


@pytest.fixture
def temp_credentials_file(tmp_path):
    """Create a temporary credentials file for testing"""
    creds_dir = tmp_path / ".aws"
    creds_dir.mkdir()
    creds_file = creds_dir / "credentials"

    # Create sample credentials
    creds_file.write_text(
        """[default]
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY

[production]
aws_access_key_id = AKIAIOSFODNN7PROD
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYPRODKEY
"""
    )

    return creds_file
