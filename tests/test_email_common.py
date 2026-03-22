#!/usr/bin/env python3
"""Unit tests for the shared SES email helper."""

from __future__ import annotations

import os
import sys
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lambda"))

from common.email import EmailConfig, send_html_email  # noqa: E402


class TestEmailCommon(unittest.TestCase):
    @patch.dict(
        os.environ,
        {
            "SENDER_EMAIL": "security@example.com",
            "SUPPORT_EMAIL": "support@example.com",
            "SES_REGION": "us-east-1",
            "SES_CONFIGURATION_SET": "ops-config",
        },
        clear=False,
    )
    def test_email_config_loads_env(self):
        config = EmailConfig.load()
        self.assertEqual(config.sender_email, "security@example.com")
        self.assertEqual(config.support_email, "support@example.com")
        self.assertEqual(config.ses_region, "us-east-1")
        self.assertEqual(config.ses_configuration_set, "ops-config")

    @patch("common.email.get_sesv2_client")
    def test_send_html_email_uses_expected_sesv2_payload(self, mock_get_client):
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        mock_client.send_email.return_value = {"MessageId": "mid-123"}

        result = send_html_email(
            config=EmailConfig(
                sender_email="security@example.com",
                support_email="support@example.com",
                ses_region="us-east-1",
                ses_configuration_set="ops-config",
            ),
            to_addresses=["alice@example.com"],
            subject="Subject",
            html_body="<p>Hello</p>",
            text_body="Hello",
            reply_to=["reply@example.com"],
        )

        self.assertEqual(result["MessageId"], "mid-123")
        mock_client.send_email.assert_called_once_with(
            FromEmailAddress="security@example.com",
            Destination={"ToAddresses": ["alice@example.com"]},
            Content={
                "Simple": {
                    "Subject": {"Data": "Subject"},
                    "Body": {
                        "Html": {"Data": "<p>Hello</p>"},
                        "Text": {"Data": "Hello"},
                    },
                }
            },
            ReplyToAddresses=["reply@example.com"],
            ConfigurationSetName="ops-config",
        )


if __name__ == "__main__":
    unittest.main()
