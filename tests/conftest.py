"""Global pytest configuration for repository tests."""

from __future__ import annotations

import os
from pathlib import Path
from tempfile import gettempdir

_aws_stub_dir = Path(gettempdir()) / "iam-key-rotation-pytest-aws"
_aws_stub_dir.mkdir(parents=True, exist_ok=True)
_credentials_file = _aws_stub_dir / "credentials"
_config_file = _aws_stub_dir / "config"
_credentials_file.write_text(
    "[default]\naws_access_key_id = testing\naws_secret_access_key = testing\n"
)
_config_file.write_text("[default]\nregion = us-east-1\n")

os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")
os.environ.setdefault("AWS_SESSION_TOKEN", "testing")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
os.environ.setdefault("AWS_EC2_METADATA_DISABLED", "true")
os.environ.setdefault("AWS_SHARED_CREDENTIALS_FILE", str(_credentials_file))
os.environ.setdefault("AWS_CONFIG_FILE", str(_config_file))
