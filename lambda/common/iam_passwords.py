"""IAM password policy helpers shared by scripts and Lambdas."""

from __future__ import annotations

import logging
import secrets
import string
from typing import Any, Mapping

from botocore.exceptions import ClientError

__all__ = [
    "load_password_policy",
    "validate_password_against_policy",
    "generate_temporary_password",
]

LOGGER = logging.getLogger(__name__)

DEFAULT_SYMBOLS = "!@#$%^&*()_+-=[]{}|;:,.<>?"
AMBIGUOUS_CHARACTERS = "0O1lI"


def load_password_policy(iam_client) -> Mapping[str, Any]:
    """Load the account password policy, returning an empty dict on failure."""
    try:
        response = iam_client.get_account_password_policy()
        if isinstance(response, Mapping):
            policy = response.get("PasswordPolicy", {})
            if isinstance(policy, Mapping):
                return policy
        return {}
    except ClientError:
        LOGGER.debug("Unable to fetch password policy, falling back to defaults")
        return {}


def validate_password_against_policy(
    password: str, policy: Mapping[str, Any]
) -> list[str]:
    errors: list[str] = []
    min_length = int(policy.get("MinimumPasswordLength", 8))
    if len(password) < min_length:
        errors.append(f"Password must be at least {min_length} characters long")
    if policy.get("RequireUppercaseCharacters", False) and not any(
        c.isupper() for c in password
    ):
        errors.append("Password must contain uppercase letters")
    if policy.get("RequireLowercaseCharacters", False) and not any(
        c.islower() for c in password
    ):
        errors.append("Password must contain lowercase letters")
    if policy.get("RequireNumbers", False) and not any(c.isdigit() for c in password):
        errors.append("Password must contain numbers")
    if policy.get("RequireSymbols", False) and not any(
        c in DEFAULT_SYMBOLS for c in password
    ):
        errors.append("Password must contain symbols")
    return errors


def _build_character_sets(exclude_ambiguous: bool) -> tuple[str, str, str, str]:
    uppercase = string.ascii_uppercase
    lowercase = string.ascii_lowercase
    digits = string.digits
    symbols = DEFAULT_SYMBOLS
    if exclude_ambiguous:
        translation = str.maketrans("", "", AMBIGUOUS_CHARACTERS)
        uppercase = uppercase.translate(translation)
        lowercase = lowercase.translate(translation)
        digits = digits.translate(translation)
    return uppercase, lowercase, digits, symbols


def generate_temporary_password(
    iam_client,
    *,
    min_length: int = 20,
    exclude_ambiguous: bool = True,
) -> str:
    """Generate a temporary password compliant with the account password policy."""
    policy = load_password_policy(iam_client)
    uppercase, lowercase, digits, symbols = _build_character_sets(exclude_ambiguous)

    while True:
        length = max(min_length, int(policy.get("MinimumPasswordLength", min_length)))
        password_chars: list[str] = [
            secrets.choice(uppercase),
            secrets.choice(lowercase),
            secrets.choice(digits),
            secrets.choice(symbols),
        ]
        all_chars = uppercase + lowercase + digits + symbols
        for _ in range(length - len(password_chars)):
            password_chars.append(secrets.choice(all_chars))
        secrets.SystemRandom().shuffle(password_chars)
        candidate = "".join(password_chars)
        validation_errors = validate_password_against_policy(candidate, policy)
        if not validation_errors:
            return candidate
        LOGGER.debug(
            "Regenerating password because of policy violations: %s", validation_errors
        )
