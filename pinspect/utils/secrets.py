"""
Secret detection and redaction utilities for environment variables.
"""

import re
from typing import Dict, Tuple, Optional

# Secret name patterns (case-insensitive substring or regex matches)
SECRET_NAME_PATTERNS = [
    re.compile(r".*_TOKEN$", re.IGNORECASE),
    re.compile(r".*_SECRET.*", re.IGNORECASE),
    re.compile(r".*_PASSWORD.*", re.IGNORECASE),
    re.compile(r".*_PASSWD.*", re.IGNORECASE),
    re.compile(r".*_PASS$", re.IGNORECASE),
    re.compile(r".*_KEY$", re.IGNORECASE),
    re.compile(r"^AWS_.*", re.IGNORECASE),
    re.compile(r".*DATABASE_URL.*", re.IGNORECASE),
    re.compile(r".*DB_URL.*", re.IGNORECASE),
    re.compile(r".*DB_PASSWORD.*", re.IGNORECASE),
    re.compile(r".*API_KEY.*", re.IGNORECASE),
    re.compile(r".*AUTH_TOKEN.*", re.IGNORECASE),
    re.compile(r"^BEARER_.*", re.IGNORECASE),
    re.compile(r".*CREDENTIALS.*", re.IGNORECASE),
    re.compile(r".*PRIVATE_KEY.*", re.IGNORECASE),
    re.compile(r".*SESSION_KEY.*", re.IGNORECASE),
    re.compile(r".*COOKIE_SECRET.*", re.IGNORECASE),
    re.compile(r".*ENCRYPTION_KEY.*", re.IGNORECASE),
    re.compile(r".*SIGNING_KEY.*", re.IGNORECASE),
    re.compile(r".*VAULT_TOKEN.*", re.IGNORECASE),
    re.compile(r".*GITHUB_TOKEN.*", re.IGNORECASE),
    re.compile(r".*GITLAB_TOKEN.*", re.IGNORECASE),
    re.compile(r".*SENTRY_DSN.*", re.IGNORECASE),
    re.compile(r".*STRIPE_.*", re.IGNORECASE),
    re.compile(r".*TWILIO_.*", re.IGNORECASE),
]

# Sensitive value regexes
SECRET_VALUE_PATTERNS = [
    re.compile(r"^AKIA[0-9A-Z]{16}$"),                       # AWS Access Key ID
    re.compile(r"^ghp_[a-zA-Z0-9]{36}$"),                   # GitHub Personal Token
    re.compile(r"^gho_[a-zA-Z0-9]{36}$"),                   # GitHub OAuth Token
    re.compile(r"^glpat-[a-zA-Z0-9\-_]{20,}$"),             # GitLab Personal Token
    re.compile(r"^ey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*$"),  # JWT Token
    re.compile(r"-----BEGIN\s+[A-Z\s]+PRIVATE\s+KEY-----"),  # Private Key header
    re.compile(r"^xox[baprs]-[0-9a-zA-Z]{10,48}"),          # Slack Token
    re.compile(r"^sq0atp-[0-9A-Za-z\-_]{22}"),              # Square Access Token
]


def is_secret_name(key: str) -> bool:
    """Check if an environment variable key name matches secret patterns."""
    for pattern in SECRET_NAME_PATTERNS:
        if pattern.search(key):
            return True
    return False


def is_secret_value(value: str) -> bool:
    """Check if an environment variable value matches known token/secret patterns."""
    if not value or len(value) < 8:
        return False
    for pattern in SECRET_VALUE_PATTERNS:
        if pattern.search(value):
            return True
    return False


def redact_value(key: str, value: str) -> str:
    """Redact a secret value, optionally keeping a tiny prefix or mask."""
    if not value:
        return ""
    if len(value) <= 6:
        return "***REDACTED***"
    # Show first 2 chars and last 2 chars for long keys if helpful, or clean mask
    return "***REDACTED***"


def process_environ(raw_env: Dict[str, str], redact: bool = True) -> Dict[str, Tuple[str, bool]]:
    """
    Process environment variables dictionary.
    Returns: {KEY: (value_string, is_secret_flag)}
    """
    processed: Dict[str, Tuple[str, bool]] = {}
    for k, v in raw_env.items():
        is_secret = is_secret_name(k) or is_secret_value(v)
        if is_secret and redact:
            display_val = redact_value(k, v)
        else:
            display_val = v
        processed[k] = (display_val, is_secret)
    return processed
