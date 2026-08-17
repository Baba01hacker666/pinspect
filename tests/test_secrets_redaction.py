"""
Unit tests for secret detection and redaction in environment variables.
"""

import unittest

from pinspect.utils.secrets import (
    is_secret_name,
    is_secret_value,
    process_environ,
)


class TestSecretsRedaction(unittest.TestCase):
    def test_secret_name_detection(self):
        self.assertTrue(is_secret_name("AWS_SECRET_ACCESS_KEY"))
        self.assertTrue(is_secret_name("AWS_ACCESS_KEY_ID"))
        self.assertTrue(is_secret_name("DATABASE_URL"))
        self.assertTrue(is_secret_name("DB_PASSWORD"))
        self.assertTrue(is_secret_name("GITHUB_TOKEN"))
        self.assertTrue(is_secret_name("AUTH_TOKEN"))
        self.assertTrue(is_secret_name("API_KEY"))
        self.assertTrue(is_secret_name("SESSION_SECRET"))
        self.assertTrue(is_secret_name("MY_APP_PASSWD"))

        self.assertFalse(is_secret_name("PATH"))
        self.assertFalse(is_secret_name("HOME"))
        self.assertFalse(is_secret_name("USER"))
        self.assertFalse(is_secret_name("SHELL"))
        self.assertFalse(is_secret_name("TERM"))

    def test_secret_value_detection(self):
        # AWS Key pattern
        self.assertTrue(is_secret_value("AKIAIOSFODNN7EXAMPLE"))
        # GitHub Token pattern
        self.assertTrue(is_secret_value("ghp_1234567890abcdefghijklmnopqrstuvwxyz"))
        # JWT pattern
        self.assertTrue(is_secret_value("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.doNotLeakThis"))

        # Normal strings
        self.assertFalse(is_secret_value("/usr/bin/bash"))
        self.assertFalse(is_secret_value("xterm-256color"))
        self.assertFalse(is_secret_value("localhost:8080"))

    def test_process_environ_redaction(self):
        raw_env = {
            "USER": "alice",
            "HOME": "/home/alice",
            "DATABASE_URL": "postgres://user:supersecret@localhost:5432/mydb",
            "AWS_SECRET_ACCESS_KEY": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "REGULAR_VAR": "hello world",
        }

        redacted = process_environ(raw_env, redact=True)
        self.assertEqual(redacted["USER"][0], "alice")
        self.assertFalse(redacted["USER"][1])

        self.assertEqual(redacted["DATABASE_URL"][0], "***REDACTED***")
        self.assertTrue(redacted["DATABASE_URL"][1])

        self.assertEqual(redacted["AWS_SECRET_ACCESS_KEY"][0], "***REDACTED***")
        self.assertTrue(redacted["AWS_SECRET_ACCESS_KEY"][1])

        # Test unredacted option
        unredacted = process_environ(raw_env, redact=False)
        self.assertEqual(unredacted["DATABASE_URL"][0], "postgres://user:supersecret@localhost:5432/mydb")
        self.assertTrue(unredacted["DATABASE_URL"][1])


if __name__ == "__main__":
    unittest.main()
