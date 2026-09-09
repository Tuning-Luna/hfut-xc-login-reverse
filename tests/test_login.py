import base64
import io
import os
import runpy
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import requests


# Keep real credentials and network access out of regression tests.
with patch("dotenv.load_dotenv"), patch.dict(
    os.environ,
    {"student_id": "test-student", "password": "test-password"},
    clear=True,
):
    from hfut import config
    from hfut.client import Reverse
    from main import UserCLI


class LoginTestCase(unittest.TestCase):
    def setUp(self):
        self.enterContext(
            patch.multiple(
                config, STUDENT_ID="test-student", PASSWORD="test-password"
            )
        )
        session = requests.Session()
        self.addCleanup(session.close)
        self.enterContext(patch.object(Reverse, "session", session))
        self.request = self.enterContext(
            patch.object(
                requests.Session,
                "request",
                side_effect=AssertionError("Unexpected network access"),
            )
        )


class ConfigTests(LoginTestCase):
    def test_loads_env_from_project_root(self):
        with patch("dotenv.load_dotenv") as load_dotenv, patch.dict(
            os.environ,
            {"student_id": "env-student", "password": "env-password"},
            clear=True,
        ):
            loaded = runpy.run_path(config.__file__)

        load_dotenv.assert_called_once_with(
            Path(config.__file__).resolve().parent.parent / ".env"
        )
        self.assertEqual(loaded["STUDENT_ID"], "env-student")
        self.assertEqual(loaded["PASSWORD"], "env-password")

    def test_missing_credentials_name_the_missing_field(self):
        for field, name in (("STUDENT_ID", "student_id"), ("PASSWORD", "password")):
            for value in (None, ""):
                with self.subTest(field=field, value=value), patch.object(
                    config, field, value
                ):
                    with self.assertRaisesRegex(ValueError, name) as error:
                        config.validate_credentials()
                    self.assertIn(".env", str(error.exception))
                    self.assertNotIn("test-student", str(error.exception))
                    self.assertNotIn("test-password", str(error.exception))

    def test_reports_both_missing_fields(self):
        with patch.multiple(config, STUDENT_ID=None, PASSWORD=None):
            with self.assertRaises(ValueError) as error:
                config.validate_credentials()
        self.assertIn("student_id", str(error.exception))
        self.assertIn("password", str(error.exception))

    def test_valid_credentials_are_not_modified(self):
        with patch.object(config, "PASSWORD", " test-password "):
            config.validate_credentials()
            self.assertEqual(config.PASSWORD, " test-password ")


class EncryptionTests(LoginTestCase):
    def setUp(self):
        super().setUp()
        Reverse.session.cookies.set("LOGIN_FLAVORING", "0123456789abcdef")

    def test_missing_password_has_actionable_error(self):
        with patch.object(config, "PASSWORD", None):
            with self.assertRaisesRegex(ValueError, "password"):
                Reverse.encryption_pwd()

    def test_missing_login_key_has_actionable_error(self):
        Reverse.session.cookies.clear()
        with self.assertRaisesRegex(ValueError, "LOGIN_FLAVORING"):
            Reverse.encryption_pwd()

    def test_null_or_empty_login_key_has_actionable_error(self):
        for value in (None, ""):
            with self.subTest(value=value):
                Reverse.session.cookies.set_cookie(
                    requests.cookies.create_cookie("LOGIN_FLAVORING", value)
                )
                with self.assertRaisesRegex(ValueError, "LOGIN_FLAVORING"):
                    Reverse.encryption_pwd()

    def test_invalid_key_length_is_rejected(self):
        Reverse.session.cookies.set("LOGIN_FLAVORING", "short")
        with self.assertRaises(ValueError):
            Reverse.encryption_pwd()

    def test_valid_encryption_preserves_password_bytes(self):
        for key in ("k" * 16, "k" * 24, "k" * 32):
            with self.subTest(key_length=len(key)), patch.object(
                config, "PASSWORD", " test-password-with-spaces"
            ):
                Reverse.session.cookies.set("LOGIN_FLAVORING", key)
                encrypted = Reverse.encryption_pwd()
                decrypted = AES.new(key.encode("utf-8"), AES.MODE_ECB).decrypt(
                    base64.b64decode(encrypted)
                )
                self.assertEqual(
                    unpad(decrypted, AES.block_size), config.PASSWORD.encode("utf-8")
                )
                self.assertEqual(config.PASSWORD, " test-password-with-spaces")


class CLITests(LoginTestCase):
    def test_missing_credentials_stop_before_captcha_or_login_requests(self):
        for field in ("STUDENT_ID", "PASSWORD"):
            with (
                self.subTest(field=field),
                patch.object(config, field, None),
                patch.object(Reverse, "load_session", return_value=False),
                patch.object(Reverse, "preLogin") as pre_login,
                patch("builtins.input") as prompt,
            ):
                with self.assertRaises(ValueError):
                    UserCLI.init()
                pre_login.assert_not_called()
                prompt.assert_not_called()
                self.request.assert_not_called()

    def test_valid_cached_session_does_not_require_credentials(self):
        with patch.multiple(config, STUDENT_ID=None, PASSWORD=None), patch.object(
            Reverse, "load_session", return_value=True
        ), patch.object(Reverse, "preLogin") as pre_login:
            self.assertTrue(UserCLI.init())
        pre_login.assert_not_called()
        self.request.assert_not_called()

    def test_cli_reports_missing_configuration_without_attribute_error(self):
        output = io.StringIO()
        with patch.object(config, "PASSWORD", None), patch.object(
            Reverse, "load_session", return_value=False
        ), patch.object(Reverse, "preLogin") as pre_login, redirect_stdout(output):
            UserCLI.login_cli()
        self.assertIn("password", output.getvalue())
        self.assertIn(".env", output.getvalue())
        self.assertNotIn("NoneType", output.getvalue())
        self.assertNotIn("test-student", output.getvalue())
        pre_login.assert_not_called()
        self.request.assert_not_called()


if __name__ == "__main__":
    unittest.main()
