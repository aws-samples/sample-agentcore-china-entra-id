"""Check local secret handling without creating credentials or cloud resources."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import identity_user_setup as setup


class IdentityUserSetupTests(unittest.TestCase):
    def test_secret_is_private_and_not_returned(self):
        example = "test-fixture-value-not-an-entra-credential"
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / ".state/secret.txt"
            with patch.object(setup, "SECRET_FILE", target), \
                 patch.object(setup.sys.stdin, "isatty", return_value=True), \
                 patch.object(setup.getpass, "getpass", side_effect=[example, example]):
                result = setup.stage_secret()
            self.assertEqual(target.read_text().strip(), example)
            self.assertEqual(target.stat().st_mode & 0o777, 0o600)
            self.assertNotIn(example, json.dumps(result))

    def test_existing_secret_is_preserved_without_prompt(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "secret.txt"
            target.write_text("existing-fixture")
            with patch.object(setup, "SECRET_FILE", target), patch.object(setup.getpass, "getpass") as prompt:
                with self.assertRaises(RuntimeError):
                    setup.stage_secret()
            prompt.assert_not_called()
            self.assertEqual(target.read_text(), "existing-fixture")

    def test_redirected_input_is_not_read(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "secret.txt"
            with patch.object(setup, "SECRET_FILE", target), \
                 patch.object(setup.sys.stdin, "isatty", return_value=False), \
                 patch.object(setup.getpass, "getpass") as prompt:
                with self.assertRaises(RuntimeError):
                    setup.stage_secret()
            prompt.assert_not_called()
            self.assertFalse(target.exists())

    def test_mismatched_confirmation_does_not_write_file(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "secret.txt"
            with patch.object(setup, "SECRET_FILE", target), \
                 patch.object(setup.sys.stdin, "isatty", return_value=True), \
                 patch.object(setup.getpass, "getpass", side_effect=["first-test-value", "second-test-value"]):
                with self.assertRaises(RuntimeError):
                    setup.stage_secret()
            self.assertFalse(target.exists())


if __name__ == "__main__":
    unittest.main()
