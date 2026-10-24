"""Unit tests verifying CLI help, doctor diagnostics, and backward-compatibility aliases."""

import os
import subprocess
import sys
import unittest

from vshield.cli import create_parser, handle_doctor
from vshield.config import get_data_dir, get_ssh_password_env


class TestCompatibilityAndCli(unittest.TestCase):

    def test_vshield_parser_help_and_subcommands(self):
        parser = create_parser()
        self.assertEqual(parser.prog, "vshield")
        self.assertIn("vShield", parser.description)

        # Check required subcommands
        subcommand_choices = parser._subparsers._actions[1].choices
        self.assertIn("doctor", subcommand_choices)
        self.assertIn("scan", subcommand_choices)
        self.assertIn("targets", subcommand_choices)
        self.assertIn("schedule", subcommand_choices)
        self.assertIn("findings", subcommand_choices)
        self.assertIn("remediate", subcommand_choices)
        self.assertIn("patch", subcommand_choices)

    def test_vshield_doctor_runs_cleanly(self):
        parser = create_parser()
        args = parser.parse_args(["doctor"])
        exit_code = handle_doctor(args)
        self.assertEqual(exit_code, 0)

    def test_env_var_resolution_vshield_primary(self):
        os.environ["VSHIELD_DATA_DIR"] = "/tmp/test_vshield_data"
        if "VULNSHIELD_DATA_DIR" in os.environ:
            del os.environ["VULNSHIELD_DATA_DIR"]

        resolved = get_data_dir()
        self.assertEqual(resolved, "/tmp/test_vshield_data")
        del os.environ["VSHIELD_DATA_DIR"]

    def test_env_var_resolution_legacy_fallback(self):
        if "VSHIELD_DATA_DIR" in os.environ:
            del os.environ["VSHIELD_DATA_DIR"]
        os.environ["VULNSHIELD_DATA_DIR"] = "/tmp/test_legacy_data"

        with self.assertWarns(DeprecationWarning):
            resolved = get_data_dir()
            self.assertEqual(resolved, "/tmp/test_legacy_data")

        del os.environ["VULNSHIELD_DATA_DIR"]

    def test_ssh_password_env_var_resolution(self):
        os.environ["VSHIELD_SSH_PASSWORD"] = "secret1"
        self.assertEqual(get_ssh_password_env(), "VSHIELD_SSH_PASSWORD")
        del os.environ["VSHIELD_SSH_PASSWORD"]

        os.environ["VULNSHIELD_SSH_PASSWORD"] = "secret2"
        with self.assertWarns(DeprecationWarning):
            self.assertEqual(get_ssh_password_env(), "VULNSHIELD_SSH_PASSWORD")
        del os.environ["VULNSHIELD_SSH_PASSWORD"]


if __name__ == "__main__":
    unittest.main()
