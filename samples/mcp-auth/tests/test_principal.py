# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Trust must bind to a persistent principal in the same China account."""
import unittest
from unittest.mock import Mock

import lab


class PrincipalTests(unittest.TestCase):
    def test_user_is_preserved_without_iam_lookup(self):
        session = Mock()
        arn = "arn:aws-cn:iam::123456789012:user/deployer"
        self.assertEqual(lab.caller_principal(session, arn), arn)
        session.client.assert_not_called()

    def test_assumed_role_resolves_real_iam_path(self):
        session = Mock()
        session.client.return_value.get_role.return_value = {
            "Role": {"Arn": "arn:aws-cn:iam::123456789012:role/deployment/ChinaDeployer"}
        }
        principal = lab.caller_principal(
            session, "arn:aws-cn:sts::123456789012:assumed-role/ChinaDeployer/session-123"
        )
        self.assertEqual(principal, "arn:aws-cn:iam::123456789012:role/deployment/ChinaDeployer")
        self.assertNotIn("session-123", principal)

    def test_cross_account_lookup_is_rejected(self):
        session = Mock()
        session.client.return_value.get_role.return_value = {
            "Role": {"Arn": "arn:aws-cn:iam::999999999999:role/ChinaDeployer"}
        }
        with self.assertRaises(RuntimeError):
            lab.caller_principal(session, "arn:aws-cn:sts::123456789012:assumed-role/ChinaDeployer/session")

    def test_unmapped_federated_principal_is_rejected(self):
        with self.assertRaises(RuntimeError):
            lab.caller_principal(Mock(), "arn:aws-cn:sts::123456789012:federated-user/unknown")


if __name__ == "__main__":
    unittest.main()
