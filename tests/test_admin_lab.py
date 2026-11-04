import unittest

from admin_lab import AdminLab


class AdminLabTests(unittest.TestCase):
    def setUp(self):
        self.lab = AdminLab(expected_token="training-only-token")

    def test_requires_authentication(self):
        self.assertIn("Access denied", self.lab.execute("status"))

    def test_authentication_success_and_failure(self):
        self.assertFalse(self.lab.authenticate("wrong"))
        self.assertTrue(self.lab.authenticate("training-only-token"))

    def test_allowlisted_commands_are_simulated(self):
        self.lab.authenticate("training-only-token")
        self.assertIn("simulation only", self.lab.execute("status"))
        self.assertIn("demo-host-01", self.lab.execute("inventory"))
        self.assertIn("Commands:", self.lab.execute("help"))

    def test_unknown_and_shell_commands_are_rejected(self):
        self.lab.authenticate("training-only-token")
        self.assertIn("not in the training allowlist", self.lab.execute("whoami"))
        self.assertIn("not in the training allowlist", self.lab.execute("ls; id"))

    def test_audit_records_denials_and_successes(self):
        self.lab.execute("status")
        self.lab.authenticate("training-only-token")
        self.lab.execute("status")
        self.assertEqual(self.lab.audit_log[0].outcome, "denied:not-authenticated")
        self.assertEqual(self.lab.audit_log[-1].outcome, "success")


if __name__ == "__main__":
    unittest.main()
