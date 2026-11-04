import tempfile,unittest,os
from unittest.mock import patch
from security_controls import new_totp_secret,totp_code
from pathlib import Path
from identity import IdentityStore

class IdentityTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.store=IdentityStore(Path(self.tmp.name)/"auth.sqlite3")
 def tearDown(self):self.tmp.cleanup()
 def test_provision_login_session_and_csrf(self):
  self.store.create_user("alice","correct horse battery staple","instructor")
  login=self.store.authenticate("alice","correct horse battery staple")
  self.assertEqual(login["role"],"instructor")
  session=self.store.session(login["token"])
  self.assertEqual(session["username"],"alice")
  self.assertTrue(self.store.verify_csrf(session,login["csrf"]))
  self.assertFalse(self.store.verify_csrf(session,"wrong"))
  self.store.logout(login["token"]);self.assertIsNone(self.store.session(login["token"]))
 def test_invalid_credentials_and_password_policy(self):
  with self.assertRaises(ValueError):self.store.create_user("bob","short","learner")
  self.store.create_user("bob","a-long-enough-password","learner")
  self.assertIsNone(self.store.authenticate("bob","wrong-password"))
  self.assertIsNone(self.store.authenticate("unknown","wrong-password"))
 def test_persistent_login_throttle(self):
  for _ in range(8):self.store.record_login_failure("127.0.0.1")
  self.assertTrue(self.store.login_locked("127.0.0.1"))
  self.store.clear_login_failures("127.0.0.1")
  self.assertFalse(self.store.login_locked("127.0.0.1"))
 def test_enrolled_mfa_is_required_and_validated(self):
  self.store.create_user("mfauser","long-enough-password","learner")
  secret=new_totp_secret()
  with patch.dict(os.environ,{"SENTINEL_MFA_ENCRYPTION_KEY":"ab"*32}):
   self.store.set_totp_secret("mfauser",secret)
   self.assertIsNone(self.store.authenticate("mfauser","long-enough-password"))
   self.assertIsNone(self.store.authenticate("mfauser","long-enough-password","000000"))
   with patch("identity.matching_totp_counter",return_value=123456):
    login=self.store.authenticate("mfauser","long-enough-password","123456")
    self.assertIsNotNone(login)
    self.assertIsNone(self.store.authenticate("mfauser","long-enough-password","123456"))
 def test_require_mfa_blocks_accounts_without_enrollment(self):
  self.store.create_user("nomfa","long-enough-password","learner")
  with patch.dict(os.environ,{"SENTINEL_REQUIRE_MFA":"1"}):
   self.assertIsNone(self.store.authenticate("nomfa","long-enough-password"))
 def test_oidc_state_is_single_use_and_subject_must_be_prelinked(self):
  self.store.create_user("sso-user","long-enough-password","instructor")
  self.store.create_oidc_transaction("opaque-state","nonce-value","pkce-verifier")
  transaction=self.store.consume_oidc_transaction("opaque-state")
  self.assertEqual(transaction,{"nonce":"nonce-value","code_verifier":"pkce-verifier"})
  self.assertIsNone(self.store.consume_oidc_transaction("opaque-state"))
  self.assertIsNone(self.store.create_oidc_session("https://idp.example","immutable-subject"))
  self.store.link_oidc_identity("sso-user","https://idp.example","immutable-subject")
  session=self.store.create_oidc_session("https://idp.example","immutable-subject")
  self.assertEqual(session["username"],"sso-user")
  self.assertEqual(session["role"],"instructor")
 def test_roles_are_provisioned_not_user_selected(self):
  self.store.create_user("reviewer","long-reviewer-password","reviewer")
  self.assertEqual(self.store.list_users()[0]["role"],"reviewer")
  with self.assertRaises(ValueError):self.store.create_user("bad","long-enough-password","admin")

if __name__=="__main__":unittest.main()
