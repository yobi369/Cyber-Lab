import tempfile,unittest
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
 def test_roles_are_provisioned_not_user_selected(self):
  self.store.create_user("reviewer","long-reviewer-password","reviewer")
  self.assertEqual(self.store.list_users()[0]["role"],"reviewer")
  with self.assertRaises(ValueError):self.store.create_user("bad","long-enough-password","admin")

if __name__=="__main__":unittest.main()
