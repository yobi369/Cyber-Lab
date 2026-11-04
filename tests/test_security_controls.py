import os,sqlite3,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
from security_controls import new_totp_secret,totp_code,verify_totp,secure_cookie_attributes,tls_context,backup_sqlite,restore_sqlite,encrypted_sqlite_connect
class SecurityControlTests(unittest.TestCase):
 def test_totp_rfc6238_and_validation(self):
  secret='GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'
  self.assertEqual(totp_code(secret,59),'287082')
  self.assertTrue(verify_totp(secret,'287082',59,0))
  self.assertFalse(verify_totp(secret,'000000',59,0))
  self.assertEqual(len(new_totp_secret()),32)
 def test_production_fails_closed_without_tls_and_secure_cookie(self):
  with patch.dict(os.environ,{'SENTINEL_ENV':'production'},clear=True):
   with self.assertRaises(RuntimeError): secure_cookie_attributes()
   with self.assertRaises(RuntimeError): tls_context()
  with patch.dict(os.environ,{'SENTINEL_COOKIE_SECURE':'1'}): self.assertIn('Secure',secure_cookie_attributes())
 def test_sqlcipher_never_falls_back_to_plaintext(self):
  with patch.dict(os.environ,{},clear=True):
   with self.assertRaises(RuntimeError): encrypted_sqlite_connect(':memory:')
 def test_consistent_backup_restore_and_aes_gcm(self):
  with tempfile.TemporaryDirectory() as d:
   src=Path(d)/'source.db';db=sqlite3.connect(src);db.execute('CREATE TABLE t(v TEXT)');db.execute("INSERT INTO t VALUES('durable')");db.commit();db.close()
   backup=Path(d)/'backup.db';backup_sqlite(str(src),str(backup));restored=Path(d)/'restored.db';restore_sqlite(str(backup),str(restored))
   db=sqlite3.connect(restored);self.assertEqual(db.execute('SELECT v FROM t').fetchone()[0],'durable');db.close()
   key=b'k'*32;enc=Path(d)/'backup.enc';backup_sqlite(str(src),str(enc),key);self.assertNotIn(b'durable',enc.read_bytes())
   out=Path(d)/'encrypted.db';restore_sqlite(str(enc),str(out),key)
   db=sqlite3.connect(out);self.assertEqual(db.execute('SELECT v FROM t').fetchone()[0],'durable');db.close()
   with self.assertRaises(ValueError): restore_sqlite(str(enc),str(Path(d)/'bad.db'),b'x'*32)
if __name__=='__main__': unittest.main()
