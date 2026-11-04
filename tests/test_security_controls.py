import os,sqlite3,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
from security_controls import new_totp_secret,totp_code,verify_totp,secure_cookie_attributes,tls_context,backup_sqlite,restore_sqlite,encrypted_sqlite_connect,migrate_sqlite_to_sqlcipher,database_connect
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

 def test_sqlcipher_migration_active_store_and_encrypted_backup_restore(self):
  try: import sqlcipher3
  except ImportError: self.skipTest('SQLCipher test dependency unavailable')
  with tempfile.TemporaryDirectory() as d:
   plain=Path(d)/'plain.db';db=sqlite3.connect(plain);db.execute('CREATE TABLE sample(value TEXT)');db.execute("INSERT INTO sample VALUES('classified')");db.commit();db.close()
   key='12'*32;encrypted=Path(d)/'encrypted.db';migrate_sqlite_to_sqlcipher(str(plain),str(encrypted),key)
   self.assertNotEqual(encrypted.read_bytes()[:16],b'SQLite format 3\\x00')
   with patch.dict(os.environ,{'SENTINEL_DB_ENCRYPTION':'1','SENTINEL_DB_KEY':key}):
    db=database_connect(str(encrypted));self.assertEqual(db.execute('SELECT value FROM sample').fetchone()[0],'classified');db.close()
    from identity import IdentityStore
    from storage import TrainingStore
    IdentityStore(str(encrypted));TrainingStore(str(encrypted))
    backup=Path(d)/'encrypted-backup.bin';backup_sqlite(str(encrypted),str(backup),b'b'*32)
    restored=Path(d)/'restored-encrypted.db';restore_sqlite(str(backup),str(restored),b'b'*32)
    db=database_connect(str(restored));self.assertEqual(db.execute('SELECT value FROM sample').fetchone()[0],'classified');db.close()
   raw=sqlite3.connect(encrypted)
   with self.assertRaises(sqlite3.DatabaseError):raw.execute('SELECT * FROM sample')
   raw.close()
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
