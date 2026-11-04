import os,sqlite3,tempfile,unittest,datetime,ssl
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from unittest.mock import patch
from security_controls import new_totp_secret,totp_code,verify_totp,secure_cookie_attributes,tls_context,backup_sqlite,restore_sqlite,encrypted_sqlite_connect,migrate_sqlite_to_sqlcipher,database_connect,rekey_sqlcipher_database
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
 def test_tls_context_loads_real_certificate_and_enforces_tls12_minimum(self):
  with tempfile.TemporaryDirectory() as d:
   key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
   name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,"localhost")])
   cert=(x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
    .serial_number(x509.random_serial_number()).not_valid_before(datetime.datetime.now(datetime.timezone.utc)-datetime.timedelta(minutes=1))
    .not_valid_after(datetime.datetime.now(datetime.timezone.utc)+datetime.timedelta(days=1))
    .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]),critical=False)
    .sign(key,hashes.SHA256()))
   cert_path=Path(d)/"tls.crt";key_path=Path(d)/"tls.key"
   cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
   key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.TraditionalOpenSSL,serialization.NoEncryption()))
   with patch.dict(os.environ,{"SENTINEL_TLS_CERT":str(cert_path),"SENTINEL_TLS_KEY":str(key_path)}):
    context=tls_context()
   self.assertEqual(context.minimum_version,ssl.TLSVersion.TLSv1_2)
 def test_production_database_refuses_plaintext_mode(self):
  with patch.dict(os.environ,{"SENTINEL_ENV":"production"},clear=True):
   with self.assertRaises(RuntimeError):database_connect(":memory:")
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
    rekey_sqlcipher_database(str(encrypted),key,'34'*32)
    with self.assertRaises(Exception): encrypted_sqlite_connect(str(encrypted),key=key)
    db=encrypted_sqlite_connect(str(encrypted),key='34'*32);self.assertEqual(db.execute('SELECT value FROM sample').fetchone()[0],'classified');db.close()
    os.environ['SENTINEL_DB_KEY']='34'*32
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
