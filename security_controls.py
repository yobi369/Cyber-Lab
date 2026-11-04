"""Security primitives: TOTP MFA, TLS, encrypted backups and S3 Object Lock."""
from __future__ import annotations
import base64, hashlib, hmac, os, secrets, sqlite3, ssl, struct, time
from pathlib import Path
def new_totp_secret(): return base64.b32encode(secrets.token_bytes(20)).decode().rstrip('=')
def totp_code(secret, at=None):
 key=base64.b32decode(secret.upper()+'='*((8-len(secret)%8)%8)); counter=int((time.time() if at is None else at)//30)
 digest=hmac.new(key,struct.pack('>Q',counter),hashlib.sha1).digest(); off=digest[-1]&15
 return str((struct.unpack('>I',digest[off:off+4])[0]&0x7fffffff)%1000000).zfill(6)
def verify_totp(secret,supplied,at=None,window=1):
 if not isinstance(supplied,str) or len(supplied)!=6 or not supplied.isdigit(): return False
 now=int(time.time() if at is None else at)
 return any(hmac.compare_digest(totp_code(secret,now+d*30),supplied) for d in range(-window,window+1))
def totp_uri(secret,username,issuer='Sentinel Lab'):
 from urllib.parse import quote,urlencode
 return 'otpauth://totp/'+quote(issuer+':'+username)+'?'+urlencode({'secret':secret,'issuer':issuer,'algorithm':'SHA1','digits':6,'period':30})
def secure_cookie_attributes():
 if os.getenv('SENTINEL_ENV','development')=='production' and os.getenv('SENTINEL_COOKIE_SECURE')!='1': raise RuntimeError('production requires Secure cookies')
 return 'HttpOnly; Secure; SameSite=Strict; Path=/' if os.getenv('SENTINEL_COOKIE_SECURE')=='1' else 'HttpOnly; SameSite=Strict; Path=/'
def tls_context():
 cert,key=os.getenv('SENTINEL_TLS_CERT'),os.getenv('SENTINEL_TLS_KEY')
 if not cert or not key:
  if os.getenv('SENTINEL_ENV','development')=='production': raise RuntimeError('production requires TLS certificate and key')
  return None
 ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);ctx.minimum_version=ssl.TLSVersion.TLSv1_2;ctx.load_cert_chain(cert,key);return ctx
def encrypted_sqlite_connect(path,timeout=10):
 key=os.getenv('SENTINEL_DB_KEY','')
 if len(key)!=64: raise RuntimeError('SENTINEL_DB_KEY must be a 256-bit hex key')
 try: from sqlcipher3 import dbapi2 as sqlcipher
 except ImportError as exc: raise RuntimeError('SQLCipher unavailable; refusing plaintext fallback') from exc
 db=sqlcipher.connect(path,timeout=timeout);db.execute("PRAGMA key = '"+key+"'")
 row=db.execute('PRAGMA cipher_version').fetchone()
 if not row or not row[0]: db.close();raise RuntimeError('SQLCipher encryption unavailable')
 db.execute('PRAGMA foreign_keys=ON');db.execute('PRAGMA journal_mode=WAL');return db
def backup_sqlite(source,destination,encryption_key=None):
 src=sqlite3.connect(source);target=Path(destination);target.parent.mkdir(parents=True,exist_ok=True);tmp=target.with_suffix(target.suffix+'.tmp')
 try:
  dst=sqlite3.connect(str(tmp))
  try: src.backup(dst)
  finally: dst.close()
 finally: src.close()
 raw=tmp.read_bytes();tmp.unlink()
 if encryption_key is not None:
  if len(encryption_key)!=32: raise ValueError('backup key must be 32 bytes')
  from cryptography.hazmat.primitives.ciphers.aead import AESGCM
  nonce=secrets.token_bytes(12);raw=b'SENTINEL-AESGCM-1'+nonce+AESGCM(encryption_key).encrypt(nonce,raw,b'sentinel-backup-v1')
 fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
 with os.fdopen(fd,'wb') as f: f.write(raw);f.flush();os.fsync(f.fileno())
 return hashlib.sha256(raw).hexdigest()
def restore_sqlite(backup,destination,encryption_key=None):
 raw=Path(backup).read_bytes();marker=b'SENTINEL-AESGCM-1'
 if raw.startswith(marker):
  if encryption_key is None or len(encryption_key)!=32: raise ValueError('encrypted backup requires 32-byte key')
  from cryptography.hazmat.primitives.ciphers.aead import AESGCM
  nonce=raw[len(marker):len(marker)+12];raw=AESGCM(encryption_key).decrypt(nonce,raw[len(marker)+12:],b'sentinel-backup-v1')
 elif encryption_key is not None: raise ValueError('expected encrypted backup')
 target=Path(destination);target.parent.mkdir(parents=True,exist_ok=True);tmp=target.with_suffix(target.suffix+'.restore-tmp');tmp.write_bytes(raw)
 db=sqlite3.connect(str(tmp))
 try:
  if db.execute('PRAGMA integrity_check').fetchone()[0]!='ok': raise ValueError('backup integrity check failed')
 finally: db.close()
 os.chmod(tmp,0o600);os.replace(tmp,target)
class S3ObjectLockArchive:
 def __init__(self,bucket,retention_days=365,client=None):
  if retention_days<1: raise ValueError('retention must be positive')
  if client is None: import boto3;client=boto3.client('s3')
  self.client,self.bucket,self.retention_days=client,bucket,retention_days
 def verify_bucket(self):
  if self.client.get_bucket_versioning(Bucket=self.bucket).get('Status')!='Enabled': raise RuntimeError('bucket versioning must be enabled')
  rule=self.client.get_object_lock_configuration(Bucket=self.bucket).get('ObjectLockConfiguration',{}).get('ObjectLockRule',{})
  if not rule: raise RuntimeError('S3 Object Lock default retention must be configured')
 def archive(self,payload):
  import datetime
  digest=hashlib.sha256(payload).hexdigest();key='sentinel-audit/sha256/'+digest+'.json'
  until=datetime.datetime.now(datetime.timezone.utc)+datetime.timedelta(days=self.retention_days)
  self.client.put_object(Bucket=self.bucket,Key=key,Body=payload,ObjectLockMode='COMPLIANCE',ObjectLockRetainUntilDate=until,Metadata={'sha256':digest})
  return key
