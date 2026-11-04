"""Security primitives for MFA, TLS, encrypted SQLite, backups and immutable audit."""
from __future__ import annotations
import base64, hashlib, hmac, os, secrets, sqlite3, ssl, struct, time
from pathlib import Path

def new_totp_secret():
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")

def totp_code(secret, at=None):
    key=base64.b32decode(secret.upper()+"="*((8-len(secret)%8)%8))
    counter=int((time.time() if at is None else at)//30)
    digest=hmac.new(key,struct.pack(">Q",counter),hashlib.sha1).digest()
    offset=digest[-1]&15
    return str((struct.unpack(">I",digest[offset:offset+4])[0]&0x7fffffff)%1000000).zfill(6)

def matching_totp_counter(secret, supplied, at=None, window=1):
    if not isinstance(supplied,str) or len(supplied)!=6 or not supplied.isdigit(): return None
    current=int((time.time() if at is None else at)//30)
    for delta in range(-window,window+1):
        counter=current+delta
        if counter>=0 and hmac.compare_digest(totp_code(secret,counter*30),supplied): return counter
    return None

def verify_totp(secret,supplied,at=None,window=1):
    return matching_totp_counter(secret,supplied,at,window) is not None

def totp_uri(secret,username,issuer="Sentinel Lab"):
    from urllib.parse import quote,urlencode
    return "otpauth://totp/"+quote(issuer+":"+username)+"?"+urlencode({"secret":secret,"issuer":issuer,"algorithm":"SHA1","digits":6,"period":30})

def secure_cookie_attributes():
    if os.getenv("SENTINEL_ENV","development")=="production" and os.getenv("SENTINEL_COOKIE_SECURE")!="1":
        raise RuntimeError("production requires Secure cookies")
    return "HttpOnly; Secure; SameSite=Strict; Path=/" if os.getenv("SENTINEL_COOKIE_SECURE")=="1" else "HttpOnly; SameSite=Strict; Path=/"

def tls_context():
    cert,key=os.getenv("SENTINEL_TLS_CERT"),os.getenv("SENTINEL_TLS_KEY")
    if not cert or not key:
        if os.getenv("SENTINEL_ENV","development")=="production": raise RuntimeError("production requires TLS certificate and key")
        return None
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version=ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(cert,key)
    return context

def encrypted_sqlite_connect(path,timeout=10,key=None):
    secret=key or os.getenv("SENTINEL_DB_KEY","")
    if len(secret)!=64 or any(ch not in "0123456789abcdefABCDEF" for ch in secret):
        raise RuntimeError("SENTINEL_DB_KEY must be a 256-bit hex key")
    try:
        from sqlcipher3 import dbapi2 as sqlcipher
    except ImportError as exc:
        raise RuntimeError("SQLCipher unavailable; refusing plaintext fallback") from exc
    db=sqlcipher.connect(path,timeout=timeout)
    db.execute('PRAGMA key = "x\'%s\'"'%secret)
    row=db.execute("PRAGMA cipher_version").fetchone()
    if not row or not row[0]:
        db.close()
        raise RuntimeError("SQLCipher encryption unavailable")
    db.row_factory=sqlcipher.Row
    db.execute("PRAGMA foreign_keys=ON")
    db.execute("PRAGMA journal_mode=WAL")
    return db

def database_connect(path,timeout=10):
    if os.getenv("SENTINEL_DB_ENCRYPTION")=="1":
        return encrypted_sqlite_connect(path,timeout)
    if os.getenv("SENTINEL_ENV")=="production":
        raise RuntimeError("production requires SENTINEL_DB_ENCRYPTION=1")
    db=sqlite3.connect(path,timeout=timeout)
    db.row_factory=sqlite3.Row
    return db

def migrate_sqlite_to_sqlcipher(source,destination,key):
    """Copy a quiesced plaintext SQLite DB into a new SQLCipher DB."""
    if Path(source).resolve()==Path(destination).resolve():
        raise ValueError("source and destination must differ")
    if Path(destination).exists(): raise FileExistsError(destination)
    src=sqlite3.connect(source)
    dst=encrypted_sqlite_connect(destination,key=key)
    try:
        dst.executescript("\n".join(src.iterdump()))
        result=dst.execute("PRAGMA integrity_check").fetchone()[0]
        if result!="ok": raise RuntimeError("encrypted migration integrity check failed")
    finally:
        dst.close()
        src.close()


def rekey_sqlcipher_database(path,old_key,new_key):
    """Atomically re-encrypt a SQLCipher database with a new independent key."""
    source=Path(path)
    if old_key==new_key: raise ValueError("new database key must differ from old key")
    temp=source.with_name(source.name+".rekey")
    if temp.exists(): raise FileExistsError(str(temp))
    src=encrypted_sqlite_connect(str(source),key=old_key)
    dst=encrypted_sqlite_connect(str(temp),key=new_key)
    os.chmod(temp,0o600)
    try:
        src.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        src.backup(dst)
        dst.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        if dst.execute("PRAGMA integrity_check").fetchone()[0]!="ok":
            raise RuntimeError("rekey verification failed")
    finally:
        dst.close()
        src.close()
    check=encrypted_sqlite_connect(str(temp),key=new_key)
    try:
        if check.execute("PRAGMA integrity_check").fetchone()[0]!="ok":
            raise RuntimeError("new database key verification failed")
    finally: check.close()
    for suffix in ("-wal","-shm"):
        sidecar=Path(str(temp)+suffix)
        if sidecar.exists(): sidecar.unlink()
        old_sidecar=Path(str(source)+suffix)
        if old_sidecar.exists(): old_sidecar.unlink()
    os.replace(temp,source)

def _configured_backup_key(explicit=None):
    if explicit is not None: return explicit
    value=os.getenv("SENTINEL_BACKUP_KEY","")
    if value:
        if len(value)!=64 or any(ch not in "0123456789abcdefABCDEF" for ch in value): raise RuntimeError("SENTINEL_BACKUP_KEY must be a 256-bit hex key")
        return bytes.fromhex(value)
    if os.getenv("SENTINEL_ENV")=="production": raise RuntimeError("production backups require SENTINEL_BACKUP_KEY")
    return None

def backup_sqlite(source,destination,encryption_key=None):
    """Consistent online backup; honors SQLCipher and production AES-GCM backup policy."""
    encryption_key=_configured_backup_key(encryption_key)
    src=database_connect(source)
    target=Path(destination)
    target.parent.mkdir(parents=True,exist_ok=True)
    tmp=target.with_suffix(target.suffix+".tmp")
    if tmp.exists(): raise FileExistsError(str(tmp))
    try:
        dst=database_connect(str(tmp))
        try: src.backup(dst)
        finally: dst.close()
    finally: src.close()
    os.chmod(tmp,0o600)
    raw=tmp.read_bytes()
    tmp.unlink()
    if encryption_key is not None:
        if len(encryption_key)!=32: raise ValueError("backup key must be exactly 32 bytes")
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        nonce=secrets.token_bytes(12)
        raw=b"SENTINEL-AESGCM-1"+nonce+AESGCM(encryption_key).encrypt(nonce,raw,b"sentinel-backup-v1")
    fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,"wb") as stream:
        stream.write(raw);stream.flush();os.fsync(stream.fileno())
    return hashlib.sha256(raw).hexdigest()

def restore_sqlite(backup,destination,encryption_key=None):
    encryption_key=_configured_backup_key(encryption_key)
    raw=Path(backup).read_bytes()
    marker=b"SENTINEL-AESGCM-1"
    if raw.startswith(marker):
        if encryption_key is None or len(encryption_key)!=32: raise ValueError("encrypted backup requires its 256-bit key")
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        nonce=raw[len(marker):len(marker)+12]
        try: raw=AESGCM(encryption_key).decrypt(nonce,raw[len(marker)+12:],b"sentinel-backup-v1")
        except Exception as exc:
            from cryptography.exceptions import InvalidTag
            if isinstance(exc,InvalidTag): raise ValueError("backup authentication failed: wrong key or corrupted ciphertext") from exc
            raise
    elif encryption_key is not None:
        raise ValueError("expected encrypted backup; refusing plaintext restore")
    target=Path(destination)
    target.parent.mkdir(parents=True,exist_ok=True)
    tmp=target.with_suffix(target.suffix+".restore-tmp")
    fd=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,"wb") as stream: stream.write(raw);stream.flush();os.fsync(stream.fileno())
    db=database_connect(str(tmp))
    try:
        if db.execute("PRAGMA integrity_check").fetchone()[0]!="ok": raise ValueError("backup integrity check failed")
    finally:
        db.close()
    os.chmod(tmp,0o600)
    os.replace(tmp,target)

class S3ObjectLockArchive:
    """Append-only S3 archive using Object Lock COMPLIANCE retention."""
    def __init__(self,bucket,retention_days=365,client=None):
        if retention_days<1: raise ValueError("retention_days must be positive")
        if client is None:
            import boto3
            client=boto3.client("s3")
        self.client,self.bucket,self.retention_days=client,bucket,retention_days
    def verify_bucket(self):
        if self.client.get_bucket_versioning(Bucket=self.bucket).get("Status")!="Enabled":
            raise RuntimeError("bucket versioning must be enabled")
        config=self.client.get_object_lock_configuration(Bucket=self.bucket).get("ObjectLockConfiguration",{})
        rule=config.get("ObjectLockRule",{})
        retention=rule.get("DefaultRetention",{})
        if config.get("ObjectLockEnabled")!="Enabled" or not rule:
            raise RuntimeError("S3 Object Lock must be enabled with a default retention rule")
        if retention.get("Mode") not in {"COMPLIANCE","GOVERNANCE"} or not (retention.get("Days") or retention.get("Years")):
            raise RuntimeError("S3 Object Lock default retention mode and duration are required")
    def archive(self,payload):
        import datetime
        digest=hashlib.sha256(payload).hexdigest()
        key="sentinel-audit/sha256/"+digest+".json"
        retain=datetime.datetime.now(datetime.timezone.utc)+datetime.timedelta(days=self.retention_days)
        self.client.put_object(Bucket=self.bucket,Key=key,Body=payload,ObjectLockMode="COMPLIANCE",
            ObjectLockRetainUntilDate=retain,Metadata={"sha256":digest})
        return key
