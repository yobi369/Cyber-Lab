"""SQLite-backed identities and opaque server-side sessions.

Accounts are provisioned out of band with manage_users.py. The browser never
chooses a role. Passwords use PBKDF2-HMAC-SHA256 with per-user salts.
"""
from __future__ import annotations
import hashlib, hmac, secrets, sqlite3, time, os
from security_controls import matching_totp_counter, database_connect
from pathlib import Path

ITERATIONS=310_000
SESSION_TTL=8*60*60

class IdentityStore:
 def __init__(self,path="sentinel-lab.sqlite3"):
  self.path=str(path)
  with self.connect() as db:
   db.executescript("""
   CREATE TABLE IF NOT EXISTS users(
    username TEXT PRIMARY KEY, password_hash BLOB NOT NULL, salt BLOB NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('learner','instructor','reviewer','auditor')),
    active INTEGER NOT NULL DEFAULT 1, created_at INTEGER NOT NULL, mfa_secret BLOB, mfa_last_counter INTEGER);
   CREATE TABLE IF NOT EXISTS sessions(
    token_hash TEXT PRIMARY KEY, username TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE,
    csrf_hash TEXT NOT NULL, csrf_token TEXT NOT NULL, expires_at INTEGER NOT NULL, created_at INTEGER NOT NULL);
   CREATE INDEX IF NOT EXISTS sessions_expiry ON sessions(expires_at);
   CREATE TABLE IF NOT EXISTS login_attempts(ip_hash TEXT PRIMARY KEY, window_start INTEGER NOT NULL, failures INTEGER NOT NULL);
   CREATE TABLE IF NOT EXISTS oidc_transactions(state_hash TEXT PRIMARY KEY, nonce TEXT NOT NULL, code_verifier TEXT NOT NULL, expires_at INTEGER NOT NULL);
   CREATE TABLE IF NOT EXISTS oidc_subjects(issuer TEXT NOT NULL, subject TEXT NOT NULL, username TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE, created_at INTEGER NOT NULL, PRIMARY KEY(issuer,subject));
   """)
   columns={row[1] for row in db.execute("PRAGMA table_info(users)")}
   if "mfa_secret" not in columns: db.execute("ALTER TABLE users ADD COLUMN mfa_secret BLOB")
   if "mfa_last_counter" not in columns: db.execute("ALTER TABLE users ADD COLUMN mfa_last_counter INTEGER")
 def connect(self):
  db=database_connect(self.path,timeout=10)
  db.execute("PRAGMA foreign_keys=ON")
  db.execute("PRAGMA journal_mode=WAL")
  return db
 @staticmethod
 def _derive(password,salt):
  return hashlib.pbkdf2_hmac("sha256",password.encode(),salt,ITERATIONS)
 def create_user(self,username,password,role):
  if not username or len(username)>80 or not username.replace("_","").replace("-","").isalnum(): raise ValueError("username must be 1–80 letters, digits, _ or -")
  if len(password)<12 or len(password)>256: raise ValueError("password must be 12–256 characters")
  if role not in {"learner","instructor","reviewer","auditor"}: raise ValueError("invalid role")
  salt=secrets.token_bytes(16); digest=self._derive(password,salt)
  with self.connect() as db:
   db.execute("INSERT INTO users(username,password_hash,salt,role,created_at) VALUES(?,?,?,?,?)",(username,digest,salt,role,int(time.time())))
  return {"username":username,"role":role}
 def set_totp_secret(self,username,secret):
  key=os.getenv("SENTINEL_MFA_ENCRYPTION_KEY","")
  if len(key)!=64 or any(ch not in "0123456789abcdefABCDEF" for ch in key): raise RuntimeError("SENTINEL_MFA_ENCRYPTION_KEY must be a 256-bit hex key")
  from cryptography.hazmat.primitives.ciphers.aead import AESGCM
  nonce=secrets.token_bytes(12);encrypted=nonce+AESGCM(bytes.fromhex(key)).encrypt(nonce,secret.encode(),username.encode())
  with self.connect() as db:
   cur=db.execute("UPDATE users SET mfa_secret=?,mfa_last_counter=NULL WHERE username=? AND active=1",(encrypted,username))
   if cur.rowcount!=1: raise ValueError("active user not found")
 def rotate_mfa_encryption_key(self,old_key,new_key):
  for key in (old_key,new_key):
   if len(key)!=64 or any(ch not in "0123456789abcdefABCDEF" for ch in key): raise ValueError("MFA keys must be 256-bit hex values")
  if old_key==new_key: raise ValueError("new MFA key must differ from old key")
  from cryptography.hazmat.primitives.ciphers.aead import AESGCM
  old_cipher,new_cipher=AESGCM(bytes.fromhex(old_key)),AESGCM(bytes.fromhex(new_key));changed=0
  with self.connect() as db:
   rows=db.execute("SELECT username,mfa_secret FROM users WHERE mfa_secret IS NOT NULL").fetchall()
   replacements=[]
   for row in rows:
    encrypted=row["mfa_secret"];secret=old_cipher.decrypt(encrypted[:12],encrypted[12:],row["username"].encode())
    nonce=secrets.token_bytes(12);replacement=nonce+new_cipher.encrypt(nonce,secret,row["username"].encode())
    replacements.append((replacement,row["username"]))
   for replacement,username in replacements: db.execute("UPDATE users SET mfa_secret=? WHERE username=?",(replacement,username));changed+=1
  return changed
 def authenticate(self,username,password,otp=None):
  with self.connect() as db: row=db.execute("SELECT * FROM users WHERE username=? AND active=1",(username,)).fetchone()
  if row is None:
   self._derive(password or "x",b"\0"*16)
   return None
  candidate=self._derive(password,row["salt"])
  if not hmac.compare_digest(candidate,row["password_hash"]): return None
  matched_counter=None
  if not row["mfa_secret"]:
   if os.getenv("SENTINEL_REQUIRE_MFA")=="1": return None
  else:
   key=os.getenv("SENTINEL_MFA_ENCRYPTION_KEY","")
   if len(key)!=64 or not otp: return None
   from cryptography.hazmat.primitives.ciphers.aead import AESGCM
   if any(ch not in "0123456789abcdefABCDEF" for ch in key): return None
   encrypted=row["mfa_secret"]
   try: secret=AESGCM(bytes.fromhex(key)).decrypt(encrypted[:12],encrypted[12:],username.encode()).decode()
   except Exception: return None
   matched_counter=matching_totp_counter(secret,str(otp))
   if matched_counter is None: return None
  token=secrets.token_urlsafe(32);csrf=secrets.token_urlsafe(32);now=int(time.time())
  with self.connect() as db:
   if matched_counter is not None:
    cur=db.execute("UPDATE users SET mfa_last_counter=? WHERE username=? AND (mfa_last_counter IS NULL OR mfa_last_counter<?)",(matched_counter,username,matched_counter))
    if cur.rowcount!=1: return None
   db.execute("DELETE FROM sessions WHERE expires_at<?",(now,))
   db.execute("INSERT INTO sessions VALUES(?,?,?,?,?,?)",(hashlib.sha256(token.encode()).hexdigest(),username,hashlib.sha256(csrf.encode()).hexdigest(),csrf,now+SESSION_TTL,now))
  return {"token":token,"csrf":csrf,"username":username,"role":row["role"],"expires_at":now+SESSION_TTL}
 def session(self,token):
  if not token:return None
  key=hashlib.sha256(token.encode()).hexdigest()
  with self.connect() as db:
   row=db.execute("SELECT s.*,u.role,u.active FROM sessions s JOIN users u USING(username) WHERE token_hash=?",(key,)).fetchone()
  if not row or not row["active"] or row["expires_at"]<int(time.time()): return None
  return {"username":row["username"],"role":row["role"],"csrf_hash":row["csrf_hash"],"csrf":row["csrf_token"]}
 def verify_csrf(self,session,value):
  return bool(session and value and hmac.compare_digest(session["csrf_hash"],hashlib.sha256(value.encode()).hexdigest()))
 def logout(self,token):
  if token:
   with self.connect() as db:db.execute("DELETE FROM sessions WHERE token_hash=?",(hashlib.sha256(token.encode()).hexdigest(),))
 def login_locked(self,remote,limit=8,window=300):
  key=hashlib.sha256(remote.encode()).hexdigest();now=int(time.time())
  with self.connect() as db:row=db.execute("SELECT * FROM login_attempts WHERE ip_hash=?",(key,)).fetchone()
  return bool(row and now-row["window_start"]<window and row["failures"]>=limit)
 def record_login_failure(self,remote,window=300):
  key=hashlib.sha256(remote.encode()).hexdigest();now=int(time.time())
  with self.connect() as db:
   row=db.execute("SELECT * FROM login_attempts WHERE ip_hash=?",(key,)).fetchone()
   if not row or now-row["window_start"]>=window:db.execute("INSERT OR REPLACE INTO login_attempts VALUES(?,?,1)",(key,now))
   else:db.execute("UPDATE login_attempts SET failures=failures+1 WHERE ip_hash=?",(key,))
 def clear_login_failures(self,remote):
  key=hashlib.sha256(remote.encode()).hexdigest()
  with self.connect() as db:db.execute("DELETE FROM login_attempts WHERE ip_hash=?",(key,))
 def create_oidc_transaction(self,state,nonce,verifier,ttl=300):
  now=int(time.time())
  with self.connect() as db:
   db.execute("DELETE FROM oidc_transactions WHERE expires_at<?",(now,))
   db.execute("INSERT INTO oidc_transactions VALUES(?,?,?,?)",(hashlib.sha256(state.encode()).hexdigest(),nonce,verifier,now+ttl))
 def consume_oidc_transaction(self,state):
  key=hashlib.sha256(state.encode()).hexdigest();now=int(time.time())
  with self.connect() as db:
   row=db.execute("SELECT * FROM oidc_transactions WHERE state_hash=? AND expires_at>=?",(key,now)).fetchone()
   db.execute("DELETE FROM oidc_transactions WHERE state_hash=?",(key,))
  return None if not row else {"nonce":row["nonce"],"code_verifier":row["code_verifier"]}
 def link_oidc_identity(self,username,issuer,subject):
  if not issuer.startswith("https://") or not subject or len(subject)>512: raise ValueError("invalid OIDC identity")
  with self.connect() as db:
   user=db.execute("SELECT active FROM users WHERE username=?",(username,)).fetchone()
   if not user or not user["active"]: raise ValueError("active local user not found")
   db.execute("INSERT INTO oidc_subjects VALUES(?,?,?,?)",(issuer,subject,username,int(time.time())))
 def create_oidc_session(self,issuer,subject):
  now=int(time.time());token=secrets.token_urlsafe(32);csrf=secrets.token_urlsafe(32)
  with self.connect() as db:
   row=db.execute("SELECT u.username,u.role,u.active FROM oidc_subjects o JOIN users u ON u.username=o.username WHERE o.issuer=? AND o.subject=?",(issuer,subject)).fetchone()
   if not row or not row["active"]: return None
   db.execute("DELETE FROM sessions WHERE expires_at<?",(now,))
   db.execute("INSERT INTO sessions VALUES(?,?,?,?,?,?)",(hashlib.sha256(token.encode()).hexdigest(),row["username"],hashlib.sha256(csrf.encode()).hexdigest(),csrf,now+SESSION_TTL,now))
  return {"token":token,"csrf":csrf,"username":row["username"],"role":row["role"],"expires_at":now+SESSION_TTL}
 def list_users(self):
  with self.connect() as db:return [dict(r) for r in db.execute("SELECT username,role,active,created_at FROM users ORDER BY username")]
