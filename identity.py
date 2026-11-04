"""SQLite-backed identities and opaque server-side sessions.

Accounts are provisioned out of band with manage_users.py. The browser never
chooses a role. Passwords use PBKDF2-HMAC-SHA256 with per-user salts.
"""
from __future__ import annotations
import hashlib, hmac, secrets, sqlite3, time, os\nfrom security_controls import verify_totp
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
    active INTEGER NOT NULL DEFAULT 1, created_at INTEGER NOT NULL, mfa_secret BLOB);
   CREATE TABLE IF NOT EXISTS sessions(
    token_hash TEXT PRIMARY KEY, username TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE,
    csrf_hash TEXT NOT NULL, csrf_token TEXT NOT NULL, expires_at INTEGER NOT NULL, created_at INTEGER NOT NULL);
   CREATE INDEX IF NOT EXISTS sessions_expiry ON sessions(expires_at);
   CREATE TABLE IF NOT EXISTS login_attempts(ip_hash TEXT PRIMARY KEY, window_start INTEGER NOT NULL, failures INTEGER NOT NULL);
   """)\n   columns={row[1] for row in db.execute("PRAGMA table_info(users)")}\n   if "mfa_secret" not in columns: db.execute("ALTER TABLE users ADD COLUMN mfa_secret BLOB")
 def connect(self):
  db=sqlite3.connect(self.path,timeout=10)
  db.row_factory=sqlite3.Row
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
 def set_totp_secret(self,username,secret):\n  key=os.getenv("SENTINEL_MFA_ENCRYPTION_KEY","")\n  if len(key)!=64: raise RuntimeError("SENTINEL_MFA_ENCRYPTION_KEY must be a 256-bit hex key")\n  from cryptography.hazmat.primitives.ciphers.aead import AESGCM\n  nonce=secrets.token_bytes(12);encrypted=nonce+AESGCM(bytes.fromhex(key)).encrypt(nonce,secret.encode(),username.encode())\n  with self.connect() as db:\n   cur=db.execute("UPDATE users SET mfa_secret=? WHERE username=? AND active=1",(encrypted,username))\n   if cur.rowcount!=1: raise ValueError("active user not found")\n def authenticate(self,username,password,otp=None):
  with self.connect() as db: row=db.execute("SELECT * FROM users WHERE username=? AND active=1",(username,)).fetchone()
  if row is None:
   self._derive(password or "x",b"\0"*16)
   return None
  candidate=self._derive(password,row["salt"])
  if not hmac.compare_digest(candidate,row["password_hash"]): return None\n  if not row["mfa_secret"]:\n   if os.getenv("SENTINEL_REQUIRE_MFA")=="1": return None\n  else:\n   key=os.getenv("SENTINEL_MFA_ENCRYPTION_KEY","")\n   if len(key)!=64 or not otp: return None\n   from cryptography.hazmat.primitives.ciphers.aead import AESGCM\n   encrypted=row["mfa_secret"];secret=AESGCM(bytes.fromhex(key)).decrypt(encrypted[:12],encrypted[12:],username.encode()).decode()\n   if not verify_totp(secret,str(otp)): return None
  token=secrets.token_urlsafe(32);csrf=secrets.token_urlsafe(32);now=int(time.time())
  with self.connect() as db:
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
 def list_users(self):
  with self.connect() as db:return [dict(r) for r in db.execute("SELECT username,role,active,created_at FROM users ORDER BY username")]
