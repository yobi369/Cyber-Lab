"""SQLite-backed identities and opaque server-side sessions.

Accounts are provisioned out of band with manage_users.py. The browser never
chooses a role. Passwords use PBKDF2-HMAC-SHA256 with per-user salts.
"""
from __future__ import annotations
import hashlib, hmac, secrets, sqlite3, time
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
    active INTEGER NOT NULL DEFAULT 1, created_at INTEGER NOT NULL);
   CREATE TABLE IF NOT EXISTS sessions(
    token_hash TEXT PRIMARY KEY, username TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE,
    csrf_hash TEXT NOT NULL, expires_at INTEGER NOT NULL, created_at INTEGER NOT NULL);
   CREATE INDEX IF NOT EXISTS sessions_expiry ON sessions(expires_at);
   """)
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
 def authenticate(self,username,password):
  with self.connect() as db: row=db.execute("SELECT * FROM users WHERE username=? AND active=1",(username,)).fetchone()
  if row is None:
   self._derive(password or "x",b"\0"*16)
   return None
  candidate=self._derive(password,row["salt"])
  if not hmac.compare_digest(candidate,row["password_hash"]): return None
  token=secrets.token_urlsafe(32);csrf=secrets.token_urlsafe(32);now=int(time.time())
  with self.connect() as db:
   db.execute("DELETE FROM sessions WHERE expires_at<?",(now,))
   db.execute("INSERT INTO sessions VALUES(?,?,?,?,?)",(hashlib.sha256(token.encode()).hexdigest(),username,hashlib.sha256(csrf.encode()).hexdigest(),now+SESSION_TTL,now))
  return {"token":token,"csrf":csrf,"username":username,"role":row["role"],"expires_at":now+SESSION_TTL}
 def session(self,token):
  if not token:return None
  key=hashlib.sha256(token.encode()).hexdigest()
  with self.connect() as db:
   row=db.execute("SELECT s.*,u.role,u.active FROM sessions s JOIN users u USING(username) WHERE token_hash=?",(key,)).fetchone()
  if not row or not row["active"] or row["expires_at"]<int(time.time()): return None
  return {"username":row["username"],"role":row["role"],"csrf_hash":row["csrf_hash"]}
 def verify_csrf(self,session,value):
  return bool(session and value and hmac.compare_digest(session["csrf_hash"],hashlib.sha256(value.encode()).hexdigest()))
 def logout(self,token):
  if token:
   with self.connect() as db:db.execute("DELETE FROM sessions WHERE token_hash=?",(hashlib.sha256(token.encode()).hexdigest(),))
 def list_users(self):
  with self.connect() as db:return [dict(r) for r in db.execute("SELECT username,role,active,created_at FROM users ORDER BY username")]
