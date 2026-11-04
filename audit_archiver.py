"""Periodic external anchoring of audit-chain heads to S3 Object Lock."""
import json,logging,os,threading,time
from audit_chain import AuditChain,canonical
from security_controls import S3ObjectLockArchive
import hashlib,hmac

class AuditArchiveWorker:
 def __init__(self,audit_path,bucket,secret,key_id="default",retention_days=365,interval_seconds=300,client=None):
  if len(secret)<32: raise ValueError("audit HMAC key must contain at least 32 characters")
  if interval_seconds<30: raise ValueError("archive interval must be at least 30 seconds")
  self.audit_path,self.secret,self.key_id=audit_path,secret,key_id
  self.archive=S3ObjectLockArchive(bucket,retention_days,client)
  self.archive.verify_bucket()
  self.interval=interval_seconds;self.stop_event=threading.Event();self.thread=None;self.last_head=None
 def archive_once(self):
  chain=AuditChain(self.audit_path);result=chain.verify()
  if not result["valid"]: raise ValueError("refusing to externally anchor invalid audit chain")
  if result["head"]==self.last_head:return None
  payload={"format":"sentinel-audit-checkpoint-v2","key_id":self.key_id,"created_at":int(time.time()),
   "event_count":result["events"],"head_hash":result["head"]}
  checkpoint={**payload,"signature":hmac.new(self.secret.encode(),canonical(payload),hashlib.sha256).hexdigest()}
  key=self.archive.archive(json.dumps(checkpoint,sort_keys=True,separators=(",",":")).encode())
  self.last_head=result["head"];return key
 def _run(self):
  while not self.stop_event.is_set():
   try:self.archive_once()
   except Exception:logging.exception("Sentinel external audit archive failed")
   self.stop_event.wait(self.interval)
 def start(self):
  if self.thread and self.thread.is_alive():return
  self.thread=threading.Thread(target=self._run,name="sentinel-audit-archive",daemon=True);self.thread.start()
 def stop(self):
  self.stop_event.set()
  if self.thread:self.thread.join(timeout=5)
