"""Signed audit checkpoints with key IDs, dual-signature rotation and S3 Object Lock export."""
import argparse,hashlib,hmac,json,os,time
from pathlib import Path
from audit_chain import AuditChain,canonical
from security_controls import S3ObjectLockArchive

def _signature(payload,secret):
 return hmac.new(secret.encode(),canonical(payload),hashlib.sha256).hexdigest()

def create_checkpoint(audit_path,output,secret,key_id=None):
 if len(secret)<32: raise ValueError("audit HMAC key must contain at least 32 characters")
 chain=AuditChain(audit_path);result=chain.verify()
 if not result["valid"]: raise ValueError("refusing to checkpoint an invalid audit chain")
 payload={"format":"sentinel-audit-checkpoint-v2","key_id":key_id or os.getenv("SENTINEL_AUDIT_KEY_ID","default"),
  "created_at":int(time.time()),"event_count":result["events"],"head_hash":result["head"]}
 checkpoint={**payload,"signature":_signature(payload,secret)}
 path=Path(output);path.parent.mkdir(parents=True,exist_ok=True)
 with path.open("x",encoding="utf-8") as stream:
  json.dump(checkpoint,stream,sort_keys=True);stream.write("\n");stream.flush();os.fsync(stream.fileno())
 return checkpoint

def verify_checkpoint(path,secret_or_keyring):
 data=json.loads(Path(path).read_text(encoding="utf-8"));signature=data.pop("signature",None)
 if isinstance(secret_or_keyring,dict):
  secret=secret_or_keyring.get(data.get("key_id"))
  if not secret:return False
 else:secret=secret_or_keyring
 if not secret or len(secret)<32:return False
 return bool(signature and hmac.compare_digest(signature,_signature(data,secret)))

def create_rotation_checkpoint(audit_path,output,old_key_id,old_secret,new_key_id,new_secret):
 if old_key_id==new_key_id or len(old_secret)<32 or len(new_secret)<32:
  raise ValueError("distinct key IDs and two 32-character keys are required")
 chain=AuditChain(audit_path);result=chain.verify()
 if not result["valid"]:raise ValueError("refusing to rotate an invalid audit chain")
 payload={"format":"sentinel-audit-key-rotation-v1","created_at":int(time.time()),
  "event_count":result["events"],"head_hash":result["head"],"old_key_id":old_key_id,"new_key_id":new_key_id}
 checkpoint={**payload,"signatures":{old_key_id:_signature(payload,old_secret),new_key_id:_signature(payload,new_secret)}}
 path=Path(output);path.parent.mkdir(parents=True,exist_ok=True)
 with path.open("x",encoding="utf-8") as stream:
  json.dump(checkpoint,stream,sort_keys=True);stream.write("\n");stream.flush();os.fsync(stream.fileno())
 return checkpoint

def verify_rotation_checkpoint(path,keyring):
 data=json.loads(Path(path).read_text(encoding="utf-8"));signatures=data.pop("signatures",{})
 ids=(data.get("old_key_id"),data.get("new_key_id"))
 return bool(ids[0]!=ids[1] and all(k in keyring and len(keyring[k])>=32 and
  k in signatures and hmac.compare_digest(signatures[k],_signature(data,keyring[k])) for k in ids))

def archive_checkpoint_s3(path,bucket,retention_days=365,client=None):
 archive=S3ObjectLockArchive(bucket,retention_days,client)
 archive.verify_bucket()
 return archive.archive(Path(path).read_bytes())

def main():
 p=argparse.ArgumentParser();p.add_argument("audit_file");p.add_argument("output");p.add_argument("--verify",action="store_true")
 p.add_argument("--key-id",default=os.getenv("SENTINEL_AUDIT_KEY_ID","default"));p.add_argument("--s3-bucket")
 p.add_argument("--retention-days",type=int,default=365);a=p.parse_args()
 secret=os.getenv("SENTINEL_AUDIT_HMAC_KEY","")
 if not secret:raise SystemExit("Set SENTINEL_AUDIT_HMAC_KEY from a secret manager.")
 if a.verify:print("valid" if verify_checkpoint(a.output,{a.key_id:secret}) else "INVALID");return
 create_checkpoint(a.audit_file,a.output,secret,a.key_id)
 if a.s3_bucket:print("Archived:",archive_checkpoint_s3(a.output,a.s3_bucket,a.retention_days))
 else:print("Checkpoint created locally; no external immutable destination was requested.")
if __name__=="__main__":main()
