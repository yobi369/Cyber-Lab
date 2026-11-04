"""Create and verify signed audit-head checkpoints for independent retention.

Upload the resulting checkpoint JSON to a separately administered immutable store.
This utility does not itself provide remote/WORM storage.
"""
import argparse,hashlib,hmac,json,os,time
from pathlib import Path
from audit_chain import AuditChain,canonical

def create_checkpoint(audit_path,output,secret):
 if len(secret)<32:raise ValueError("SENTINEL_AUDIT_HMAC_KEY must contain at least 32 characters")
 chain=AuditChain(audit_path);result=chain.verify()
 if not result["valid"]:raise ValueError("refusing to checkpoint an invalid audit chain")
 payload={"format":"sentinel-audit-checkpoint-v1","created_at":int(time.time()),"event_count":result["events"],"head_hash":result["head"]}
 signature=hmac.new(secret.encode(),canonical(payload),hashlib.sha256).hexdigest()
 checkpoint={**payload,"signature":signature}
 path=Path(output);path.parent.mkdir(parents=True,exist_ok=True)
 with path.open("x",encoding="utf-8") as stream:json.dump(checkpoint,stream,sort_keys=True);stream.write("\\n");stream.flush();os.fsync(stream.fileno())
 return checkpoint

def verify_checkpoint(path,secret):
 data=json.loads(Path(path).read_text(encoding="utf-8"));signature=data.pop("signature",None)
 expected=hmac.new(secret.encode(),canonical(data),hashlib.sha256).hexdigest()
 return bool(signature and hmac.compare_digest(signature,expected))

def main():
 p=argparse.ArgumentParser();p.add_argument("audit_file");p.add_argument("output");p.add_argument("--verify",action="store_true");a=p.parse_args()
 secret=os.getenv("SENTINEL_AUDIT_HMAC_KEY","")
 if not secret:raise SystemExit("Set SENTINEL_AUDIT_HMAC_KEY from a secret manager.")
 if a.verify:print("valid" if verify_checkpoint(a.output,secret) else "INVALID");return
 print(json.dumps(create_checkpoint(a.audit_file,a.output,secret),indent=2))
if __name__=="__main__":main()
