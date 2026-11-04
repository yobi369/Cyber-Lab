import tempfile,unittest,json
from pathlib import Path
from audit_chain import AuditChain
from audit_checkpoint import create_checkpoint,verify_checkpoint,create_rotation_checkpoint,verify_rotation_checkpoint,archive_checkpoint_s3
from unittest.mock import MagicMock

class CheckpointTests(unittest.TestCase):
 def test_signed_checkpoint_and_tamper_detection(self):
  with tempfile.TemporaryDirectory() as d:
   audit=Path(d)/"audit.jsonl";chain=AuditChain(audit);chain.append("auditor","auditor","test")
   output=Path(d)/"checkpoint.json";secret="test-secret-key-that-is-at-least-32-bytes"
   create_checkpoint(audit,output,secret)
   self.assertTrue(verify_checkpoint(output,secret))
   data=json.loads(output.read_text());data["event_count"]=9;output.write_text(json.dumps(data))
   self.assertFalse(verify_checkpoint(output,secret))
 def test_dual_signed_key_rotation(self):
  with tempfile.TemporaryDirectory() as d:
   audit=Path(d)/"audit.jsonl";AuditChain(audit).append("auditor","auditor","rotate")
   output=Path(d)/"rotation.json";old="old-key-material-at-least-32-characters";new="new-key-material-at-least-32-characters"
   create_rotation_checkpoint(audit,output,"v1",old,"v2",new)
   self.assertTrue(verify_rotation_checkpoint(output,{"v1":old,"v2":new}))
   self.assertFalse(verify_rotation_checkpoint(output,{"v2":new}))
 def test_s3_object_lock_archive(self):
  with tempfile.TemporaryDirectory() as d:
   path=Path(d)/"checkpoint.json";path.write_bytes(b'{"signed":true}')
   client=MagicMock();client.get_bucket_versioning.return_value={"Status":"Enabled"}
   client.get_object_lock_configuration.return_value={"ObjectLockConfiguration":{"ObjectLockRule":{"DefaultRetention":{"Days":365}}}}
   key=archive_checkpoint_s3(path,"audit-bucket",30,client)
   self.assertTrue(key.startswith("sentinel-audit/sha256/"))
   self.assertEqual(client.put_object.call_args.kwargs["ObjectLockMode"],"COMPLIANCE")
 def test_refuses_short_secret_and_invalid_chain(self):
  with tempfile.TemporaryDirectory() as d:
   audit=Path(d)/"audit.jsonl";audit.write_text("{bad json}\n")
   with self.assertRaises(ValueError):create_checkpoint(audit,Path(d)/"out.json","short")
   with self.assertRaises(ValueError):create_checkpoint(audit,Path(d)/"out.json","this-secret-is-long-enough-to-be-valid")

if __name__=="__main__":unittest.main()
