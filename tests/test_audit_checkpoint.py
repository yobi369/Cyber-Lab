import tempfile,unittest,json
from pathlib import Path
from audit_chain import AuditChain
from audit_checkpoint import create_checkpoint,verify_checkpoint

class CheckpointTests(unittest.TestCase):
 def test_signed_checkpoint_and_tamper_detection(self):
  with tempfile.TemporaryDirectory() as d:
   audit=Path(d)/"audit.jsonl";chain=AuditChain(audit);chain.append("auditor","auditor","test")
   output=Path(d)/"checkpoint.json";secret="test-secret-key-that-is-at-least-32-bytes"
   create_checkpoint(audit,output,secret)
   self.assertTrue(verify_checkpoint(output,secret))
   data=json.loads(output.read_text());data["event_count"]=9;output.write_text(json.dumps(data))
   self.assertFalse(verify_checkpoint(output,secret))
 def test_refuses_short_secret_and_invalid_chain(self):
  with tempfile.TemporaryDirectory() as d:
   audit=Path(d)/"audit.jsonl";audit.write_text("{bad json}\n")
   with self.assertRaises(ValueError):create_checkpoint(audit,Path(d)/"out.json","short")
   with self.assertRaises(ValueError):create_checkpoint(audit,Path(d)/"out.json","this-secret-is-long-enough-to-be-valid")

if __name__=="__main__":unittest.main()
