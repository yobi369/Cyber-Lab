import tempfile,unittest
from pathlib import Path
from unittest.mock import MagicMock
from audit_chain import AuditChain
from audit_archiver import AuditArchiveWorker

class AuditArchiverTests(unittest.TestCase):
 def test_changed_heads_are_anchored_once_to_object_lock(self):
  with tempfile.TemporaryDirectory() as d:
   path=Path(d)/"audit.jsonl";chain=AuditChain(path);chain.append("tester","auditor","first")
   client=MagicMock();client.get_bucket_versioning.return_value={"Status":"Enabled"}
   client.get_object_lock_configuration.return_value={"ObjectLockConfiguration":{"ObjectLockEnabled":"Enabled","ObjectLockRule":{"DefaultRetention":{"Mode":"COMPLIANCE","Days":365}}}}
   worker=AuditArchiveWorker(path,"bucket","audit-secret-material-at-least-32-characters","key-v1",30,300,client)
   first=worker.archive_once();self.assertIsNotNone(first)
   self.assertIsNone(worker.archive_once())
   chain.append("tester","auditor","second")
   second=worker.archive_once();self.assertIsNotNone(second)
   self.assertEqual(client.put_object.call_count,2)
   self.assertEqual(client.put_object.call_args.kwargs["ObjectLockMode"],"COMPLIANCE")
 def test_invalid_chain_is_not_archived(self):
  with tempfile.TemporaryDirectory() as d:
   path=Path(d)/"audit.jsonl";path.write_text("{invalid}\n")
   client=MagicMock();client.get_bucket_versioning.return_value={"Status":"Enabled"}
   client.get_object_lock_configuration.return_value={"ObjectLockConfiguration":{"ObjectLockEnabled":"Enabled","ObjectLockRule":{"DefaultRetention":{"Mode":"COMPLIANCE","Days":365}}}}
   worker=AuditArchiveWorker(path,"bucket","audit-secret-material-at-least-32-characters",client=client)
   with self.assertRaises(ValueError):worker.archive_once()
   client.put_object.assert_not_called()

if __name__=="__main__":unittest.main()
