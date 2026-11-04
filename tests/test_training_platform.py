import tempfile, unittest
from pathlib import Path
from audit_chain import AuditChain
from training_platform import Actor, AuthorizationError, Role, TrainingPlatform, RUBRIC

class AuditTests(unittest.TestCase):
 def test_chain_detects_edit(self):
  chain=AuditChain();chain.append("alice","learner","submit");chain.append("bob","reviewer","grade")
  self.assertTrue(chain.verify()["valid"]);chain._events[0]["action"]="forged";self.assertFalse(chain.verify()["valid"])
 def test_persistent_round_trip(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/"events.jsonl";a=AuditChain(p);a.append("alice","learner","submit")
   b=AuditChain(p);self.assertTrue(b.verify()["valid"]);b.append("bob","reviewer","grade");self.assertEqual(b.verify()["events"],2)

class PlatformTests(unittest.TestCase):
 def setUp(self):
  self.p=TrainingPlatform();self.learner=Actor("learner-a",Role.LEARNER);self.instructor=Actor("teacher",Role.INSTRUCTOR);self.reviewer=Actor("reviewer",Role.REVIEWER);self.auditor=Actor("auditor",Role.AUDITOR)
 def evidence(self):
  return {k:"Synthetic evidence for "+k for k in ("observations","timeline","actions","rationale","confidence","remediation")}
 def test_rbac_denies_unauthorized_actions(self):
  self.assertEqual(len(self.p.scenarios(self.learner)),3)
  with self.assertRaises(AuthorizationError):self.p.list_submissions(self.learner)
  with self.assertRaises(AuthorizationError):self.p.submit(self.auditor,"identity-01",self.evidence())
  with self.assertRaises(AuthorizationError):self.p.grade(self.learner,1,{},"no")
 def test_evidence_and_rubric_workflow(self):
  item=self.p.submit(self.learner,"identity-01",self.evidence());scores={k:3 for k in RUBRIC}
  result=self.p.grade(self.reviewer,item["id"],scores,"Good evidence; explain uncertainty more clearly.")
  self.assertEqual(result["total"],15);self.assertEqual(self.p.submissions[0]["status"],"reviewed")
  self.assertEqual(len(self.p.learner_assessments(self.learner)),1)
 def test_assessments_are_scoped_to_learner(self):
  item=self.p.submit(self.learner,"identity-01",self.evidence());self.p.grade(self.instructor,item["id"],{k:2 for k in RUBRIC},"Feedback")
  self.assertEqual(self.p.learner_assessments(Actor("other",Role.LEARNER)),[])
 def test_invalid_evidence_and_scores_rejected(self):
  with self.assertRaises(ValueError):self.p.submit(self.learner,"identity-01",{"observations":"only"})
  item=self.p.submit(self.learner,"identity-01",self.evidence())
  with self.assertRaises(ValueError):self.p.grade(self.instructor,item["id"],{k:5 for k in RUBRIC},"Feedback")
  with self.assertRaises(ValueError):self.p.submit(self.learner,"unknown",self.evidence())

if __name__=="__main__":unittest.main()
