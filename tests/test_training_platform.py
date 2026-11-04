import tempfile,unittest
from pathlib import Path
from audit_chain import AuditChain
from storage import TrainingStore
from training_platform import Actor,AuthorizationError,Role,TrainingPlatform,RUBRIC

class PlatformTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.p=TrainingPlatform(AuditChain(),TrainingStore(Path(self.tmp.name)/"training.sqlite3"))
  self.learner=Actor("learner-a",Role.LEARNER);self.instructor=Actor("teacher",Role.INSTRUCTOR);self.reviewer=Actor("reviewer",Role.REVIEWER);self.reviewer2=Actor("reviewer2",Role.REVIEWER);self.auditor=Actor("auditor",Role.AUDITOR)
 def tearDown(self):self.tmp.cleanup()
 def evidence(self):return {k:"Synthetic evidence for "+k for k in ("observations","timeline","actions","rationale","confidence","remediation")}
 def scenario(self):return {"title":"Phishing report triage","category":"Email security","level":"Foundation","brief":"Synthetic message reported.","safe_boundary":"Synthetic email only.","objectives":["Assess sender indicators","Recommend safe reporting"],"artifacts":["Synthetic header","User report"]}
 def test_published_seed_scenarios_and_rbac(self):
  self.assertEqual(len(self.p.scenarios(self.learner)),3)
  with self.assertRaises(AuthorizationError):self.p.list_submissions(self.learner)
  with self.assertRaises(AuthorizationError):self.p.submit(self.auditor,"identity-01",self.evidence())
  with self.assertRaises(AuthorizationError):self.p.grade(self.learner,1,{},"no")
 def test_scenario_draft_version_publish_and_edit(self):
  draft=self.p.create_scenario(self.instructor,self.scenario())
  self.assertEqual(draft["status"],"draft")
  with self.assertRaises(ValueError):self.p.submit(self.learner,draft["id"],self.evidence())
  published=self.p.publish_scenario(self.instructor,draft["id"],draft["version"])
  self.assertEqual(published["status"],"published")
  revised=self.scenario();revised["brief"]="Updated synthetic brief."
  v2=self.p.edit_scenario(self.instructor,draft["id"],revised)
  self.assertEqual(v2["version"],2);self.assertEqual(v2["status"],"draft")
  learner_versions=self.p.scenarios(self.learner)
  self.assertTrue(any(x["id"]==draft["id"] and x["version"]==1 for x in learner_versions))
  submission=self.p.submit(self.learner,draft["id"],self.evidence())
  self.assertEqual(submission["scenario_version"],1)
  self.assertEqual(self.p.store.scenario(draft["id"],1)["brief"],"Synthetic message reported.")
 def test_submissions_survive_restart(self):
  item=self.p.submit(self.learner,"identity-01",self.evidence())
  again=TrainingPlatform(AuditChain(),TrainingStore(Path(self.tmp.name)/"training.sqlite3"))
  self.assertEqual(again.store.submissions(self.learner.username)[0]["id"],item["id"])
 def test_second_review_and_moderation(self):
  item=self.p.submit(self.learner,"identity-01",self.evidence())
  scores={k:3 for k in RUBRIC}
  self.p.grade(self.reviewer,item["id"],scores,"Evidence supports this conclusion.")
  self.assertEqual(self.p.moderation_report(self.auditor,item["id"])["status"],"awaiting_second_review")
  with self.assertRaises(ValueError):self.p.grade(self.reviewer,item["id"],scores,"Duplicate review")
  other={k:2 for k in RUBRIC}
  self.p.grade(self.reviewer2,item["id"],other,"Second independent review.")
  report=self.p.moderation_report(self.auditor,item["id"])
  self.assertEqual(report["reviews"],2);self.assertEqual(report["status"],"moderated")
  self.assertEqual(report["agreement_rate"],0.0);self.assertEqual(report["within_one_agreement_rate"],1.0)
  with self.assertRaises(ValueError):self.p.grade(Actor("reviewer3",Role.REVIEWER),item["id"],scores,"Third review not allowed.")
 def test_learner_assessment_privacy_and_invalid_input(self):
  item=self.p.submit(self.learner,"identity-01",self.evidence())
  self.p.grade(self.reviewer,item["id"],{k:2 for k in RUBRIC},"Feedback tied to artifacts.")
  self.assertEqual(len(self.p.learner_assessments(self.learner)),1)
  self.assertEqual(self.p.learner_assessments(Actor("other",Role.LEARNER)),[])
  with self.assertRaises(ValueError):self.p.submit(self.learner,"unknown",self.evidence())
  with self.assertRaises(ValueError):self.p.grade(self.reviewer2,item["id"],{k:9 for k in RUBRIC},"Bad score")

if __name__=="__main__":unittest.main()
