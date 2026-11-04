"""SQLite-backed defensive training platform with RBAC and assessment moderation."""
from __future__ import annotations
from dataclasses import dataclass
from enum import Enum
from typing import Any
from audit_chain import AuditChain
from storage import TrainingStore

class Role(str,Enum):
 LEARNER="learner";INSTRUCTOR="instructor";REVIEWER="reviewer";AUDITOR="auditor"
PERMISSIONS={
 Role.LEARNER:frozenset({"scenario:read","submission:create","assessment:read"}),
 Role.INSTRUCTOR:frozenset({"scenario:read","scenario:create","scenario:edit","scenario:publish","submission:read","assessment:grade","assessment:moderate","audit:read"}),
 Role.REVIEWER:frozenset({"scenario:read","submission:read","assessment:grade","assessment:moderate"}),
 Role.AUDITOR:frozenset({"scenario:read","audit:read","assessment:moderate"}),
}
@dataclass(frozen=True)
class Actor:
 username:str
 role:Role
SCENARIOS=(
 {"id":"identity-01","title":"Suspicious account activity","level":"Foundation","category":"Identity & access","brief":"A staff account shows sign-ins from two distant locations within 12 minutes. MFA fatigue reports are also present.","objectives":["Build a defensible timeline","Assess compromise indicators","Recommend proportionate containment","Preserve evidence and communicate impact"],"artifacts":["Sign-in log: 08:02 Nairobi; 08:14 Frankfurt","MFA report: 7 unexpected prompts","No confirmed data export in available telemetry"],"safe_boundary":"Analyze synthetic records only. Do not contact real accounts or infrastructure."},
 {"id":"endpoint-02","title":"Ransomware tabletop (no malware)","level":"Intermediate","category":"Endpoint response","brief":"A simulated finance workstation reports renamed documents and an unavailable shared folder. Backups are reported healthy but not yet verified.","objectives":["Separate confirmed facts from assumptions","Propose safe isolation and escalation","Validate backup integrity before recovery","Define business-impact communications"],"artifacts":["EDR alert: suspicious mass file modifications","File server: elevated write volume","Backup dashboard: last job successful; restore test unknown"],"safe_boundary":"Tabletop only. No malware, exploit, encryption, or destructive command is provided."},
 {"id":"data-03","title":"Possible sensitive-data exposure","level":"Advanced","category":"Data protection","brief":"A public sharing link was reported for a folder containing synthetic customer records. Access history is incomplete.","objectives":["Scope exposure without overclaiming","Recommend containment and evidence preservation","Identify notification decision owners","Propose control improvements"],"artifacts":["Sharing link created yesterday by a contractor","12 external views recorded; identities unavailable","Dataset is synthetic and contains no real personal data"],"safe_boundary":"Use only supplied synthetic evidence. Do not enumerate or open external links."}
)
RUBRIC={"evidence_quality":"Uses supplied artifacts and distinguishes fact from assumption.","reasoning":"Explains how observations support conclusions and identifies uncertainty.","containment":"Recommends safe, proportionate, reversible defensive actions.","preservation":"Addresses evidence integrity, timestamps, custody, and documentation.","remediation":"Proposes prioritized preventive controls and validation."}
class AuthorizationError(PermissionError):pass
class TrainingPlatform:
 def __init__(self,audit:AuditChain|None=None,store:TrainingStore|None=None):
  self.audit=audit or AuditChain();self.store=store or TrainingStore()
  if not self.store.scenarios(include_unpublished=True):
   for scenario in SCENARIOS:self.store.save_scenario(scenario,"system","published")
 @staticmethod
 def require(actor,permission):
  if permission not in PERMISSIONS[actor.role]:raise AuthorizationError(f"{actor.role.value} cannot perform {permission}")
 def scenarios(self,actor):
  self.require(actor,"scenario:read")
  return self.store.scenarios(include_unpublished=actor.role in {Role.INSTRUCTOR,Role.REVIEWER,Role.AUDITOR})
 def create_scenario(self,actor,scenario):
  self.require(actor,"scenario:create")
  item=self._validate_scenario(scenario);item["id"]=str(scenario.get("id") or "scenario-"+__import__("secrets").token_hex(6))
  version=self.store.save_scenario(item,actor.username,"draft")
  self.audit.append(actor.username,actor.role.value,"scenario.created",{"scenario_id":item["id"],"version":version})
  return self.store.scenario(item["id"],version)
 def edit_scenario(self,actor,scenario_id,scenario):
  self.require(actor,"scenario:edit")
  current=self.store.scenario(scenario_id)
  if not current:raise ValueError("scenario not found")
  item=self._validate_scenario(scenario);item["id"]=scenario_id
  version=self.store.save_scenario(item,actor.username,"draft")
  self.audit.append(actor.username,actor.role.value,"scenario.version_created",{"scenario_id":scenario_id,"version":version})
  return self.store.scenario(scenario_id,version)
 def publish_scenario(self,actor,scenario_id,version):
  self.require(actor,"scenario:publish")
  item=self.store.scenario(scenario_id,version)
  if not item:raise ValueError("scenario version not found")
  self.store.set_scenario_status(scenario_id,version,"published")
  self.audit.append(actor.username,actor.role.value,"scenario.published",{"scenario_id":scenario_id,"version":version})
  return self.store.scenario(scenario_id,version)
 def archive_scenario(self,actor,scenario_id,version):
  self.require(actor,"scenario:publish")
  self.store.set_scenario_status(scenario_id,version,"archived")
  self.audit.append(actor.username,actor.role.value,"scenario.archived",{"scenario_id":scenario_id,"version":version})
 def _validate_scenario(self,scenario):
  fields=("title","category","level","brief","safe_boundary")
  item={k:str(scenario.get(k,"")).strip() for k in fields}
  if any(not v for v in item.values()):raise ValueError("all scenario fields are required")
  if any(len(item[k])>1000 for k in fields):raise ValueError("scenario field exceeds 1000 characters")
  objectives=[str(x).strip() for x in scenario.get("objectives",[]) if str(x).strip()]
  artifacts=[str(x).strip() for x in scenario.get("artifacts",[]) if str(x).strip()]
  if not 2<=len(objectives)<=8 or not 1<=len(artifacts)<=10:raise ValueError("provide 2–8 objectives and 1–10 evidence artifacts")
  if any(len(x)>500 for x in objectives+artifacts):raise ValueError("objective or artifact exceeds 500 characters")
  item.update(objectives=objectives,artifacts=artifacts);return item
 def submit(self,actor,scenario_id,evidence):
  self.require(actor,"submission:create")
  scenario=self.store.scenario(scenario_id)
  if not scenario or scenario["status"]!="published":raise ValueError("scenario is not published")
  fields=("observations","timeline","actions","rationale","confidence","remediation")
  cleaned={k:str(evidence.get(k,"")).strip() for k in fields}
  if any(not v for v in cleaned.values()):raise ValueError("all evidence fields are required")
  if any(len(v)>4000 for v in cleaned.values()):raise ValueError("evidence field exceeds 4000 characters")
  sid=self.store.add_submission(scenario_id,scenario["version"],actor.username,cleaned)
  self.audit.append(actor.username,actor.role.value,"evidence.submitted",{"submission_id":sid,"scenario_id":scenario_id,"scenario_version":scenario["version"]})
  return next(x for x in self.store.submissions() if x["id"]==sid)
 def list_submissions(self,actor):
  self.require(actor,"submission:read");rows=self.store.submissions();
  for row in rows:row["review_count"]=len(self.store.assessments(row["id"]))
  return rows
 def grade(self,actor,submission_id,scores,feedback):
  self.require(actor,"assessment:grade")
  submission=next((s for s in self.store.submissions() if s["id"]==submission_id),None)
  if not submission:raise ValueError("unknown submission")
  if set(scores)!=set(RUBRIC) or any(type(v)is not int or not 0<=v<=4 for v in scores.values()):raise ValueError("provide an integer score from 0 to 4 for every rubric dimension")
  if not feedback.strip() or len(feedback)>2000:raise ValueError("feedback is required and must be at most 2000 characters")
  prior=self.store.assessments(submission_id)
  if any(x["reviewer"]==actor.username for x in prior):raise ValueError("a reviewer may assess a submission only once")
  round_number=len(prior)+1
  aid=self.store.add_assessment(submission_id,actor.username,scores,feedback.strip(),round_number)
  result=next(x for x in self.store.assessments(submission_id) if x["id"]==aid)
  self.audit.append(actor.username,actor.role.value,"assessment.graded",{"submission_id":submission_id,"assessment_id":aid,"round":round_number,"total":result["total"]})
  return result
 def moderation_report(self,actor,submission_id):
  self.require(actor,"assessment:moderate")
  rows=self.store.assessments(submission_id)
  if len(rows)<2:return {"status":"awaiting_second_review","reviews":len(rows)}
  a,b=rows[0],rows[1];diff={k:abs(a["scores"][k]-b["scores"][k]) for k in RUBRIC}
  agreement=sum(v==0 for v in diff.values())
  return {"status":"moderated" if max(diff.values())<=1 else "adjudication_required","reviews":2,"dimension_differences":diff,"exact_dimension_agreement":agreement,"agreement_rate":agreement/len(RUBRIC),"total_score_difference":abs(a["total"]-b["total"])}
 def learner_assessments(self,actor):
  self.require(actor,"assessment:read")
  own={s["id"] for s in self.store.submissions(actor.username)}
  return [a for sid in own for a in self.store.assessments(sid)]
 def audit_report(self,actor):
  self.require(actor,"audit:read");return self.audit.verify()
