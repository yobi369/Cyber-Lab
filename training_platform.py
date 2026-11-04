"""Scenario-based defensive training, RBAC, and evidence assessment."""
from __future__ import annotations
from dataclasses import dataclass
from enum import Enum
from typing import Any
from audit_chain import AuditChain

class Role(str, Enum):
    LEARNER="learner"; INSTRUCTOR="instructor"; REVIEWER="reviewer"; AUDITOR="auditor"

PERMISSIONS = {
 Role.LEARNER:frozenset({"scenario:read","submission:create","assessment:read"}),
 Role.INSTRUCTOR:frozenset({"scenario:read","scenario:create","submission:read","assessment:grade","audit:read"}),
 Role.REVIEWER:frozenset({"scenario:read","submission:read","assessment:grade"}),
 Role.AUDITOR:frozenset({"scenario:read","audit:read"}),
}
@dataclass(frozen=True)
class Actor:
    username:str
    role:Role

SCENARIOS = (
 {"id":"identity-01","title":"Suspicious account activity","level":"Foundation","category":"Identity & access",
  "brief":"A staff account shows sign-ins from two distant locations within 12 minutes. MFA fatigue reports are also present.",
  "objectives":["Build a defensible timeline","Assess compromise indicators","Recommend proportionate containment","Preserve evidence and communicate impact"],
  "artifacts":["Sign-in log: 08:02 Nairobi; 08:14 Frankfurt","MFA report: 7 unexpected prompts","No confirmed data export in available telemetry"],
  "safe_boundary":"Analyze synthetic records only. Do not contact real accounts or infrastructure."},
 {"id":"endpoint-02","title":"Ransomware tabletop (no malware)","level":"Intermediate","category":"Endpoint response",
  "brief":"A simulated finance workstation reports renamed documents and an unavailable shared folder. Backups are reported healthy but not yet verified.",
  "objectives":["Separate confirmed facts from assumptions","Propose safe isolation and escalation","Validate backup integrity before recovery","Define business-impact communications"],
  "artifacts":["EDR alert: suspicious mass file modifications","File server: elevated write volume","Backup dashboard: last job successful; restore test unknown"],
  "safe_boundary":"Tabletop only. No malware, exploit, encryption, or destructive command is provided."},
 {"id":"data-03","title":"Possible sensitive-data exposure","level":"Advanced","category":"Data protection",
  "brief":"A public sharing link was reported for a folder containing synthetic customer records. Access history is incomplete.",
  "objectives":["Scope exposure without overclaiming","Recommend containment and evidence preservation","Identify notification decision owners","Propose control improvements"],
  "artifacts":["Sharing link created yesterday by a contractor","12 external views recorded; identities unavailable","Dataset is synthetic and contains no real personal data"],
  "safe_boundary":"Use only supplied synthetic evidence. Do not enumerate or open external links."}
)
RUBRIC = {
 "evidence_quality":"Uses supplied artifacts and distinguishes fact from assumption.",
 "reasoning":"Explains how observations support conclusions and identifies uncertainty.",
 "containment":"Recommends safe, proportionate, reversible defensive actions.",
 "preservation":"Addresses evidence integrity, timestamps, custody, and documentation.",
 "remediation":"Proposes prioritized preventive controls and validation."
}
class AuthorizationError(PermissionError): pass

class TrainingPlatform:
 def __init__(self,audit:AuditChain|None=None):
  self.audit=audit or AuditChain(); self.submissions=[]; self.assessments=[]
 @staticmethod
 def require(actor:Actor,permission:str):
  if permission not in PERMISSIONS[actor.role]: raise AuthorizationError(f"{actor.role.value} cannot perform {permission}")
 def scenarios(self,actor):
  self.require(actor,"scenario:read"); return [dict(s) for s in SCENARIOS]
 def create_scenario(self,actor,scenario):
  self.require(actor,"scenario:create")
  raise NotImplementedError("Custom scenario authoring is staged; built-in scenarios are read-only.")
 def submit(self,actor,scenario_id,evidence):
  self.require(actor,"submission:create")
  if scenario_id not in {s["id"] for s in SCENARIOS}: raise ValueError("unknown scenario")
  fields=("observations","timeline","actions","rationale","confidence","remediation")
  cleaned={k:str(evidence.get(k,"")).strip() for k in fields}
  if any(not v for v in cleaned.values()): raise ValueError("all evidence fields are required")
  if any(len(v)>4000 for v in cleaned.values()): raise ValueError("evidence field exceeds 4000 characters")
  record={"id":len(self.submissions)+1,"scenario_id":scenario_id,"learner":actor.username,"evidence":cleaned,"status":"submitted"}
  self.submissions.append(record)
  self.audit.append(actor.username,actor.role.value,"evidence.submitted",{"submission_id":record["id"],"scenario_id":scenario_id})
  return dict(record)
 def list_submissions(self,actor):
  self.require(actor,"submission:read"); return [dict(x) for x in self.submissions]
 def grade(self,actor,submission_id,scores,feedback):
  self.require(actor,"assessment:grade")
  submission=next((s for s in self.submissions if s["id"]==submission_id),None)
  if submission is None: raise ValueError("unknown submission")
  if set(scores)!=set(RUBRIC) or any(type(v)is not int or not 0<=v<=4 for v in scores.values()):
   raise ValueError("provide an integer score from 0 to 4 for every rubric dimension")
  if not feedback.strip() or len(feedback)>2000: raise ValueError("feedback is required and must be at most 2000 characters")
  result={"submission_id":submission_id,"reviewer":actor.username,"scores":dict(scores),"total":sum(scores.values()),"maximum":20,"feedback":feedback.strip()}
  self.assessments.append(result); submission["status"]="reviewed"
  self.audit.append(actor.username,actor.role.value,"assessment.graded",{"submission_id":submission_id,"total":result["total"]})
  return dict(result)
 def learner_assessments(self,actor):
  self.require(actor,"assessment:read")
  own={s["id"] for s in self.submissions if s["learner"]==actor.username}
  return [dict(a) for a in self.assessments if a["submission_id"] in own]
 def audit_report(self,actor):
  self.require(actor,"audit:read"); return self.audit.verify()
