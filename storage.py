"""SQLite persistence for Sentinel Lab training records and scenario lifecycle."""
from __future__ import annotations
import json, sqlite3, time
from contextlib import contextmanager

class TrainingStore:
 def __init__(self,path="sentinel-lab.sqlite3"):
  self.path=str(path)
  with self.connect() as db:
   db.executescript("""
   CREATE TABLE IF NOT EXISTS scenarios(
    id TEXT NOT NULL, version INTEGER NOT NULL, payload TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('draft','published','archived')),
    author TEXT NOT NULL, created_at INTEGER NOT NULL,
    PRIMARY KEY(id,version));
   CREATE TABLE IF NOT EXISTS submissions(
    id INTEGER PRIMARY KEY AUTOINCREMENT, scenario_id TEXT NOT NULL,
    scenario_version INTEGER NOT NULL, learner TEXT NOT NULL, evidence TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'submitted', created_at INTEGER NOT NULL);
   CREATE TABLE IF NOT EXISTS assessments(
    id INTEGER PRIMARY KEY AUTOINCREMENT, submission_id INTEGER NOT NULL REFERENCES submissions(id),
    reviewer TEXT NOT NULL, scores TEXT NOT NULL, total INTEGER NOT NULL,
    feedback TEXT NOT NULL, round INTEGER NOT NULL DEFAULT 1, created_at INTEGER NOT NULL);
   CREATE INDEX IF NOT EXISTS submissions_learner ON submissions(learner);
   CREATE INDEX IF NOT EXISTS assessments_submission ON assessments(submission_id);
   """)
 def connect(self):
  db=sqlite3.connect(self.path,timeout=10);db.row_factory=sqlite3.Row
  db.execute("PRAGMA foreign_keys=ON");db.execute("PRAGMA journal_mode=WAL");return db
 def save_scenario(self,item,author,status="draft"):
  with self.connect() as db:
   version=db.execute("SELECT COALESCE(MAX(version),0)+1 FROM scenarios WHERE id=?",(item["id"],)).fetchone()[0]
   db.execute("INSERT INTO scenarios VALUES(?,?,?,?,?,?)",(item["id"],version,json.dumps(item,sort_keys=True),status,author,int(time.time())))
  return version
 def scenarios(self,include_unpublished=False):
  with self.connect() as db:
   rows=db.execute("""SELECT s.* FROM scenarios s JOIN (SELECT id,MAX(version) v FROM scenarios GROUP BY id) x ON s.id=x.id AND s.version=x.v ORDER BY s.id""").fetchall()
  return [{"version":r["version"],"status":r["status"],"author":r["author"],**json.loads(r["payload"])} for r in rows if include_unpublished or r["status"]=="published"]
 def set_scenario_status(self,sid,version,status):
  if status not in {"draft","published","archived"}:raise ValueError("invalid scenario status")
  with self.connect() as db:
   cur=db.execute("UPDATE scenarios SET status=? WHERE id=? AND version=?",(status,sid,version))
   if cur.rowcount!=1:raise ValueError("scenario version not found")
 def scenario(self,sid,version=None):
  with self.connect() as db:
   if version is None:r=db.execute("SELECT * FROM scenarios WHERE id=? ORDER BY version DESC LIMIT 1",(sid,)).fetchone()
   else:r=db.execute("SELECT * FROM scenarios WHERE id=? AND version=?",(sid,version)).fetchone()
  return None if not r else {"version":r["version"],"status":r["status"],"author":r["author"],**json.loads(r["payload"])}
 def add_submission(self,sid,version,learner,evidence):
  with self.connect() as db:
   cur=db.execute("INSERT INTO submissions(scenario_id,scenario_version,learner,evidence,created_at) VALUES(?,?,?,?,?)",(sid,version,learner,json.dumps(evidence,sort_keys=True),int(time.time())))
   return cur.lastrowid
 def submissions(self,learner=None):
  with self.connect() as db:
   rows=db.execute("SELECT * FROM submissions WHERE learner=? ORDER BY id" ,(learner,)).fetchall() if learner else db.execute("SELECT * FROM submissions ORDER BY id").fetchall()
  return [{"id":r["id"],"scenario_id":r["scenario_id"],"scenario_version":r["scenario_version"],"learner":r["learner"],"evidence":json.loads(r["evidence"]),"status":r["status"],"created_at":r["created_at"]} for r in rows]
 def add_assessment(self,sid,reviewer,scores,feedback,round_number=1):
  with self.connect() as db:
   cur=db.execute("INSERT INTO assessments(submission_id,reviewer,scores,total,feedback,round,created_at) VALUES(?,?,?,?,?,?,?)",(sid,reviewer,json.dumps(scores,sort_keys=True),sum(scores.values()),feedback,round_number,int(time.time())))
   db.execute("UPDATE submissions SET status='reviewed' WHERE id=?",(sid,))
   return cur.lastrowid
 def assessments(self,submission_id=None,reviewer=None):
  sql="SELECT * FROM assessments WHERE 1=1";args=[]
  if submission_id is not None:sql+=" AND submission_id=?";args.append(submission_id)
  if reviewer is not None:sql+=" AND reviewer=?";args.append(reviewer)
  with self.connect() as db:rows=db.execute(sql+" ORDER BY id",args).fetchall()
  return [{"id":r["id"],"submission_id":r["submission_id"],"reviewer":r["reviewer"],"scores":json.loads(r["scores"]),"total":r["total"],"feedback":r["feedback"],"round":r["round"]} for r in rows]
