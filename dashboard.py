"""Loopback-only browser dashboard for defensive training exercises."""
from __future__ import annotations
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json, os
from urllib.parse import urlparse, parse_qs
from audit_chain import AuditChain
from training_platform import Actor, Role, TrainingPlatform, AuthorizationError

PLATFORM=TrainingPlatform(AuditChain(os.getenv("ADMIN_LAB_AUDIT_FILE","training-audit.jsonl")))
PAGE="""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sentinel Lab | Defensive Training</title><style>
:root{color-scheme:dark;--bg:#0a1220;--panel:#132238;--line:#2b405c;--text:#e9f0fa;--muted:#9db0c8;--accent:#62d8c5}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at 85% 0,#1b3550,transparent 35%),var(--bg);color:var(--text);font:15px/1.55 system-ui,sans-serif}
header{padding:22px max(20px,calc((100% - 1160px)/2));border-bottom:1px solid var(--line);display:flex;justify-content:space-between;gap:16px;flex-wrap:wrap}
main{max-width:1160px;margin:28px auto;padding:0 20px}.brand{font-weight:850;letter-spacing:.12em}.brand b{color:var(--accent)}.muted{color:var(--muted)}.eyebrow{color:var(--accent);font-size:11px;letter-spacing:.14em;text-transform:uppercase}
h1{font-size:clamp(26px,4vw,38px);margin:7px 0}h2{font-size:18px;margin:0 0 12px}.notice{padding:12px 15px;border:1px solid #705b31;background:#2a2419;color:#f3dca8;border-radius:12px;margin:20px 0}
.stats{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin:18px 0}.stat,.panel,.scenario{background:linear-gradient(145deg,#172a43,#111d30);border:1px solid var(--line);border-radius:15px;padding:17px}.stat strong{display:block;font-size:27px}
.layout{display:grid;grid-template-columns:minmax(250px,.8fr) minmax(0,1.5fr);gap:16px}.scenario{margin:10px 0;cursor:pointer}.scenario.active{border-color:var(--accent)}.tag{color:var(--accent);font-size:11px;text-transform:uppercase}
.artifact{background:#0c1828;border-radius:9px;padding:10px;margin:7px 0;color:#c9d8e9}label{display:block;margin:12px 0 5px;color:#c3d0e1;font-size:13px}
textarea,input,select,button{font:inherit;border:1px solid var(--line);border-radius:9px;padding:10px 12px;background:#0c1828;color:var(--text)}textarea{width:100%;min-height:76px}button{background:var(--accent);color:#061a1a;font-weight:750;border:0;cursor:pointer}button.secondary{background:#203651;color:var(--text);border:1px solid var(--line)}.row{display:flex;gap:9px;align-items:center;flex-wrap:wrap}.hidden{display:none}#message{min-height:24px;color:var(--accent);margin:12px 0}footer{max-width:1160px;margin:26px auto;padding:0 20px 24px;color:var(--muted);font-size:12px}
@media(max-width:740px){.layout{grid-template-columns:1fr}.stats{grid-template-columns:1fr}header{display:block}header .row{margin-top:12px}}
</style></head><body><header><div><div class="brand">◈ SENTINEL <b>LAB</b></div><div class="muted">Defensive cybersecurity training workspace</div></div>
<div class="row"><label for="role">Demo role</label><select id="role"><option>learner</option><option>instructor</option><option>reviewer</option><option>auditor</option></select><input id="username" value="trainee-01" aria-label="Demo username"></div></header>
<main><div class="eyebrow">Training operations / local environment</div><h1>Incident response workspace</h1><div class="muted">Investigate synthetic incidents. Submit evidence. Learn through structured feedback.</div>
<div class="notice">SIMULATION ONLY · Synthetic evidence only. No scanning, malware, remote access, or real system changes. Role switching is a demonstration—not authentication.</div>
<div class="stats"><div class="stat"><span class="muted">Scenario library</span><strong id="scenarioCount">—</strong><span class="muted">Tabletop exercises</span></div><div class="stat"><span class="muted">Evidence submissions</span><strong id="submissionCount">—</strong><span class="muted">Local session</span></div><div class="stat"><span class="muted">Audit integrity</span><strong id="auditState">Pending</strong><span id="auditMeta" class="muted">Not yet verified</span></div></div>
<div class="layout"><section class="panel"><h2>Scenario library</h2><div class="muted">Choose an exercise.</div><div id="scenarios"></div></section>
<section class="panel"><div id="category" class="eyebrow">Select a scenario</div><h2 id="title">Training brief</h2><p id="brief" class="muted">Choose a scenario from the library.</p><h3>Objectives</h3><ul id="objectives"></ul><h3>Evidence pack</h3><div id="artifacts"></div><p id="boundary" class="muted"></p>
<div id="submitPanel" class="hidden"><h3>Evidence submission</h3><form id="evidence"><label>Observations (facts vs assumptions)</label><textarea name="observations" required maxlength="4000"></textarea><label>Incident timeline</label><textarea name="timeline" required maxlength="4000"></textarea><label>Containment and escalation</label><textarea name="actions" required maxlength="4000"></textarea><label>Reasoning and uncertainty</label><textarea name="rationale" required maxlength="4000"></textarea><label>Confidence and justification</label><textarea name="confidence" required maxlength="4000"></textarea><label>Remediation and validation</label><textarea name="remediation" required maxlength="4000"></textarea><p><button>Submit evidence for review</button></p></form></div>
<div id="authorPanel" class="hidden"><h3>Scenario authoring</h3><form id="scenarioForm"><label>Scenario title</label><input name="title" required maxlength="100"><label>Category</label><input name="category" required maxlength="60"><label>Difficulty</label><select name="level"><option>Foundation</option><option>Intermediate</option><option>Advanced</option></select><label>Incident brief</label><textarea name="brief" required maxlength="1000"></textarea><label>Learning objectives (one per line; 2–8)</label><textarea name="objectives" required></textarea><label>Synthetic evidence artifacts (one per line)</label><textarea name="artifacts" required></textarea><label>Safety boundary</label><textarea name="safe_boundary" required maxlength="1000"></textarea><p><button>Create scenario</button></p></form></div><div id="learnerResults" class="hidden"><h3>My assessment results</h3><div id="results"></div></div><div id="reviewPanel" class="hidden"><h3>Review queue</h3><div id="queue"></div></div><div id="message" role="status"></div><button class="secondary" id="verify">Verify audit integrity</button></section></div></main>
<footer>Educational prototype only. Do not expose publicly or enter real customer, personal, or production security data.</footer>
<script>
let items=[],selected=null;const el=id=>document.getElementById(id);
const actor=()=>({role:el('role').value,username:el('username').value.trim()||'anonymous'});
async function api(path,options={}){let r=await fetch(path,{...options,headers:{'Content-Type':'application/json'}});let d=await r.json();if(!r.ok)throw Error(d.error||'Request failed');return d}
function say(s){el('message').textContent=s}
function choose(s){selected=s;el('category').textContent=s.category+' / '+s.level;el('title').textContent=s.title;el('brief').textContent=s.brief;el('objectives').replaceChildren(...s.objectives.map(t=>{let n=document.createElement('li');n.textContent=t;return n}));el('artifacts').replaceChildren(...s.artifacts.map(t=>{let n=document.createElement('div');n.className='artifact';n.textContent=t;return n}));el('boundary').textContent=s.safe_boundary;document.querySelectorAll('.scenario').forEach(n=>n.classList.toggle('active',n.dataset.id===s.id));el('submitPanel').classList.toggle('hidden',actor().role!=='learner')}
async function stats(){try{let d=await api('/api/stats?role='+actor().role+'&username='+encodeURIComponent(actor().username));el('submissionCount').textContent=d.submissions;el('auditState').textContent=d.audit.valid?'Valid':'Alert';el('auditMeta').textContent=d.audit.events+' events · '+d.audit.head.slice(0,12)}catch(e){el('auditState').textContent='Restricted'}}
async function queue(){try{let q=await api('/api/submissions?role='+actor().role+'&username='+encodeURIComponent(actor().username));el('reviewPanel').classList.remove('hidden');el('queue').replaceChildren(...q.map(x=>{let d=document.createElement('div');d.className='artifact';let t=document.createElement('span');t.textContent='#'+x.id+' · '+x.learner+' · '+x.scenario_id+' · '+x.status;d.append(t);if(x.status==='submitted'){let b=document.createElement('button');b.className='secondary';b.textContent='Grade';b.onclick=()=>grade(x.id);d.append(b)}return d}))}catch(e){say(e.message)}}
async function grade(id){let keys=['evidence_quality','reasoning','containment','preservation','remediation'],scores={};for(let k of keys){let v=prompt(k+' score (0–4)');if(v===null)return;scores[k]=Number(v)}let feedback=prompt('Written feedback:');if(feedback===null)return;try{let r=await api('/api/grade',{method:'POST',body:JSON.stringify({actor:actor(),submission_id:id,scores,feedback})});say('Assessment recorded: '+r.total+'/20');await queue();await stats()}catch(e){say(e.message)}}
async function learnerResults(){try{let a=await api('/api/assessments?role='+actor().role+'&username='+encodeURIComponent(actor().username));el('learnerResults').classList.remove('hidden');el('results').replaceChildren(...a.map(x=>{let d=document.createElement('div');d.className='artifact';d.textContent='Submission #'+x.submission_id+' · '+x.total+'/'+x.maximum+' · '+x.feedback;return d}))}catch(e){say(e.message)}}
async function load(){try{items=await api('/api/scenarios?role='+actor().role+'&username='+encodeURIComponent(actor().username));el('scenarioCount').textContent=items.length;el('scenarios').replaceChildren(...items.map(s=>{let d=document.createElement('div');d.className='scenario';d.dataset.id=s.id;let tag=document.createElement('div');tag.className='tag';tag.textContent=s.level+' / '+s.category;let title=document.createElement('h3');title.textContent=s.title;let p=document.createElement('div');p.className='muted';p.textContent=s.brief.slice(0,100)+'…';d.append(tag,title,p);d.onclick=()=>choose(s);return d}));if(items.length)choose(items[0]);el('authorPanel').classList.toggle('hidden',actor().role!=='instructor');if(actor().role==='learner')await learnerResults();else el('learnerResults').classList.add('hidden');if(['instructor','reviewer'].includes(actor().role))await queue();else el('reviewPanel').classList.add('hidden');await stats()}catch(e){say(e.message)}}
el('scenarioForm').onsubmit=async e=>{e.preventDefault();let data=Object.fromEntries(new FormData(e.target).entries());data.objectives=data.objectives.split('\n');data.artifacts=data.artifacts.split('\n');try{let created=await api('/api/scenario',{method:'POST',body:JSON.stringify({actor:actor(),scenario:data})});say('Scenario created: '+created.id);e.target.reset();await load()}catch(err){say(err.message)}};
el('evidence').onsubmit=async e=>{e.preventDefault();if(!selected)return;try{await api('/api/submit',{method:'POST',body:JSON.stringify({actor:actor(),scenario_id:selected.id,evidence:Object.fromEntries(new FormData(e.target).entries())})});say('Evidence submitted for instructor review.');e.target.reset();await stats()}catch(err){say(err.message)}};
el('role').onchange=load;el('username').onchange=load;el('verify').onclick=async()=>{try{let r=await api('/api/audit?role='+actor().role+'&username='+encodeURIComponent(actor().username));say(r.valid?'Audit chain verified · '+r.events+' events':'INTEGRITY FAILURE · '+r.reason);await stats()}catch(e){say(e.message)}};load();
</script></body></html>"""

def parse_actor(query):
    return Actor(query.get("username",["anonymous"])[0][:80],Role(query.get("role",["learner"])[0]))

class Handler(BaseHTTPRequestHandler):
    def send_json(self,status,payload):
        body=json.dumps(payload).encode();self.send_response(status)
        self.send_header("Content-Type","application/json; charset=utf-8");self.send_header("Content-Length",str(len(body)))
        self.send_header("X-Content-Type-Options","nosniff");self.send_header("Cache-Control","no-store");self.end_headers();self.wfile.write(body)
    def do_GET(self):
        parsed=urlparse(self.path)
        if parsed.path=="/":
            body=PAGE.encode();self.send_response(200);self.send_header("Content-Type","text/html; charset=utf-8")
            self.send_header("Content-Security-Policy","default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'")
            self.send_header("X-Content-Type-Options","nosniff");self.send_header("Content-Length",str(len(body)));self.end_headers();self.wfile.write(body);return
        try:
            q=parse_qs(parsed.query);actor=parse_actor(q)
            if parsed.path=="/api/scenarios":return self.send_json(200,PLATFORM.scenarios(actor))
            if parsed.path=="/api/submissions":return self.send_json(200,PLATFORM.list_submissions(actor))
            if parsed.path=="/api/assessments":return self.send_json(200,PLATFORM.learner_assessments(actor))
            if parsed.path=="/api/stats":
                PLATFORM.require(actor,"scenario:read")
                return self.send_json(200,{"submissions":len(PLATFORM.submissions),"audit":PLATFORM.audit.verify()})
            if parsed.path=="/api/audit":return self.send_json(200,PLATFORM.audit_report(actor))
            return self.send_json(404,{"error":"not found"})
        except AuthorizationError as exc:return self.send_json(403,{"error":str(exc)})
        except ValueError as exc:return self.send_json(400,{"error":str(exc)})
    def do_POST(self):
        if self.path not in {"/api/submit","/api/grade","/api/scenario"}:return self.send_json(404,{"error":"not found"})
        try:
            size=int(self.headers.get("Content-Length","0"))
            if size>20000:return self.send_json(413,{"error":"request too large"})
            data=json.loads(self.rfile.read(size));a=data.get("actor",{})
            actor=Actor(str(a.get("username","anonymous"))[:80],Role(a.get("role","learner")))
            if self.path=="/api/submit":result=PLATFORM.submit(actor,data.get("scenario_id",""),data.get("evidence",{}))
            elif self.path=="/api/scenario":result=PLATFORM.create_scenario(actor,data.get("scenario",{}))
            else:result=PLATFORM.grade(actor,int(data.get("submission_id",0)),data.get("scores",{}),str(data.get("feedback","")))
            return self.send_json(201,result)
        except AuthorizationError as exc:return self.send_json(403,{"error":str(exc)})
        except (ValueError,TypeError,json.JSONDecodeError) as exc:return self.send_json(400,{"error":str(exc)})
    def log_message(self,*args):pass

def main():
    server=ThreadingHTTPServer(("127.0.0.1",8765),Handler)
    print("Sentinel Lab: http://127.0.0.1:8765 (loopback only; demo roles are not authentication)")
    try:server.serve_forever()
    except KeyboardInterrupt:print("\nStopping Sentinel Lab.")
    finally:server.server_close()

if __name__=="__main__":main()
