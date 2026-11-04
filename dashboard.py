"""Authenticated loopback dashboard; no browser-supplied identity or role is trusted."""
from __future__ import annotations
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from http.cookies import SimpleCookie
from urllib.parse import urlparse,parse_qs
import json,os,secrets,base64
from identity import IdentityStore,SESSION_TTL
from audit_chain import AuditChain
from audit_archiver import AuditArchiveWorker
from storage import TrainingStore
from training_platform import Actor,Role,TrainingPlatform,AuthorizationError
from security_controls import tls_context,secure_cookie_attributes
from oidc import oidc_client_from_env,OIDCError

DB=os.getenv("SENTINEL_DB","sentinel-lab.sqlite3")
AUDIT_PATH=os.getenv("ADMIN_LAB_AUDIT_FILE","training-audit.jsonl")
IDENTITY=IdentityStore(DB)
PLATFORM=TrainingPlatform(AuditChain(AUDIT_PATH),TrainingStore(DB))
PAGE="""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Sentinel Lab</title>
<style>
:root{color-scheme:dark;--bg:#081321;--panel:#12243a;--line:#2a405c;--text:#edf4ff;--muted:#9eb2ca;--accent:#62d8c5}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at 85% 0,#1b3550,transparent 35%),var(--bg);color:var(--text);font:15px/1.55 system-ui,sans-serif}
header{padding:20px max(20px,calc((100% - 1160px)/2));border-bottom:1px solid var(--line);display:flex;justify-content:space-between;gap:16px;align-items:center;flex-wrap:wrap}
main{max-width:1160px;margin:28px auto;padding:0 20px}.brand{font-weight:850;letter-spacing:.12em}.brand b,.eyebrow,.tag{color:var(--accent)}.muted{color:var(--muted)}h1{font-size:clamp(26px,4vw,38px);margin:7px 0}h2{font-size:18px;margin:0 0 12px}
.panel,.scenario,.stat{background:linear-gradient(145deg,#172a43,#111d30);border:1px solid var(--line);border-radius:15px;padding:17px}.stats{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin:18px 0}.stat strong{display:block;font-size:27px}
.layout{display:grid;grid-template-columns:minmax(250px,.8fr) minmax(0,1.5fr);gap:16px}.scenario{margin:10px 0;cursor:pointer}.scenario.active{border-color:var(--accent)}.tag{font-size:11px;text-transform:uppercase}
.artifact{background:#0c1828;border-radius:9px;padding:10px;margin:7px 0;color:#c9d8e9}label{display:block;margin:12px 0 5px;color:#c3d0e1;font-size:13px}
input,select,textarea,button{font:inherit;border:1px solid var(--line);border-radius:9px;padding:10px 12px;background:#0c1828;color:var(--text)}input,textarea{width:100%}textarea{min-height:76px}button{background:var(--accent);color:#061a1a;font-weight:750;border:0;cursor:pointer}button.secondary{background:#203651;color:var(--text);border:1px solid var(--line)}.row{display:flex;gap:9px;align-items:center;flex-wrap:wrap}.hidden{display:none!important}#message{min-height:24px;color:var(--accent);margin:12px 0}.notice{padding:12px;border:1px solid #705b31;background:#2a2419;color:#f3dca8;border-radius:12px;margin:18px 0}
footer{max-width:1160px;margin:26px auto;padding:0 20px 24px;color:var(--muted);font-size:12px}@media(max-width:740px){.layout,.stats{grid-template-columns:1fr}header{display:block}}
</style></head><body><header><div><div class="brand">◈ SENTINEL <b>LAB</b></div><div class="muted">Defensive cybersecurity training workspace</div></div><div id="account" class="row hidden"><span id="identity"></span><button id="logout" class="secondary">Sign out</button></div></header>
<main><section id="login" class="panel"><div class="eyebrow">Secure access</div><h1>Sign in to Sentinel Lab</h1><p class="muted">Accounts and roles are provisioned by an administrator.</p><form id="loginForm"><label>Username</label><input name="username" autocomplete="username" required maxlength="80"><label>Password</label><input name="password" type="password" autocomplete="current-password" required maxlength="256"><label>Authenticator code (required when MFA is enrolled)</label><input name="otp" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" maxlength="6"><p><button>Sign in</button></p></form><p><a class="secondary" href="/auth/oidc/start">Continue with enterprise SSO</a></p></section>
<section id="workspace" class="hidden"><div class="eyebrow">Training operations / authenticated session</div><h1>Incident response workspace</h1><div class="muted">Investigate synthetic incidents. Submit evidence. Learn through structured feedback.</div>
<div class="notice">SIMULATION ONLY · Synthetic evidence. No scanning, malware, remote access, or real system changes.</div>
<div class="stats"><div class="stat"><span class="muted">Scenario library</span><strong id="scenarioCount">—</strong></div><div class="stat"><span class="muted">Evidence submissions</span><strong id="submissionCount">—</strong></div><div class="stat"><span class="muted">Audit integrity</span><strong id="auditState">Pending</strong><span id="auditMeta" class="muted"></span></div></div>
<div class="layout"><section class="panel"><h2>Scenario library</h2><div class="muted">Published exercises and authorized drafts.</div><div id="scenarios"></div></section>
<section class="panel"><div id="category" class="eyebrow">Select a scenario</div><h2 id="title">Training brief</h2><p id="brief" class="muted">Choose a scenario.</p><h3>Objectives</h3><ul id="objectives"></ul><h3>Evidence pack</h3><div id="artifacts"></div><p id="boundary" class="muted"></p>
<div id="submitPanel" class="hidden"><h3>Evidence submission</h3><form id="evidence"><label>Observations (facts vs assumptions)</label><textarea name="observations" required maxlength="4000"></textarea><label>Incident timeline</label><textarea name="timeline" required maxlength="4000"></textarea><label>Containment and escalation</label><textarea name="actions" required maxlength="4000"></textarea><label>Reasoning and uncertainty</label><textarea name="rationale" required maxlength="4000"></textarea><label>Confidence and justification</label><textarea name="confidence" required maxlength="4000"></textarea><label>Remediation and validation</label><textarea name="remediation" required maxlength="4000"></textarea><p><button>Submit evidence</button></p></form></div>
<div id="authorPanel" class="hidden"><h3 id="authorTitle">Create scenario draft</h3><form id="scenarioForm"><label>Scenario title</label><input name="title" required maxlength="100"><label>Category</label><input name="category" required maxlength="60"><label>Difficulty</label><select name="level"><option>Foundation</option><option>Intermediate</option><option>Advanced</option></select><label>Incident brief</label><textarea name="brief" required maxlength="1000"></textarea><label>Learning objectives (one per line; 2–8)</label><textarea name="objectives" required></textarea><label>Synthetic evidence artifacts (one per line)</label><textarea name="artifacts" required></textarea><label>Safety boundary</label><textarea name="safe_boundary" required maxlength="1000"></textarea><p class="row"><button>Save draft/version</button><button type="button" id="resetScenario" class="secondary">New draft</button></p></form></div>
<div id="learnerResults" class="hidden"><h3>My assessment results</h3><div id="results"></div></div><div id="reviewPanel" class="hidden"><h3>Review queue</h3><div id="queue"></div></div><div id="message" role="status"></div><button class="secondary" id="verify">Verify audit integrity</button></section></div></section></main>
<footer>Local training prototype. Do not expose publicly or enter real customer, personal, or production security data.</footer>
<script>
let items=[],selected=null,user=null,csrf='';
const el=id=>document.getElementById(id);
async function api(path,options={}){let headers={'Content-Type':'application/json',...(options.headers||{})};if(csrf)headers['X-CSRF-Token']=csrf;let r=await fetch(path,{...options,credentials:'same-origin',headers});let d=await r.json();if(!r.ok)throw Error(d.error||'Request failed');return d}
function say(s){el('message').textContent=s}
function showApp(){el('login').classList.add('hidden');el('workspace').classList.remove('hidden');el('account').classList.remove('hidden');el('identity').textContent=user.username+' · '+user.role}
function choose(s){selected=s;el('category').textContent=s.category+' / '+s.level+' · v'+s.version+' · '+s.status;el('title').textContent=s.title;el('brief').textContent=s.brief;el('objectives').replaceChildren(...s.objectives.map(t=>{let n=document.createElement('li');n.textContent=t;return n}));el('artifacts').replaceChildren(...s.artifacts.map(t=>{let n=document.createElement('div');n.className='artifact';n.textContent=t;return n}));el('boundary').textContent=s.safe_boundary;document.querySelectorAll('.scenario').forEach(n=>n.classList.toggle('active',n.dataset.id===s.id+'@'+s.version));el('submitPanel').classList.toggle('hidden',user.role!=='learner'||s.status!=='published');}
async function stats(){let d=await api('/api/stats');el('submissionCount').textContent=d.submissions;el('auditState').textContent=d.audit.valid?'Valid':'Alert';el('auditMeta').textContent=d.audit.events+' events · '+d.audit.head.slice(0,12)}
async function queue(){let q=await api('/api/submissions');el('reviewPanel').classList.remove('hidden');el('queue').replaceChildren(...q.map(x=>{let d=document.createElement('div');d.className='artifact';let t=document.createElement('span');t.textContent='#'+x.id+' · '+x.learner+' · '+x.scenario_id+' · '+x.status;d.append(t);if(x.review_count<2){let b=document.createElement('button');b.className='secondary';b.textContent=x.review_count?'Second review':'Review';b.onclick=()=>grade(x.id);d.append(b)}let m=document.createElement('button');m.className='secondary';m.textContent='Moderation';m.onclick=()=>moderate(x.id);d.append(m);return d}))}
async function moderate(id){try{let r=await api('/api/moderation?id='+id);say(JSON.stringify(r))}catch(e){say(e.message)}}
async function grade(id){let keys=['evidence_quality','reasoning','containment','preservation','remediation'],scores={};for(let k of keys){let v=prompt(k+' score (0–4)');if(v===null)return;scores[k]=Number(v)}let feedback=prompt('Evidence-linked written feedback:');if(feedback===null)return;try{let r=await api('/api/grade',{method:'POST',body:JSON.stringify({submission_id:id,scores,feedback})});say('Review recorded: '+r.total+'/20');await queue();await stats()}catch(e){say(e.message)}}
async function learnerResults(){let a=await api('/api/assessments');el('learnerResults').classList.remove('hidden');el('results').replaceChildren(...a.map(x=>{let d=document.createElement('div');d.className='artifact';d.textContent='Submission #'+x.submission_id+' · '+x.total+'/20 · '+x.feedback;return d}))}
async function load(){try{items=await api('/api/scenarios');el('scenarioCount').textContent=items.length;el('scenarios').replaceChildren(...items.map(s=>{let d=document.createElement('div');d.className='scenario';d.dataset.id=s.id+'@'+s.version;let tag=document.createElement('div');tag.className='tag';tag.textContent=s.level+' / '+s.category+' · '+s.status+' · v'+s.version;let title=document.createElement('h3');title.textContent=s.title;let p=document.createElement('div');p.className='muted';p.textContent=s.brief.slice(0,100)+'…';d.append(tag,title,p);d.onclick=()=>choose(s);if(user.role==='instructor'&&s.id.startsWith('custom-')){let edit=document.createElement('button');edit.className='secondary';edit.textContent='Edit version';edit.onclick=e=>{e.stopPropagation();selected=s;el('authorTitle').textContent='Edit '+s.id+' · create new version';for(let k of ['title','category','level','brief','safe_boundary'])el('scenarioForm').elements[k].value=s[k];el('scenarioForm').elements.objectives.value=s.objectives.join(String.fromCharCode(10));el('scenarioForm').elements.artifacts.value=s.artifacts.join(String.fromCharCode(10));el('authorPanel').scrollIntoView({behavior:'smooth'})};d.append(edit)}if(user.role==='instructor'&&s.status==='draft'){let b=document.createElement('button');b.textContent='Publish';b.onclick=async e=>{e.stopPropagation();try{await api('/api/publish',{method:'POST',body:JSON.stringify({scenario_id:s.id,version:s.version})});say('Published '+s.id+' v'+s.version);await load()}catch(x){say(x.message)}};d.append(b)}return d}));if(items.length)choose(items[0]);el('authorPanel').classList.toggle('hidden',user.role!=='instructor');if(user.role==='learner')await learnerResults();else el('learnerResults').classList.add('hidden');if(['instructor','reviewer'].includes(user.role))await queue();else el('reviewPanel').classList.add('hidden');await stats()}catch(e){say(e.message)}}
async function boot(){try{let m=await api('/api/me');user=m.user;csrf=m.csrf;showApp();await load()}catch(e){el('login').classList.remove('hidden');el('workspace').classList.add('hidden')}}
el('loginForm').onsubmit=async e=>{e.preventDefault();let data=Object.fromEntries(new FormData(e.target).entries());try{let r=await api('/api/login',{method:'POST',body:JSON.stringify(data)});user=r.user;csrf=r.csrf;showApp();await load()}catch(x){say(x.message);let p=el('login').querySelector('.muted');p.textContent=x.message}};
el('logout').onclick=async()=>{try{await api('/api/logout',{method:'POST',body:'{}'})}finally{user=null;csrf='';location.reload()}};
el('scenarioForm').onsubmit=async e=>{e.preventDefault();let data=Object.fromEntries(new FormData(e.target).entries());data.objectives=data.objectives.split(String.fromCharCode(10)).map(x=>x.trim()).filter(Boolean);data.artifacts=data.artifacts.split(String.fromCharCode(10)).map(x=>x.trim()).filter(Boolean);try{let body={scenario:data};let path='/api/scenario';if(selected&&selected.id.startsWith('custom-')&&user.role==='instructor'){body.scenario_id=selected.id;path='/api/scenario/edit'}let created=await api(path,{method:'POST',body:JSON.stringify(body)});say('Saved draft '+created.id+' v'+created.version);e.target.reset();selected=null;await load()}catch(x){say(x.message)}};
el('resetScenario').onclick=()=>{selected=null;el('scenarioForm').reset();el('authorTitle').textContent='Create scenario draft'};
el('evidence').onsubmit=async e=>{e.preventDefault();if(!selected)return;try{await api('/api/submit',{method:'POST',body:JSON.stringify({scenario_id:selected.id,evidence:Object.fromEntries(new FormData(e.target).entries())})});say('Evidence submitted for review.');e.target.reset();await stats()}catch(x){say(x.message)}};
el('verify').onclick=async()=>{try{let r=await api('/api/audit');say(r.valid?'Audit chain verified · '+r.events+' events':'INTEGRITY FAILURE · '+r.reason)}catch(e){say(e.message)}};
boot();
</script></body></html>"""

def cookie_token(handler):
 c=SimpleCookie();c.load(handler.headers.get("Cookie",""));return c["sentinel_session"].value if "sentinel_session" in c else None
class Handler(BaseHTTPRequestHandler):
 def send_json(self,status,payload,headers=None):
  body=json.dumps(payload).encode();self.send_response(status);self.send_header("Content-Type","application/json; charset=utf-8");self.send_header("Content-Length",str(len(body)));self.send_header("Cache-Control","no-store");self.send_header("X-Content-Type-Options","nosniff");self.send_header("Referrer-Policy","no-referrer");self.send_header("Permissions-Policy","camera=(), microphone=(), geolocation=()");
  if getattr(self.server,"tls_enabled",False):self.send_header("Strict-Transport-Security","max-age=31536000; includeSubDomains")
  for k,v in (headers or {}).items():self.send_header(k,v)
  self.end_headers();self.wfile.write(body)
 def session(self):return IDENTITY.session(cookie_token(self))
 def actor(self,s):return Actor(s["username"],Role(s["role"]))
 def body(self):
  size=int(self.headers.get("Content-Length","0"))
  if size<1 or size>20000:raise ValueError("request body must be 1–20000 bytes")
  return json.loads(self.rfile.read(size))
 def do_GET(self):
  path=urlparse(self.path)
  if path.path=="/auth/oidc/start":
   try:
    client=oidc_client_from_env();url,state,nonce,verifier=client.begin()
    IDENTITY.create_oidc_transaction(state,nonce,verifier)
    self.send_response(302);self.send_header("Location",url);self.send_header("Cache-Control","no-store");self.end_headers();return
   except OIDCError as exc:return self.send_json(503,{"error":str(exc)})
  if path.path=="/auth/oidc/callback":
   query=parse_qs(path.query);state=query.get("state",[""])[0];code=query.get("code",[""])[0]
   transaction=IDENTITY.consume_oidc_transaction(state) if state else None
   if not transaction:return self.send_json(400,{"error":"OIDC state invalid, expired, or already used"})
   try:
    result=oidc_client_from_env().complete(code,transaction["code_verifier"],transaction["nonce"])
    session=IDENTITY.create_oidc_session(result["issuer"],result["subject"])
    if not session:return self.send_json(403,{"error":"identity is not linked to a provisioned Sentinel account"})
    self.send_response(302);self.send_header("Location","/");self.send_header("Cache-Control","no-store")
    self.send_header("Set-Cookie",f"sentinel_session={session['token']}; {secure_cookie_attributes()}; Max-Age={SESSION_TTL}")
    self.end_headers();return
   except (OIDCError,ValueError) as exc:return self.send_json(401,{"error":str(exc)})
  if path.path=="/":
   nonce=base64.urlsafe_b64encode(secrets.token_bytes(24)).decode().rstrip('=');html=PAGE.replace('<style>','<style nonce="'+nonce+'">').replace('<script>','<script nonce="'+nonce+'">');body=html.encode();self.send_response(200);self.send_header("Content-Type","text/html; charset=utf-8");self.send_header("Content-Length",str(len(body)));self.send_header("Content-Security-Policy","default-src 'self'; style-src 'nonce-"+nonce+"'; script-src 'nonce-"+nonce+"'; connect-src 'self'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'; form-action 'self'");self.send_header("X-Content-Type-Options","nosniff");self.send_header("Referrer-Policy","no-referrer");self.send_header("Permissions-Policy","camera=(), microphone=(), geolocation=()");
   if getattr(self.server,"tls_enabled",False):self.send_header("Strict-Transport-Security","max-age=31536000; includeSubDomains")
   self.send_header("Cache-Control","no-store");self.end_headers();self.wfile.write(body);return
  if path.path=="/api/me":
   s=self.session()
   return self.send_json(200,{"user":{"username":s["username"],"role":s["role"]},"csrf":s["csrf"]}) if s else self.send_json(401,{"error":"authentication required"})
  s=self.session()
  if not s:return self.send_json(401,{"error":"authentication required"})
  a=self.actor(s)
  try:
   if path.path=="/api/scenarios":return self.send_json(200,PLATFORM.scenarios(a))
   if path.path=="/api/submissions":return self.send_json(200,PLATFORM.list_submissions(a))
   if path.path=="/api/assessments":return self.send_json(200,PLATFORM.learner_assessments(a))
   if path.path=="/api/stats":
    PLATFORM.require(a,"scenario:read");return self.send_json(200,{"submissions":len(PLATFORM.store.submissions()),"audit":PLATFORM.audit.verify()})
   if path.path=="/api/audit":return self.send_json(200,PLATFORM.audit_report(a))
   if path.path=="/api/moderation":return self.send_json(200,PLATFORM.moderation_report(a,int(dict([x.split("=") for x in path.query.split("&") if "=" in x]).get("id","0"))))
   return self.send_json(404,{"error":"not found"})
  except AuthorizationError as e:return self.send_json(403,{"error":str(e)})
  except (ValueError,TypeError) as e:return self.send_json(400,{"error":str(e)})
 def do_POST(self):
  origin=self.headers.get('Origin')
  expected=os.getenv('SENTINEL_PUBLIC_ORIGIN') or (('https://' if getattr(self.server,'tls_enabled',False) else 'http://')+self.headers.get('Host',''))
  if origin and origin!=expected:return self.send_json(403,{'error':'origin validation failed'})
  path=urlparse(self.path).path
  try:data=self.body()
  except (ValueError,json.JSONDecodeError) as e:return self.send_json(400,{"error":str(e)})
  if path=="/api/login":
   remote=self.client_address[0]
   if IDENTITY.login_locked(remote):return self.send_json(429,{"error":"too many login attempts; wait five minutes"})
   result=IDENTITY.authenticate(str(data.get("username","")),str(data.get("password","")),str(data.get("otp","")))
   if not result:
    IDENTITY.record_login_failure(remote)
    return self.send_json(401,{"error":"invalid username or password"})
   IDENTITY.clear_login_failures(remote)
   return self.send_json(200,{"user":{"username":result["username"],"role":result["role"]},"csrf":result["csrf"]},{"Set-Cookie":f"sentinel_session={result['token']}; {secure_cookie_attributes()}; Max-Age={SESSION_TTL}"})
  token=cookie_token(self);s=IDENTITY.session(token)
  if not s:return self.send_json(401,{"error":"authentication required"})
  if not IDENTITY.verify_csrf(s,self.headers.get("X-CSRF-Token","")):return self.send_json(403,{"error":"CSRF validation failed"})
  if path=="/api/logout":
   IDENTITY.logout(token);return self.send_json(200,{"ok":True},{"Set-Cookie":"sentinel_session=; "+secure_cookie_attributes()+"; Max-Age=0"})
  a=self.actor(s)
  try:
   if path=="/api/submit":result=PLATFORM.submit(a,data.get("scenario_id",""),data.get("evidence",{}))
   elif path=="/api/grade":result=PLATFORM.grade(a,int(data.get("submission_id",0)),data.get("scores",{}),str(data.get("feedback","")))
   elif path=="/api/scenario":result=PLATFORM.create_scenario(a,data.get("scenario",{}))
   elif path=="/api/scenario/edit":result=PLATFORM.edit_scenario(a,data.get("scenario_id",""),data.get("scenario",{}))
   elif path=="/api/publish":result=PLATFORM.publish_scenario(a,data.get("scenario_id",""),int(data.get("version",0)))
   else:return self.send_json(404,{"error":"not found"})
   return self.send_json(201,result)
  except AuthorizationError as e:return self.send_json(403,{"error":str(e)})
  except (ValueError,TypeError) as e:return self.send_json(400,{"error":str(e)})
 def log_message(self,*args):pass

def main():
 server=ThreadingHTTPServer((os.getenv("SENTINEL_BIND","127.0.0.1"),int(os.getenv("SENTINEL_PORT","8765"))),Handler)
 context=tls_context()
 archive_worker=None
 bucket=os.getenv("SENTINEL_AUDIT_S3_BUCKET")
 if os.getenv("SENTINEL_REQUIRE_EXTERNAL_AUDIT")=="1" and not bucket: raise RuntimeError("production policy requires SENTINEL_AUDIT_S3_BUCKET")
 if bucket:
  secret=os.getenv("SENTINEL_AUDIT_HMAC_KEY","")
  if len(secret)<32: raise RuntimeError("external audit archiving requires SENTINEL_AUDIT_HMAC_KEY")
  archive_worker=AuditArchiveWorker(AUDIT_PATH,bucket,secret,os.getenv("SENTINEL_AUDIT_KEY_ID","default"),int(os.getenv("SENTINEL_AUDIT_RETENTION_DAYS","365")),int(os.getenv("SENTINEL_AUDIT_ARCHIVE_INTERVAL_SECONDS","300")))
  archive_worker.start()
 if context:
  server.socket=context.wrap_socket(server.socket,server_side=True);server.tls_enabled=True
 else:server.tls_enabled=False
 scheme="https" if context else "http"
 print(f"Sentinel Lab: {scheme}://{server.server_address[0]}:{server.server_address[1]} (authenticated sessions)")
 try:server.serve_forever()
 except KeyboardInterrupt:print("\nStopping Sentinel Lab.")
 finally:
  if archive_worker:archive_worker.stop()
  server.server_close()
if __name__=="__main__":main()
