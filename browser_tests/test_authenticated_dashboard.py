import os,socket,subprocess,sys,tempfile,time,unittest,urllib.request,urllib.error
from pathlib import Path
from playwright.sync_api import sync_playwright
from identity import IdentityStore
from security_controls import new_totp_secret,totp_code

class AuthenticatedBrowserTests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.tmp=tempfile.TemporaryDirectory();cls.port=8766
  db=str(Path(cls.tmp.name)/"browser.sqlite3")
  store=IdentityStore(db);store.create_user("browser-teacher","browser-test-password-long","instructor")
  store.create_user("browser-mfa","browser-mfa-password-long","reviewer");cls.mfa_secret=new_totp_secret()
  env=os.environ.copy();env["SENTINEL_MFA_ENCRYPTION_KEY"]="ab"*32;store.set_totp_secret("browser-mfa",cls.mfa_secret)
  env["SENTINEL_DB"]=db;env["ADMIN_LAB_AUDIT_FILE"]=str(Path(cls.tmp.name)/"audit.jsonl")
  cls.server=subprocess.Popen([sys.executable,"dashboard.py"],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
  # Dashboard defaults to 8765; wait for its loopback listener.
  deadline=time.time()+15
  while time.time()<deadline:
   try:
    with urllib.request.urlopen("http://127.0.0.1:8765/api/me",timeout=1):pass
   except urllib.error.HTTPError as e:
    if e.code==401:break
   except Exception:time.sleep(.2)
  else:raise RuntimeError("dashboard did not start")
 @classmethod
 def tearDownClass(cls):
  cls.server.terminate();cls.server.wait(timeout=5);cls.tmp.cleanup()
 def test_login_csrf_and_server_side_role(self):
  with sync_playwright() as p:
   browser=p.chromium.launch()
   page=browser.new_page()
   page.goto("http://127.0.0.1:8765")
   self.assertTrue(page.locator("#login").is_visible())
   response=page.request.get("http://127.0.0.1:8765/")
   policy=response.headers.get("content-security-policy","")
   self.assertIn("script-src 'nonce-",policy)
   self.assertIn("style-src 'nonce-",policy)
   self.assertNotIn("unsafe-inline",policy)
   self.assertNotIn("unsafe-eval",policy)
   html=response.text()
   import re
   nonce=re.search(r'<script nonce="([^"]+)"',html).group(1)
   self.assertIn("script-src 'nonce-"+nonce+"'",policy)
   second=page.request.get("http://127.0.0.1:8765/")
   second_nonce=re.search(r'<script nonce="([^"]+)"',second.text()).group(1)
   self.assertNotEqual(nonce,second_nonce)
   self.assertFalse(page.locator("#workspace").is_visible())
   page.locator('input[name="username"]').fill("browser-teacher")
   page.locator('input[name="password"]').fill("browser-test-password-long")
   page.locator("#loginForm button").click()
   page.wait_for_selector("#workspace:not(.hidden)")
   self.assertIn("instructor",page.locator("#identity").inner_text())
   self.assertFalse(page.locator("#role").count())
   # A forged learner identity in the request body cannot reduce or elevate server identity.
   csrf=page.evaluate("async () => (await (await fetch('/api/me')).json()).csrf")
   result=page.evaluate("""async csrf => {let r=await fetch('/api/submit',{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':csrf},body:JSON.stringify({actor:{username:'attacker',role:'learner'},scenario_id:'identity-01',evidence:{}})});return r.status}""",csrf)
   self.assertEqual(result,403)
   no_csrf=page.evaluate("""async () => {let r=await fetch('/api/logout',{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'});return r.status}""")
   self.assertEqual(no_csrf,403)
   browser.close()

 def test_mfa_login_and_oidc_routes_fail_closed_when_unconfigured(self):
  with sync_playwright() as p:
   browser=p.chromium.launch();page=browser.new_page();page.goto("http://127.0.0.1:8765")
   page.locator('input[name="username"]').fill("browser-mfa")
   page.locator('input[name="password"]').fill("browser-mfa-password-long")
   page.locator('input[name="otp"]').fill(totp_code(self.mfa_secret))
   page.locator("#loginForm button").click();page.wait_for_selector("#workspace:not(.hidden)")
   self.assertIn("reviewer",page.locator("#identity").inner_text())
   self.assertEqual(page.request.get("http://127.0.0.1:8765/auth/oidc/start").status,503)
   self.assertEqual(page.request.get("http://127.0.0.1:8765/auth/oidc/callback?state=forged&code=x").status,400)
   browser.close()

if __name__=="__main__":unittest.main()
