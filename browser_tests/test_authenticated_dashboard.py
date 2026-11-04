import os,socket,subprocess,sys,tempfile,time,unittest,urllib.request,urllib.error
from pathlib import Path
from playwright.sync_api import sync_playwright
from identity import IdentityStore

class AuthenticatedBrowserTests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.tmp=tempfile.TemporaryDirectory();cls.port=8766
  db=str(Path(cls.tmp.name)/"browser.sqlite3")
  IdentityStore(db).create_user("browser-teacher","browser-test-password-long","instructor")
  env=os.environ.copy();env["SENTINEL_DB"]=db;env["ADMIN_LAB_AUDIT_FILE"]=str(Path(cls.tmp.name)/"audit.jsonl")
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
   self.assertFalse(page.locator("#workspace").is_visible())
   page.locator('input[name="username"]').fill("browser-teacher")
   page.locator('input[name="password"]').fill("browser-test-password-long")
   page.locator("#loginForm button").click()
   page.wait_for_selector("#workspace:not(.hidden)")
   self.assertIn("instructor",page.locator("#identity").inner_text())
   self.assertFalse(page.locator("#role").count())
   # A forged learner identity in the request body cannot reduce or elevate server identity.
   csrf=page.evaluate("csrf")
   result=page.evaluate("""async csrf => {let r=await fetch('/api/submit',{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':csrf},body:JSON.stringify({actor:{username:'attacker',role:'learner'},scenario_id:'identity-01',evidence:{}})});return r.status}""",csrf)
   self.assertEqual(result,403)
   no_csrf=page.evaluate("""async () => {let r=await fetch('/api/logout',{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'});return r.status}""")
   self.assertEqual(no_csrf,403)
   browser.close()

if __name__=="__main__":unittest.main()
