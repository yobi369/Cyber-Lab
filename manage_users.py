"""Provision accounts from a trusted terminal; passwords are prompted, never CLI arguments."""
import argparse,getpass
from identity import IdentityStore
from security_controls import new_totp_secret,totp_uri,verify_totp
def main():
 p=argparse.ArgumentParser(description="Create or list Sentinel Lab users");p.add_argument("--db",default="sentinel-lab.sqlite3")
 sub=p.add_subparsers(dest="command",required=True)
 c=sub.add_parser("create-user");c.add_argument("username");c.add_argument("--role",choices=["learner","instructor","reviewer","auditor"],required=True)
 m=sub.add_parser("enroll-mfa");m.add_argument("username")
 sub.add_parser("list-users");a=p.parse_args();store=IdentityStore(a.db)
 if a.command=="create-user":
  password=getpass.getpass("New password (12+ characters): ");confirm=getpass.getpass("Confirm password: ")
  if password!=confirm:raise SystemExit("Passwords do not match.")
  print(store.create_user(a.username,password,a.role))
 elif a.command=="enroll-mfa":
  secret=new_totp_secret();print("Add this TOTP URI to your authenticator:",totp_uri(secret,a.username))
  code=getpass.getpass("Enter the current six-digit authenticator code to confirm: ")
  if not verify_totp(secret,code):raise SystemExit("Code invalid; MFA was not enabled.")
  store.set_totp_secret(a.username,secret);print("MFA enabled for",a.username)
 else:
  for user in store.list_users():print(user)
if __name__=="__main__":main()
