"""Provision accounts from a trusted terminal; passwords are prompted, never CLI arguments."""
import argparse,getpass,os
from identity import IdentityStore
from security_controls import new_totp_secret,totp_uri,verify_totp
def main():
 p=argparse.ArgumentParser(description="Create or list Sentinel Lab users");p.add_argument("--db",default="sentinel-lab.sqlite3")
 sub=p.add_subparsers(dest="command",required=True)
 c=sub.add_parser("create-user");c.add_argument("username");c.add_argument("--role",choices=["learner","instructor","reviewer","auditor"],required=True)
 m=sub.add_parser("enroll-mfa");m.add_argument("username")
 o=sub.add_parser("link-oidc");o.add_argument("username");o.add_argument("--issuer",required=True);o.add_argument("--subject",required=True)
 sub.add_parser("rotate-mfa-key")
 sub.add_parser("list-users");a=p.parse_args();store=IdentityStore(a.db)
 if a.command=="create-user":
  password=getpass.getpass("New password (12+ characters): ");confirm=getpass.getpass("Confirm password: ")
  if password!=confirm:raise SystemExit("Passwords do not match.")
  print(store.create_user(a.username,password,a.role))
 elif a.command=="rotate-mfa-key":
  old=os.getenv("SENTINEL_MFA_OLD_ENCRYPTION_KEY","");new=os.getenv("SENTINEL_MFA_ENCRYPTION_KEY","")
  if not old or not new:raise SystemExit("Set SENTINEL_MFA_OLD_ENCRYPTION_KEY and SENTINEL_MFA_ENCRYPTION_KEY from your secret manager.")
  print("Re-encrypted MFA seeds:",store.rotate_mfa_encryption_key(old,new))
 elif a.command=="link-oidc":
  store.link_oidc_identity(a.username,a.issuer,a.subject);print("Linked immutable OIDC subject to",a.username)
 elif a.command=="enroll-mfa":
  secret=new_totp_secret();print("Add this TOTP URI to your authenticator:",totp_uri(secret,a.username))
  code=getpass.getpass("Enter the current six-digit authenticator code to confirm: ")
  if not verify_totp(secret,code):raise SystemExit("Code invalid; MFA was not enabled.")
  store.set_totp_secret(a.username,secret);print("MFA enabled for",a.username)
 else:
  for user in store.list_users():print(user)
if __name__=="__main__":main()
