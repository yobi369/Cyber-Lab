"""Provision accounts from a trusted terminal; passwords are prompted, never CLI arguments."""
import argparse,getpass
from identity import IdentityStore
def main():
 p=argparse.ArgumentParser(description="Create or list Sentinel Lab users");p.add_argument("--db",default="sentinel-lab.sqlite3")
 sub=p.add_subparsers(dest="command",required=True)
 c=sub.add_parser("create-user");c.add_argument("username");c.add_argument("--role",choices=["learner","instructor","reviewer","auditor"],required=True)
 sub.add_parser("list-users");a=p.parse_args();store=IdentityStore(a.db)
 if a.command=="create-user":
  password=getpass.getpass("New password (12+ characters): ");confirm=getpass.getpass("Confirm password: ")
  if password!=confirm:raise SystemExit("Passwords do not match.")
  print(store.create_user(a.username,password,a.role))
 else:
  for user in store.list_users():print(user)
if __name__=="__main__":main()
