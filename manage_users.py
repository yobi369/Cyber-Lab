"""Provision Sentinel Lab accounts from a trusted terminal, never from the browser."""
import argparse
from identity import IdentityStore

def main():
 p=argparse.ArgumentParser(description="Create or list Sentinel Lab users")
 p.add_argument("--db",default="sentinel-lab.sqlite3")
 sub=p.add_subparsers(dest="command",required=True)
 c=sub.add_parser("create-user");c.add_argument("username");c.add_argument("--role",choices=["learner","instructor","reviewer","auditor"],required=True);c.add_argument("--password",required=True)
 sub.add_parser("list-users")
 a=p.parse_args();store=IdentityStore(a.db)
 if a.command=="create-user":print(store.create_user(a.username,a.password,a.role))
 else:
  for user in store.list_users():print(user)
if __name__=="__main__":main()
