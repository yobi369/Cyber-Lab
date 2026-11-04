"""Offline encrypted-database migration and key rotation utility.

Stop Sentinel Lab and take a verified backup before running either command.
"""
import argparse,os
from security_controls import migrate_sqlite_to_sqlcipher,rekey_sqlcipher_database

def main():
 p=argparse.ArgumentParser(description=__doc__)
 sub=p.add_subparsers(dest="command",required=True)
 enc=sub.add_parser("encrypt");enc.add_argument("plaintext_database");enc.add_argument("encrypted_destination")
 rotate=sub.add_parser("rekey");rotate.add_argument("encrypted_database")
 a=p.parse_args()
 if a.command=="encrypt":
  key=os.getenv("SENTINEL_DB_KEY","")
  if len(key)!=64:raise SystemExit("Set SENTINEL_DB_KEY to a new 256-bit hex key from your secret manager.")
  migrate_sqlite_to_sqlcipher(a.plaintext_database,a.encrypted_destination,key)
  print("Encrypted copy created. Verify it before switching the application database path.")
 else:
  old=os.getenv("SENTINEL_DB_OLD_KEY","");new=os.getenv("SENTINEL_DB_KEY","")
  if len(old)!=64 or len(new)!=64:raise SystemExit("Set SENTINEL_DB_OLD_KEY and SENTINEL_DB_KEY to distinct 256-bit hex keys.")
  if old==new:raise SystemExit("Old and new database keys must differ.")
  rekey_sqlcipher_database(a.encrypted_database,old,new)
  print("Database rekeyed and verified. Retain the old key until recovery validation completes.")
if __name__=="__main__":main()
