"""Is the password stored in the keyring the one you use today?

Asks for your current Apple ID password (not echoed) and compares it with the
entry obsisync keeps in the keyring. Prints only "same" or "different": never
either password, its length or a hash. No network request, so no sign-in
attempt is spent.

    ~/scripts/obsisync/.venv/bin/python tools/compare_password.py
"""
import getpass
import hmac
import json
import os

import keyring

account = json.load(open(os.path.expanduser("~/.config/obsisync/config.json")))["apple_id"]
stored = keyring.get_password("obsisync", account)
if stored is None:
    raise SystemExit(f"no keyring entry for {account}")
typed = getpass.getpass(f"Current Apple ID password for {account}: ")
print("same" if hmac.compare_digest(stored, typed) else "different")
