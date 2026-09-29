"""Does `secret-tool` return the same password obsisync reads through Python keyring?

Prints only the backend name and whether the two values agree — never the
password, its length or a hash of it. Makes no network request.

    ~/scripts/obsisync/.venv/bin/python tools/check_keyring.py
"""
import hmac
import json
import os
import subprocess

import keyring

cfg = json.load(open(os.path.expanduser("~/.config/obsisync/config.json")))
account = cfg["apple_id"]

backend = keyring.get_keyring()
print("python keyring backend:", f"{type(backend).__module__}.{type(backend).__name__}")

via_keyring = keyring.get_password("obsisync", account)
try:
    via_secret_tool = subprocess.run(
        ["secret-tool", "lookup", "service", "obsisync", "username", account],
        capture_output=True, text=True, check=True,
    ).stdout
except subprocess.CalledProcessError:
    via_secret_tool = None

print("found by python keyring:", via_keyring is not None)
print("found by secret-tool:   ", via_secret_tool is not None)
if via_keyring is not None and via_secret_tool is not None:
    same = hmac.compare_digest(via_keyring, via_secret_tool)
    same_stripped = hmac.compare_digest(via_keyring, via_secret_tool.rstrip("\n"))
    print("identical:", same, "| identical after stripping a trailing newline:", same_stripped)
