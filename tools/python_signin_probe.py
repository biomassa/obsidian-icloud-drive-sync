"""Does obsisync's own Python sign-in still work against Apple today?

One SRP sign-in with icloudlite, the reference the TypeScript port is checked
against. It spends ONE sign-in attempt, so run it only when a failure would be
acceptable. It:

- asks for the password (not echoed) instead of reading the keyring;
- uses a throwaway cookie directory, so obsisync's own session is untouched;
- never requests a 2FA code: icloudlite's automatic push+SMS is disabled, so an
  accepted password shows as "Apple asks for 2FA" and the challenge just lapses;
- prints the same names-only trace as the spike's --dry-run (cookie and header
  names, never values), so the two exchanges can be compared line by line.

    ~/scripts/obsisync/.venv/bin/python tools/python_signin_probe.py
"""
import getpass
import json
import os
import sys
import tempfile
import time
from urllib.parse import urlparse

sys.path.insert(0, os.path.expanduser("~/scripts/obsisync"))

import requests  # noqa: E402

from icloudlite.base import PyiCloudService  # noqa: E402
from icloudlite.exceptions import PyiCloudException  # noqa: E402

_real_send = requests.adapters.HTTPAdapter.send


def _traced_send(self, request, **kw):
    response = _real_send(self, request, **kw)
    url = urlparse(request.url)
    sent = [c.split("=")[0] for c in request.headers.get("Cookie", "").split("; ") if c]
    raw = response.raw.headers.getlist("Set-Cookie") if hasattr(response.raw, "headers") else []
    set_names = []
    for c in raw:
        attrs = {a.split("=")[0].strip().lower(): (a.split("=", 1)[1].strip() if "=" in a else "")
                 for a in c.split(";")[1:]}
        set_names.append(f"{c.split('=')[0]}@{attrs.get('domain', '(host)')}{attrs.get('path', '(default path)')}")
    apple = [h.lower() for h in response.headers if h.lower().startswith("x-apple") or h.lower() == "scnt"]
    stamp = time.strftime("%H:%M:%S")
    print(f"[{stamp}]   {request.method} {url.hostname}{url.path} -> {response.status_code}")
    print(f"[{stamp}]       cookies sent: [{', '.join(sent)}]  set: [{', '.join(set_names)}]")
    print(f"[{stamp}]       apple headers: [{', '.join(apple)}]")
    if response.status_code >= 400 and "signin/complete" in url.path:
        try:
            errors = response.json().get("serviceErrors") or []
            print(f"[{stamp}]       apple error codes: {[e.get('code') for e in errors]}")
        except ValueError:
            pass
    return response


requests.adapters.HTTPAdapter.send = _traced_send

account = json.load(open(os.path.expanduser("~/.config/obsisync/config.json")))["apple_id"]
password = getpass.getpass(f"Apple ID password for {account}: ")

api = PyiCloudService(account, password, cookie_directory=tempfile.mkdtemp(prefix="probe-"),
                      authenticate=False)
api._request_2fa_code = lambda: None  # never send a code from this probe

try:
    api._srp_authentication()
except PyiCloudException as exc:
    print(f"RESULT: REJECTED — {exc}")
    raise SystemExit(1)

if api._auth_data or api._requires_mfa or api.session.data.get("session_token"):
    print("RESULT: ACCEPTED — Apple took the password (2FA would follow; none was requested)")
else:
    print("RESULT: unclear — no error, but no session token either")
