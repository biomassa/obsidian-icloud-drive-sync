"""Compute Apple's SRP proof with obsisync's known-good implementation.

Reads one JSON object on stdin — the password travels on stdin, never argv:

    {"account", "password", "a", "salt", "B", "iterations", "protocol"}

(`a`, `salt` and `B` base64) and prints {"A", "M1", "M2"} as base64 JSON. This
is exactly what obsisync's icloudlite sends to Apple: pysrp's OpenSSL backend
(_ctsrp) with rfc5054_enable() and no_username_in_x(). The spike runs it on the
real challenge and refuses to send a proof the two implementations disagree on.
No network access.
"""
import base64
import json
import os
import sys

sys.path.insert(0, os.path.expanduser("~/scripts/obsisync"))

import srp  # noqa: E402

from icloudlite.srp_password import SrpPassword, SrpProtocolType  # noqa: E402


def main():
    req = json.load(sys.stdin)
    srp.rfc5054_enable()
    srp.no_username_in_x()
    pw = SrpPassword(req["password"])
    salt = base64.b64decode(req["salt"])
    pw.set_encrypt_info(salt, int(req["iterations"]), 32, SrpProtocolType(req["protocol"]))
    usr = srp.User(
        req["account"], pw, hash_alg=srp.SHA256, ng_type=srp.NG_2048,
        bytes_a=base64.b64decode(req["a"]),
    )
    _, A = usr.start_authentication()
    m1 = usr.process_challenge(salt, base64.b64decode(req["B"]))
    if m1 is None:
        raise SystemExit("SRP safety check failed")
    enc = lambda b: base64.b64encode(b).decode()
    print(json.dumps({"backend": srp.User.__module__, "A": enc(A), "M1": enc(m1), "M2": enc(usr.H_AMK)}))


if __name__ == "__main__":
    main()
