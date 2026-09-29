"""Generate parity vectors from obsisync's icloudlite, which works against Apple.

Run with obsisync's virtualenv:

    ~/scripts/obsisync/.venv/bin/python tools/gen_vectors.py

The TypeScript port is correct when it reproduces these values exactly. Nothing
here talks to the network.
"""
import base64
import json
import os
import sys

sys.path.insert(0, os.path.expanduser("~/scripts/obsisync"))

import srp  # noqa: E402
import srp._pysrp as pysrp  # noqa: E402

from icloudlite import hsa2_bridge as hb  # noqa: E402
from icloudlite import hsa2_bridge_prover as pv  # noqa: E402
from icloudlite.srp_password import SrpPassword, SrpProtocolType  # noqa: E402

OUT = os.path.join(os.path.dirname(__file__), "..", "test", "fixtures")


def b64(b):
    return base64.b64encode(b).decode()


def srp_vectors():
    # obsisync runs srp's OpenSSL backend (_ctsrp). Its M1/M2 are the ground
    # truth; the pure-Python backend supplies the intermediates, and the two
    # must agree or these vectors mean nothing.
    for backend in (srp, pysrp):
        backend.rfc5054_enable()
        backend.no_username_in_x()
    cases = []
    for i, (protocol, password, account) in enumerate([
        ("s2k", "correct horse battery staple", "someone@example.com"),
        ("s2k_fo", "pässwörd-ünïcode", "Other.Person@icloud.com"),
        ("s2k", "x", "a@b.c"),
    ]):
        # _ctsrp draws a 32-byte ephemeral; pysrp insists on 256 bytes, and the
        # zero-padded form is the same integer.
        a = bytes((i * 37 + j) % 256 for j in range(32))
        # The two backends disagree on a salt that starts with 0x00: _ctsrp hashes
        # it as a minimal bignum and drops the zero, pysrp hashes the raw bytes
        # (RFC 5054). The port follows the RFC; keep the leading byte non-zero
        # so the cross-check compares like with like.
        salt = bytes((i * 11 + j * 7 + 1) % 256 for j in range(16))
        iterations = 20000 + i * 1111
        # Any B in [1, N) exercises the client math; the server side is not needed.
        n, _ = pysrp.get_ng(srp.NG_2048, None, None)
        b_int = (int.from_bytes(bytes((i * 5 + j * 3 + 1) % 256 for j in range(256)), "big")) % n
        b_bytes = pysrp.long_to_bytes(b_int)

        pw = SrpPassword(password)
        pw.set_encrypt_info(salt, iterations, 32, SrpProtocolType(protocol))
        usr = srp.User(account, pw, hash_alg=srp.SHA256, ng_type=srp.NG_2048, bytes_a=a)
        _, A = usr.start_authentication()
        m1 = usr.process_challenge(salt, b_bytes)
        ref = pysrp.User(account, pw, hash_alg=pysrp.SHA256, ng_type=pysrp.NG_2048,
                         bytes_a=bytes(224) + a)
        _, A_ref = ref.start_authentication()
        m1_ref = ref.process_challenge(salt, b_bytes)
        assert (A, m1, usr.H_AMK) == (A_ref, m1_ref, ref.H_AMK), "srp backends disagree"
        cases.append({
            "account": account,
            "password": password,
            "protocol": protocol,
            "a": b64(a),
            "salt": b64(salt),
            "iterations": iterations,
            "B": b64(b_bytes),
            "A": b64(A),
            "derivedPassword": b64(pw.encode()),
            "u": format(ref.u, "x"),
            "x": format(ref.x, "x"),
            "S": format(ref.S, "x"),
            "K": b64(ref.K),
            "M1": b64(m1),
            "M2": b64(usr.H_AMK),
        })
    return cases


def spake2_vectors():
    """A full prover/verifier exchange with fixed scalars, as Apple's bridge runs it."""
    code = "123456"
    salt_b64 = b64(bytes(range(16)))
    w0, w1 = pv._compute_w0_w1(code, salt_b64)
    x_scalar = int("1d" * 31 + "07", 16) % pv._P256_ORDER
    y_scalar = int("3c" * 31 + "11", 16) % pv._P256_ORDER

    client = pv._ClientHandshake(x_scalar=x_scalar, w0=w0, w1=w1)
    server = pv._ServerHandshake(
        y_scalar=y_scalar, w0=w0, verifier_point=pv._multiply_point(pv._GENERATOR, w1))

    client_msg = client.get_message()
    server_msg = server.get_message()
    client_secret = client.finish(server_msg)
    server_secret = server.finish(client_msg)
    client_confirm = client_secret.get_confirmation()
    server_confirm = server_secret.get_confirmation()
    raw_key = client_secret.verify(server_confirm).hex()
    verifier_key, prover_key = pv._derive_prover_and_verifier_keys(raw_key)

    # The encrypted code Apple sends at the end, in its v0 AES-GCM layout.
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    iv = bytes(range(100, 112))
    sealed = AESGCM(bytes.fromhex(verifier_key)).encrypt(iv, b"987654", bytes([0]))
    ciphertext, tag = sealed[:-16], sealed[-16:]
    encrypted_code = b64(bytes([0]) + iv + tag + ciphertext)

    return {
        "code": code,
        "salt": salt_b64,
        "w0": format(w0, "x"),
        "w1": format(w1, "x"),
        "x": format(x_scalar, "x"),
        "clientMessage": client_msg,
        "serverMessage": server_msg,
        "clientConfirmation": client_confirm,
        "serverConfirmation": server_confirm,
        "rawKey": raw_key,
        "verifierKey": verifier_key,
        "proverKey": prover_key,
        "encryptedCode": encrypted_code,
        "decryptedCode": "987654",
    }


def protobuf_vectors():
    public_key = bytes([4]) + bytes(range(64))
    nonce = hb._build_nonce(1_700_000_000_123)[:9] + bytes(range(8))
    signature = bytes(range(70))
    push_payload = json.dumps({"sessionUUID": "abc-1", "nextStep": 2, "salt": "c2FsdA=="}).encode()
    server_frame = hb._encode_bytes_field(
        2,
        hb._encode_bytes_field(1, b"topic-bytes")
        + hb._encode_uint32_field(2, 300)
        + hb._encode_bytes_field(4, push_payload),
    )
    connection_frame = hb._encode_bytes_field(
        1,
        hb._encode_bytes_field(1, b"cHVzaHRva2Vu")
        + hb._encode_uint32_field(2, 0)
        + hb._encode_uint32_field(3, 1_700_000_000),
    )
    return {
        "publicKey": public_key.hex(),
        "nonce": nonce.hex(),
        "signature": signature.hex(),
        "connectionMessage": hb._encode_connection_message(public_key, nonce, signature).hex(),
        "webFilterMessage": hb._encode_web_filter_message(["com.apple.idmsauthwidget"]).hex(),
        "ackMessage": hb._encode_ack_message(b"topic-bytes", 300).hex(),
        "topicHash": hb._topic_hash("com.apple.idmsauthwidget"),
        "serverPushFrame": server_frame.hex(),
        "serverPushPayload": push_payload.decode(),
        "serverConnectionFrame": connection_frame.hex(),
    }


def main():
    os.makedirs(OUT, exist_ok=True)
    for name, data in [
        ("srp-vectors.json", srp_vectors()),
        ("spake2-vectors.json", spake2_vectors()),
        ("protobuf-vectors.json", protobuf_vectors()),
    ]:
        with open(os.path.join(OUT, name), "w") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
            f.write("\n")
        print("wrote", name)


if __name__ == "__main__":
    main()
