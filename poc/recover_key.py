#!/usr/bin/env python3
import argparse
import os
import sys
import time

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from weak_ec import G, bsgs, scalar_mul

MAX_TRIVIAL_SCALAR_BITS = 24
MAX_DEMO_BITS = 32


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
    if args.bits < 0 or args.bits > MAX_DEMO_BITS:
        ap.error("--bits must be between 0 and {}".format(MAX_DEMO_BITS))

    if args.bits:
        import random

        d = random.getrandbits(args.bits - 1) | (1 << (args.bits - 1))
        print(f"[*] Simulating an intermediate whose scalar is only {args.bits} bits (d = {d})")
        target = scalar_mul(d, G)
        bound = 1 << args.bits
    else:
        print("[*] Loading public key of the 'compromised' intermediate from")
        print(f"    {os.path.relpath(args.cert)}")
        target = load_pub_point(args.cert)
        bound = 1 << MAX_TRIVIAL_SCALAR_BITS

    print("[*] Searching for private scalar: candidate d -> d*G == public key ?")
    t0 = time.perf_counter()
    found = bsgs(target, bound)
    dt = time.perf_counter() - t0
    if found is None:
        print(f"[-] Not found under 2^{max(args.bits, MAX_TRIVIAL_SCALAR_BITS)} after {dt:.2f}s")
        return 1
    print(f"[+] PRIVATE KEY RECOVERED: d = {found}   (0x{found:x})")
    print(f"[+] recovered in {dt:.3f} seconds using baby-step giant-step from the PUBLIC key")
    print("[+] Search cost is O(sqrt(bound)) operations and memory; 32 bits needs about 2 x 2^16 point operations.")
    print("[+] An attacker can now sign fraudulent certificates with this CA key.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
