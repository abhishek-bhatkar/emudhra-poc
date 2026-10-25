#!/usr/bin/env python3
"""Never use real eMudhra keys; forging certificates with them is illegal in most jurisdictions."""

import datetime
import ipaddress
import os
import sys

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePrivateNumbers,
    EllipticCurvePublicNumbers,
)
from cryptography.x509.oid import NameOID

from weak_ec import G, scalar_mul

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "..")
KEYS = os.path.join(OUT, "keys")
TRUST = os.path.join(OUT, "trust")
os.makedirs(KEYS, exist_ok=True)
os.makedirs(TRUST, exist_ok=True)

NOW = datetime.datetime.now(datetime.timezone.utc)
LEAF_CN = "www.google.com"

WEAK_INTERMEDIATE_PRIVATE_SCALAR = 4


def pem(priv):
    return priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def write(path, data):
    with open(path, "wb") as f:
        f.write(data)
    print(f"  wrote {os.path.relpath(path, OUT)}")


def name(cn):
    return x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "IN"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "eMudhra PoC Lab"),
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
        ]
    )


def main():
    root_key = ec.generate_private_key(ec.SECP256R1())
    root_cert = (
        x509.CertificateBuilder()
        .subject_name(name("Lab Root CA - G3 (emSign-Like, PoC)"))
        .issuer_name(name("Lab Root CA - G3 (emSign-Like, PoC)"))
        .public_key(root_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW)
        .not_valid_after(NOW + datetime.timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
        .sign(root_key, hashes.SHA256())
    )
    write(os.path.join(KEYS, "root_ca_key.pem"), pem(root_key))
    root_pem = root_cert.public_bytes(serialization.Encoding.PEM)
    write(os.path.join(TRUST, "lab-root-ca.pem"), root_pem)

    pub_point = scalar_mul(WEAK_INTERMEDIATE_PRIVATE_SCALAR, G)
    weak_key = EllipticCurvePrivateNumbers(
        private_value=WEAK_INTERMEDIATE_PRIVATE_SCALAR,
        public_numbers=EllipticCurvePublicNumbers(
            pub_point[0], pub_point[1], ec.SECP256R1()
        ),
    ).private_key()
    inter_cert = (
        x509.CertificateBuilder()
        .subject_name(name("emSign-Like Intermediate - EV/OV/DV (PoC, weak key)"))
        .issuer_name(root_cert.subject)
        .public_key(weak_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW)
        .not_valid_after(NOW + datetime.timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(root_key, hashes.SHA256())
    )
    write(os.path.join(KEYS, "weak_intermediate_key.pem"), pem(weak_key))
    inter_pem = inter_cert.public_bytes(serialization.Encoding.PEM)
    write(os.path.join(TRUST, "lab-intermediate.pem"), inter_pem)
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf_cert = (
        x509.CertificateBuilder()
        .subject_name(name(LEAF_CN))
        .issuer_name(inter_cert.subject)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW)
        .not_valid_after(NOW + datetime.timedelta(days=30))
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName(LEAF_CN), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
            ),
            critical=False,
        )
        .sign(weak_key, hashes.SHA256())
    )
    write(os.path.join(KEYS, "leaf_key.pem"), pem(leaf_key))
    leaf_pem = leaf_cert.public_bytes(serialization.Encoding.PEM)
    write(os.path.join(TRUST, f"forged-{LEAF_CN}.pem"), leaf_pem + inter_pem)

    write(os.path.join(TRUST, "stale-ca-bundle.pem"), root_pem + inter_pem)

    other_key = ec.generate_private_key(ec.SECP256R1())
    other_cert = (
        x509.CertificateBuilder()
        .subject_name(name("Some Other Trust Anchor (Post-Purge)"))
        .issuer_name(name("Some Other Trust Anchor (Post-Purge)"))
        .public_key(other_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW)
        .not_valid_after(NOW + datetime.timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(other_key, hashes.SHA256())
    )
    other_pem = other_cert.public_bytes(serialization.Encoding.PEM)
    write(os.path.join(TRUST, "patched-ca-bundle.pem"), other_pem)

    print("\n[+] Lab PKI created. The 'compromised' intermediate key is now")
    print(f"    recoverable by anyone (see recover_key.py); the forged cert for")
    print(f"    {LEAF_CN} chains: leaf -> weak intermediate -> Lab Root CA.")


if __name__ == "__main__":
    sys.exit(main())
