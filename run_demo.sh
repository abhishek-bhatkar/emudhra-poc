#!/usr/bin/env bash
# Lab-only full pipeline.
set -euo pipefail
cd "$(dirname "$0")"

echo "=============================================================="
echo " STEP 1: recreate the failure mode (weak-key CA, forged leaf)"
echo "=============================================================="
python3 poc/gen_weak_ca.py

echo
echo "=============================================================="
echo " STEP 2: show the key recovery is trivial from the public key"
echo "=============================================================="
python3 poc/recover_key.py

echo
echo "=============================================================="
echo " STEP 3: MITM the stale client, get blocked by the patched one"
echo "=============================================================="
python3 poc/mitm_demo.py

echo
echo "=============================================================="
echo " BONUS: openssl chain verification with each bundle"
echo "=============================================================="
echo "-- openssl verify against the STALE bundle (trusts emSign-like root):"
openssl verify -CAfile trust/stale-ca-bundle.pem trust/forged-www.google.com.pem
echo "-- openssl verify against the PATCHED bundle (root purged):"
openssl verify -CAfile trust/patched-ca-bundle.pem trust/forged-www.google.com.pem || true
