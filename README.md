# eMudhra / emSign "stale trust store" MITM PoC (lab-only)

A self-contained demo of why the October 2026 eMudhra/emSign intermediate-CA
key compromise matters for **real systems with frozen trust stores** — built
entirely with **our own throwaway keys**, never the real ones.

## What it demonstrates

1. **The failure mode** — a CA intermediate whose private key was generated
   with insufficient randomness (in the real incident, one key was reportedly
   the integer `4`). We recreate that with our own P-256 key whose scalar is
   `4`.
2. **Trivial key recovery** — from the intermediate's *public* key alone, the
   private scalar is brute-forced in seconds (poc/recover_key.py). This is
   what let a researcher prove possession of all 8 real keys by signing
   *"We have a problem here - Wayne"*.
3. **Forge & MITM** — a leaf certificate for `www.google.com` signed with the
   compromised intermediate key, served by an attacker endpoint.
   Two victims connect:
   - **stale** bundle (root still present, no revocation checks — the
     "everything that never updates" population) → handshake succeeds,
     attacker logs the traffic.
   - **patched** bundle (root purged, the OneCRL / NSS 3.131.1 / updated
     distro-bundle behavior) → handshake rejected, nothing captured.

## Run

```bash
./run_demo.sh            # or: pip install cryptography && python3 poc/gen_weak_ca.py && ...
```

Requires: Python 3.10+, `cryptography` (>= 3.1), curl, openssl.

## Mapping to the real incident

| PoC object | Real-world counterpart |
|---|---|
| Lab Root CA | emSign ECC Root CA - G3 (trusted root) |
| Weak intermediate (scalar=4) | 8 compromised emSign intermediates |
| recover_key.py | "Wayne"'s proof-of-possession to Mozilla/Chrome/Apple/MS root programs, Oct 17 2026 |
| patched-ca-bundle.pem | OneCRL / NSS 3.131.1 / Chrome / Apple / MS blocks (Oct 17–20) |
| Stale victim (curl with frozen bundle) | IoT firmware, Docker images, old JDKs, appliances, kiosks — anything shipping its own roots |

## Guardrails

- **Lab only.** All keys are generated locally, trusted by nobody.
- **Never use the real eMudhra/emSign keys.** Minting certificates with them
  is illegal in most jurisdictions, forensically loud (CT logs), and the keys
  are actively monitored by every root program.
- The `www.google.com` name is only honored because *we* redirect DNS with
  `curl --resolve` inside the lab; no external network is involved.

## Mitigation checklist (for your real estate)

- [ ] Rebuild Docker images / pin newer base images (fresh `ca-certificates`).
- [ ] Upgrade `certifi`, `pip`, `curl` bundles, JDK `cacerts`, Node (pending fix).
- [ ] Grep every bundled/pinned CA list for `emSign` / `eMudhra` roots —
      remove *explicitly*; don't wait for the device.
- [ ] Audit mTLS client-CA trust stores on gateways/load balancers.
- [ ] Assume unpatchable devices (printers, cameras, kiosks) are MITM-able on
      hostile networks; segment them.
