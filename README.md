# eMudhra MITM PoC

Demo of the [Oct 2026 eMudhra/emSign CA incident](https://blog.mozilla.org/security/2026/10/20/protecting-firefox-users-following-the-compromise-of-emudhra-intermediate-certificates/): intermediate CA keys were so weak (one was literally `4`) that anyone could recover them from the public key and forge trusted certs. Patched browsers are fine — **anything with a frozen trust store isn't**.

This repo recreates the flaw with **our own throwaway keys** (never the real ones) and shows the impact.

## Run

```bash
pip install cryptography
./run_demo.sh
```

## How it works

```mermaid
flowchart TB
    M["Build a CA with a weak key (private key = 4)"] --> P["Recover the private key<br/>from the public key in seconds"]
    P --> F["Forge a cert for www.google.com<br/>using the recovered key"]
    F --> S["Victim with STALE trust store<br/>❌ accepts the forgery — attacker reads traffic"]
    F --> T["Victim with PATCHED store<br/>✅ rejects it — attacker gets nothing"]
```

**In one sentence:** we forge a CA certificate the way the real attacker could, then show one client accepting it (stale trust store) and one rejecting it (patched).

The chain being tested:

```
www.google.com (forged)  ←  weak intermediate (key = 4)  ←  root trusted before Oct 20
```

- STALE — store never updated → forgery validates → MITM works
- PATCHED — root removed (like OneCRL) → forgery rejected → safe

## What each script does

| Script | One-liner |
|---|---|
| `gen_weak_ca.py` | Builds a lab CA, weak-key intermediate, forged cert + the two trust bundles |
| `recover_key.py` | Brute-forces the weak private key from the public key alone |
| `mitm_demo.py` | Attacker HTTPS server + two curl victims (stale vs patched bundles) |

## Mapping to the real incident

| Here | Real world |
|---|---|
| Lab Root CA | emSign ECC Root CA - G3 |
| Weak intermediate (key=4) | 8 compromised emSign intermediates |
| `recover_key.py` | Researcher "Wayne" proving key possession, Oct 17 |
| Patched bundle | OneCRL / NSS 3.131.1 blocks, Oct 17–20 |
| Stale victim | Docker images, old JDKs, IoT firmware, kiosks |

## Rules

- Lab only — keys are local, trusted by nobody, DNS faked with `curl --resolve`.
- Never use the real eMudhra/emSign keys — illegal, CT-logged, monitored.

## If you maintain systems

- [ ] Rebuild Docker images / bump base images
- [ ] Update `certifi`, pip bundles, JDK `cacerts`, Node
- [ ] Grep pinned CA lists for `emSign` / `eMudhra`, remove them
- [ ] Audit mTLS client-CA stores on gateways
- [ ] Segment unpatchable devices (printers, cameras, kiosks)
