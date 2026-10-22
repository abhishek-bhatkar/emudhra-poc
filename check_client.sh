#!/usr/bin/env bash
# Test this client's trust store against the real eMudhra incident hosts.
# macOS curl: exit 0 = chain accepted = vulnerable, exit 60 = TLS verify failed = safe.
set -u

HOSTS=(
  "https://dv-g3b-emudhra.we-have-a-problem.com/"
  "https://dv-g3b-aaa-emudhra.we-have-a-problem.com/"
)

verdicts=()
fail=0
safe=0
for url in "${HOSTS[@]}"; do
  body=$(mktemp)
  curl -q -sS -o "$body" -m 20 "$url" 2>/dev/null
  rc=$?
  case $rc in
    0)
      verdict="VULNERABLE  client accepted the forged chain"
      fail=1 ;;
    60)
      verdict="SAFE        client rejected TLS (exit 60) - for these hosts that means the compromised chain"
      safe=$((safe+1)) ;;
    *)
      verdict="UNKNOWN     curl exit $rc, no signal. Check network." ;;
  esac
  printf '%-60s %s\n' "$url" "$verdict"
  rm -f "$body"
done

if [ $fail -ne 0 ]; then
  echo "Result: this client still trusts compromised intermediates. Update your trust store."
  exit 1
fi
if [ $safe -eq 2 ]; then
  echo "Result: this client rejects the compromised chains."
else
  echo "Result: inconclusive. At least one probe gave no signal; fix your network or flags and rerun."
  exit 2
fi
