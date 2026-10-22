#!/usr/bin/env bash
# Usage: ./check_url.sh <url>
# Reports whether the served chain contains a compromised eMudhra key
# and whether this machine's trust store accepted it.
set -u

url=${1:?usage: ./check_url.sh <url>}
hostport=$(awk -F/ '{print ($3 ~ /:/ ? $3 : $3":443")}' <<<"$url")
spki_file="$(dirname "$0")/keys/compromised_spki.txt"

if [ ! -s "$spki_file" ]; then
  echo "Compromised SPKI list missing; fetching the operator's public report..."
  mkdir -p keys
  tmp=$(mktemp -d)
  curl -sS -o "$tmp/db.json" https://emudhra.we-have-a-problem.com/impacted-intermediates.json
  for pem in $(python3 -c "import json,sys;[print(c['pem'].encode().hex()) for c in json.load(open(sys.argv[1]))]" "$tmp/db.json"); do
    echo -n "$pem" | xxd -r -p | \
      openssl x509 -pubkey -noout 2>/dev/null | \
      openssl pkey -pubin -outform DER 2>/dev/null | \
      openssl dgst -sha256 | awk '{print $2}'
  done | sort -u > "$spki_file"
  rm -rf "$tmp"
  echo "Cached $(wc -l < "$spki_file" | tr -d ' ') hashes to $spki_file"
fi

tmp_dir=$(mktemp -d)
servername="${url#*://}"; servername="${servername%%/*}"; servername="${servername%%:*}"
TMP_DIR="$tmp_dir" openssl s_client -connect "$hostport" -servername "$servername" -showcerts </dev/null 2>/dev/null > "$tmp_dir/sc.raw"
TMP_DIR="$tmp_dir" python3 -c "
import os, re
data = open(os.path.join(os.environ['TMP_DIR'], 'sc.raw')).read()
certs = re.findall(r'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----', data, re.S)
for i, c in enumerate(certs):
    open(os.path.join(os.environ['TMP_DIR'], f'c{i}.pem'), 'w').write(c + '\n')
"

match=""
verify="?"
n=0
for cert in "$tmp_dir"/c*.pem; do
  [ -f "$cert" ] || continue
  h=$(openssl x509 -in "$cert" -pubkey -noout | openssl pkey -pubin -outform DER | openssl dgst -sha256 | awk '{print $2}')
  n=$((n+1))
  if grep -qx "$h" "$spki_file"; then
    issuer=$(openssl x509 -in "$cert" -noout -issuer | sed 's/issuer=//')
    match="cert $n in the chain: $issuer"
  fi
  rm -f "$cert"
done
rm -rf "$tmp_dir"
if [ $n = 0 ]; then
  echo "VERDICT: UNKNOWN - no certificates served for $url"
  exit 2
fi

curl -sS -o /dev/null -m 20 "$url" 2>/dev/null
rc=$?
case $rc in
  0)  verify="this client ACCEPTED the chain" ;;
  60) verify="this client REJECTED the chain (TLS verify failed)" ;;
  *)  verify="no curl signal (exit $rc)" ;;
esac

echo "URL:      $url"
echo "Chain:    $n certificate(s) served"
[ -n "$match" ] && echo "Chain:    $match (matches a compromised SPKI hash)" || echo "Chain:    no compromised key in the served chain"
echo "Trust:    $verify"
if [ -n "$match" ] && [ "$rc" = 0 ]; then
  echo "VERDICT:  VULNERABLE - forged chains through these keys validate on this machine"
  exit 1
fi
if [ -n "$match" ]; then
  echo "VERDICT:  SAFE for this client (chain still exists, but you reject it)"
  exit 0
fi
echo "VERDICT:  NOT APPLICABLE - this URL does not exercise the compromised keys"
exit 0
