#!/usr/bin/env bash
# Usage: ./check_url.sh <url>
set -u

if [ "$#" -ne 1 ]; then
  echo "usage: ./check_url.sh <url>"
  exit 2
fi

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
if ! command -v python3 >/dev/null; then
  echo "python3 is required"
  exit 2
fi
exec python3 "$here/tools/tlsfacts.py" check-url "$1"
