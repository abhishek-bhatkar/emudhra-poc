#!/usr/bin/env bash
set -u

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
if ! command -v python3 >/dev/null; then
  echo "python3 is required"
  exit 2
fi
exec python3 "$here/tools/tlsfacts.py" check-client
