#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

if [ ! -d .git ]; then
  echo "This script must run inside a git clone of NOARTEX." >&2
  exit 1
fi

git submodule update --init --recursive

echo "Stack repositories initialized under ./stack (sentinel-cli, sentinel-audit, sentinel-oracle, sentinel-runtime)."
echo "Review each component README/LICENSE and install prerequisites before use."
