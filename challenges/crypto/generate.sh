#!/usr/bin/env bash
# Regenerate the Crypto challenge artifacts.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"
python3 instructor/make_challenge.py
