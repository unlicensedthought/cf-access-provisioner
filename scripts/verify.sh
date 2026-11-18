#!/usr/bin/env bash
# Install, typecheck, test. The last stdout line is the verdict.
set -u
cd "$(dirname "$0")/.."
gates=0
step() {
  name=$1; shift
  if "$@" >&2; then
    gates=$((gates + 1))
  else
    echo "VERIFY {\"verdict\":\"fail\",\"failed\":\"$name\"}"
    exit 1
  fi
}
step install npm install --no-audit --no-fund
step typecheck npm run typecheck
step test npm test
echo "VERIFY {\"verdict\":\"pass\",\"gates\":$gates}"
