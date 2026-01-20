#!/usr/bin/env bash
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "Run as root to manage tc qdisc" >&2
  exit 1
fi

DEV="${1:-lo}"
DELAY="${2:-50ms}"
LOSS="${3:-0%}"

setup() {
  tc qdisc replace dev "$DEV" root netem delay "$DELAY" loss "$LOSS"
  tc qdisc show dev "$DEV"
}

cleanup() {
  tc qdisc delete dev "$DEV" root || true
}

case "${ACTION:-setup}" in
  setup) setup ;;
  cleanup) cleanup ;;
  *)
    echo "Unknown ACTION=$ACTION (use setup|cleanup)" >&2
    exit 1
    ;;
esac
