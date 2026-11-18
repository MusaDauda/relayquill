#!/bin/sh
set -eu

ROLE="${1:-}"
if [ -z "$ROLE" ]; then
  ROLE="${RELAYQUILL_ROLE:-}"
else
  case "$ROLE" in
    -*)
      ROLE="${RELAYQUILL_ROLE:-}"
      ;;
    *)
      shift
      ;;
  esac
fi

resolve_entry() {
  pkg_dir="$1"
  if [ -f "/app/${pkg_dir}/dist/main.js" ]; then
    printf '%s\n' "/app/${pkg_dir}/dist/main.js"
  elif [ -f "/app/${pkg_dir}/dist/index.js" ]; then
    printf '%s\n' "/app/${pkg_dir}/dist/index.js"
  else
    echo "Missing built entrypoint under /app/${pkg_dir}/dist" >&2
    exit 70
  fi
}

case "$ROLE" in
  api)
    ENTRY="$(resolve_entry "apps/api")"
    ;;
  relay)
    ENTRY="$(resolve_entry "apps/relay")"
    ;;
  fanout)
    ENTRY="$(resolve_entry "apps/fanout")"
    ;;
  sender)
    ENTRY="$(resolve_entry "apps/sender")"
    ;;
  coordinator)
    ENTRY="$(resolve_entry "apps/coordinator")"
    ;;
  admin)
    ENTRY="$(resolve_entry "apps/admin")"
    ;;
  receiver)
    ENTRY="$(resolve_entry "examples/receiver")"
    ;;
  provider-ingress)
    ENTRY="$(resolve_entry "examples/provider-ingress")"
    ;;
  *)
    echo "Disallowed or missing role '${ROLE}'. Allowed: api|relay|fanout|sender|coordinator|admin|receiver|provider-ingress" >&2
    exit 64
    ;;
esac

exec node --enable-source-maps "$ENTRY" "$@"
