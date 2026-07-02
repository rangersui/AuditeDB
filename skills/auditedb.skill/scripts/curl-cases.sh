#!/usr/bin/env bash
set -euo pipefail

# AuditeDB curl cookbook.
#
# Environment:
#   AUDITEDB_BASE          default: http://127.0.0.1:3105
#   AUDITEDB_WORLD         default: /home/AuditeDB-skill-demo
#   AUDITEDB_WRITE_TOKEN   required for PUT/POST/DELETE examples
#   AUDITEDB_READ_TOKEN    optional; write/approve tokens also satisfy reads
#
# Usage:
#   bash scripts/curl-cases.sh version
#   bash scripts/curl-cases.sh put
#   bash scripts/curl-cases.sh cas
#   bash scripts/curl-cases.sh all

BASE="${AUDITEDB_BASE:-http://127.0.0.1:3105}"
WORLD="${AUDITEDB_WORLD:-/home/AuditeDB-skill-demo}"
WRITE_TOKEN="${AUDITEDB_WRITE_TOKEN:-}"
APPROVE_TOKEN="${AUDITEDB_APPROVE_TOKEN:-}"
READ_TOKEN="${AUDITEDB_READ_TOKEN:-${AUDITEDB_WRITE_TOKEN:-${AUDITEDB_APPROVE_TOKEN:-}}}"

read_auth=()
write_auth=()
if [ -n "$READ_TOKEN" ]; then
  read_auth=(-H "Authorization: Bearer $READ_TOKEN")
fi
if [ -n "$WRITE_TOKEN" ]; then
  write_auth=(-H "Authorization: Bearer $WRITE_TOKEN")
fi

need_write_token() {
  if [ -z "$WRITE_TOKEN" ]; then
    echo "missing AUDITEDB_WRITE_TOKEN" >&2
    exit 2
  fi
}

title() {
  printf '\n## %s\n' "$1"
}

case_version() {
  title "GET /proc/version"
  curl -sS -i "${read_auth[@]}" "$BASE/proc/version"
}

case_worlds() {
  title "GET /proc/worlds (plain text, not JSON)"
  curl -sS -i "${read_auth[@]}" "$BASE/proc/worlds"
}

case_put() {
  need_write_token
  title "PUT world bytes"
  printf 'hello from AuditeDB skill\n' |
    curl -sS -i -X PUT "${write_auth[@]}" \
      -H "Content-Type: text/plain; charset=utf-8" \
      --data-binary @- \
      "$BASE$WORLD"
}

case_put_metadata() {
  need_write_token
  title "PUT with representation metadata"
  echo "Note: X-Meta-Summary persists only when AUDITEDB_PERSIST_HEADERS includes x-meta-*." >&2
  printf '<!doctype html><title>AuditeDB</title><p>Hello.</p>\n' |
    curl -sS -i -X PUT "${write_auth[@]}" \
      -H "Content-Type: text/html; charset=utf-8" \
      -H "Content-Language: en" \
      -H "Cache-Control: no-cache" \
      -H "X-Meta-Summary: Generic AuditeDB curl example page." \
      --data-binary @- \
      "$BASE$WORLD"
}

case_head() {
  title "HEAD world metadata"
  curl -sS -i -I "${read_auth[@]}" "$BASE$WORLD"
}

case_get() {
  title "GET world body"
  curl -sS -i "${read_auth[@]}" "$BASE$WORLD"
}

case_range() {
  title "Range GET"
  curl -sS -i "${read_auth[@]}" \
    -H "Range: bytes=0-15" \
    "$BASE$WORLD"
}

case_cas() {
  need_write_token
  title "CAS with ETag and If-Match"
  etag="$(
    curl -fsSI "${read_auth[@]}" "$BASE$WORLD" |
      awk 'BEGIN{IGNORECASE=1} /^etag:/ { sub(/\r$/, ""); print substr($0, index($0, ":") + 2); exit }'
  )"
  if [ -z "$etag" ]; then
    echo "no ETag from HEAD $WORLD; PUT a durable world first" >&2
    exit 1
  fi
  printf 'updated by CAS\n' |
    curl -sS -i -X PUT "${write_auth[@]}" \
      -H "If-Match: $etag" \
      -H "Content-Type: text/plain; charset=utf-8" \
      --data-binary @- \
      "$BASE$WORLD"
}

case_audit_verify() {
  title "Verify audit chain"
  curl -sS -i -I "${read_auth[@]}" "$BASE/proc/audit$WORLD/verify"
}

case_listen() {
  title "Listen for changes"
  echo "This is a streaming request; stop it with Ctrl-C."
  curl -sS -N "${read_auth[@]}" "$BASE/listen$WORLD"
}

case "${1:-help}" in
  version) case_version ;;
  worlds) case_worlds ;;
  put) case_put ;;
  put-metadata) case_put_metadata ;;
  head) case_head ;;
  get) case_get ;;
  range) case_range ;;
  cas) case_cas ;;
  audit-verify) case_audit_verify ;;
  listen) case_listen ;;
  all)
    case_version
    case_worlds
    case_put
    case_head
    case_get
    case_range
    case_cas
    case_audit_verify
    ;;
  *)
    cat <<'USAGE'
AuditeDB curl cases:
  version       GET /proc/version
  worlds        GET /proc/worlds as plain text
  put           PUT bytes into $AUDITEDB_WORLD
  put-metadata  PUT HTML with Content-Type, language, cache, X-Meta-Summary
  head          HEAD $AUDITEDB_WORLD
  get           GET $AUDITEDB_WORLD
  range         GET byte range
  cas           HEAD ETag, then PUT with If-Match
  audit-verify  HEAD /proc/audit$AUDITEDB_WORLD/verify
  listen        GET /listen$AUDITEDB_WORLD as event stream
  all           run non-streaming examples
USAGE
    ;;
esac
