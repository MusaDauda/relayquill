#!/bin/sh
set -eu

: "${RELAYQUILL_API_UPSTREAM:=http://relayquill-api:8005}"
export RELAYQUILL_API_UPSTREAM

mkdir -p /tmp/nginx/client_temp /tmp/nginx/proxy_temp /tmp/nginx/fastcgi_temp /tmp/nginx/uwsgi_temp /tmp/nginx/scgi_temp

envsubst '${RELAYQUILL_API_UPSTREAM}' \
  < /etc/nginx/templates/default.conf.template \
  > /tmp/nginx/default.conf

exec nginx -g "daemon off;"
