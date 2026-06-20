#!/bin/bash
set -e

export NGINX_PORT="${HTTP_PORT:-8080}"
export XRAY_BIN="${XRAY_BIN:-/usr/local/bin/xray}"
export XRAY_LOCATION_ASSET="${XRAY_LOCATION_ASSET:-/usr/local/share/xray}"
DATA_DIR="${DATA_DIR:-/data}"

mkdir -p "$DATA_DIR" /tmp/xray

envsubst '${NGINX_PORT}' < /etc/nginx/nginx.conf > /tmp/nginx_rendered.conf
nginx -t -c /tmp/nginx_rendered.conf 2>/dev/null

uvicorn main_xray:app \
    --host 127.0.0.1 \
    --port 8000 \
    --workers 1 \
    --log-level warning \
    --no-access-log &
UVICORN_PID=$!

for i in $(seq 1 20); do
    if curl -sf http://127.0.0.1:8000/health > /dev/null 2>&1; then
        break
    fi
    sleep 1
done

nginx -c /tmp/nginx_rendered.conf -g 'daemon off;' &
NGINX_PID=$!

trap 'kill -TERM $NGINX_PID $UVICORN_PID 2>/dev/null' TERM INT

set +e
wait -n "$NGINX_PID" "$UVICORN_PID"
EXIT_CODE=$?
set -e
kill -TERM "$NGINX_PID" "$UVICORN_PID" 2>/dev/null
wait
exit "$EXIT_CODE"
