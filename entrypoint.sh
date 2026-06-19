#!/bin/bash
set -e

# ───── متغیرها ─────
export NGINX_PORT="${PORT:-8080}"
export XRAY_BIN="${XRAY_BIN:-/usr/local/bin/xray}"
export XRAY_LOCATION_ASSET="${XRAY_LOCATION_ASSET:-/usr/local/share/xray}"
DATA_DIR="${DATA_DIR:-/data}"

# اطمینان از وجود پوشه‌های لازم
mkdir -p "$DATA_DIR" /tmp/xray /var/log/nginx /var/log/xray

echo "🚀 tryak-Xray starting..."
echo "   PORT      = $NGINX_PORT"
echo "   DATA_DIR  = $DATA_DIR"
echo "   XRAY_BIN  = $XRAY_BIN"

# ───── جایگذاری پورت در nginx.conf ─────
# envsubst فقط ${NGINX_PORT} رو جایگذاری می‌کنه تا $ های دیگه سالم بمونند
envsubst '${NGINX_PORT}' < /etc/nginx/nginx.conf > /tmp/nginx_rendered.conf

# ───── تست کانفیگ Nginx ─────
echo "📄 کانفیگ نهایی nginx (برای دیباگ):"
grep -n "listen" /tmp/nginx_rendered.conf
nginx -t -c /tmp/nginx_rendered.conf
echo "✅ Nginx config OK"

# ───── شروع Nginx (foreground, زیر نظر این اسکریپت) ─────
nginx -c /tmp/nginx_rendered.conf -g 'daemon off;' &
NGINX_PID=$!
echo "✅ Nginx started (pid=$NGINX_PID)"

# ───── شروع FastAPI (داشبورد + مدیریت Xray) ─────
echo "✅ Starting FastAPI dashboard on 127.0.0.1:8000"
uvicorn main_xray:app \
    --host 127.0.0.1 \
    --port 8000 \
    --workers 1 \
    --log-level info &
UVICORN_PID=$!

# ───── نظارت: اگه هرکدوم از این دو پروسه (nginx یا uvicorn) بمیره،
# کل کانتینر باید exit بشه تا Railway طبق restartPolicy دوباره راهش بندازه.
# اینطوری دیگه نمی‌مونیم با یه nginx مرده و یه uvicorn زنده (که نتیجه‌اش 502 از بیرونه).
trap 'kill -TERM $NGINX_PID $UVICORN_PID 2>/dev/null' TERM INT

set +e
wait -n "$NGINX_PID" "$UVICORN_PID"
EXIT_CODE=$?
set -e
echo "⚠️ یکی از پروسه‌ها (nginx یا uvicorn) متوقف شد — کانتینر بسته می‌شود تا ری‌استارت بشه."
kill -TERM "$NGINX_PID" "$UVICORN_PID" 2>/dev/null
wait
exit "$EXIT_CODE"
