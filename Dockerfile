FROM python:3.11-slim

# ───── ابزارهای پایه ─────
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl unzip ca-certificates nginx gettext-base \
    && rm -rf /var/lib/apt/lists/*

# ───── Xray-core ─────
# ورژن پین شده — برای آپدیت فقط این عدد رو عوض کن
ARG XRAY_VERSION=v25.6.8
RUN echo "Installing Xray ${XRAY_VERSION}" \
    && curl -fL --retry 3 --retry-delay 3 \
        "https://github.com/XTLS/Xray-core/releases/download/${XRAY_VERSION}/Xray-linux-64.zip" \
        -o /tmp/xray.zip \
    && unzip -q /tmp/xray.zip -d /tmp/xray \
    && mv /tmp/xray/xray /usr/local/bin/xray \
    && chmod +x /usr/local/bin/xray \
    && rm -rf /tmp/xray /tmp/xray.zip

# ───── GeoIP (با چند fallback مطمئن) ─────
# geosite.dat لازم نیست — routing فقط از geoip:private/geoip:cn استفاده می‌کنه
RUN mkdir -p /usr/local/share/xray \
    && (curl -fL --retry 3 --retry-delay 2 \
        https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat \
        -o /usr/local/share/xray/geoip.dat 2>/dev/null \
     || curl -fL --retry 3 --retry-delay 2 \
        https://github.com/v2fly/geoip/releases/latest/download/geoip.dat \
        -o /usr/local/share/xray/geoip.dat 2>/dev/null \
     || echo "⚠️ geoip.dat دانلود نشد — routing مبتنی بر geoip غیرفعال خواهد بود") \
    && apt-get purge -y unzip && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/* /tmp/*

# ───── Nginx config ─────
COPY nginx.conf /etc/nginx/nginx.conf

# ───── Python deps ─────
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# ───── App ─────
COPY main_xray.py .
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# ───── ENV defaults ─────
ENV PYTHONUNBUFFERED=1 \
    XRAY_LOCATION_ASSET=/usr/local/share/xray \
    XRAY_BIN=/usr/local/bin/xray \
    DATA_DIR=/data

EXPOSE 8080

CMD ["/entrypoint.sh"]
