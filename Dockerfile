# ═══════════════════════════════════════════════════════════════
# پروژه فقط و فقط برای Railway بهینه شده است.
# Stage 1: Builder — دانلود Xray + build کردن wheelها
# (curl/unzip فقط در همین stage هستند و وارد image نهایی نمی‌شن)
# ═══════════════════════════════════════════════════════════════
FROM python:3.11-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl unzip ca-certificates \
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
    && chmod +x /usr/local/bin/xray

# ───── Python wheels (در همین stage build می‌شن) ─────
WORKDIR /app
COPY requirements.txt .
RUN pip wheel --no-cache-dir --wheel-dir /wheels -r requirements.txt

# ═══════════════════════════════════════════════════════════════
# Stage 2: Runtime — image سبک نهایی (بدون curl/unzip/gettext)
# ═══════════════════════════════════════════════════════════════
FROM python:3.11-slim

# فقط ابزارهای لازم زمان اجرا (envsubst حذف شد — رندر nginx با sed انجام می‌شه)
RUN apt-get update && apt-get install -y --no-install-recommends \
    nginx ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# ───── باینری Xray از builder ─────
COPY --from=builder /usr/local/bin/xray /usr/local/bin/xray

# ───── Nginx config ─────
COPY nginx.conf /etc/nginx/nginx.conf

# ───── Python deps (از wheelهای از پیش build شده) ─────
WORKDIR /app
COPY requirements.txt .
COPY --from=builder /wheels /wheels
RUN pip install --no-cache-dir --no-index --find-links=/wheels -r requirements.txt \
    && rm -rf /wheels

# ───── App ─────
COPY main_xray.py .
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# ───── ENV defaults ─────
# GOGC/GOMEMLIMIT: مهار حافظه‌ی پروسه‌ی Xray (Go). GC زودتر و مکررتر جمع می‌کنه
#   و سقف نرم حافظه می‌ذاره. GOMEMLIMIT رو بسته به پلن Railway و تعداد کاربر تنظیم کن (60–120MiB).
# MALLOC_ARENA_MAX=2: جلوگیری از رشد RSS پایتون/glibc (هر thread arena جدا نسازه)
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONOPTIMIZE=1 \
    XRAY_BIN=/usr/local/bin/xray \
    DATA_DIR=/data \
    GOGC=20 \
    GOMEMLIMIT=80MiB \
    MALLOC_ARENA_MAX=2

EXPOSE 8080

CMD ["/entrypoint.sh"]
