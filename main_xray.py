import asyncio
import json
import os
import hashlib
import secrets
import time
import signal
import base64
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from pathlib import Path
from urllib.parse import quote
import uuid as _uuid_mod
from collections import deque, defaultdict

from fastapi import FastAPI, Request, HTTPException, Depends
from fastapi.responses import Response, HTMLResponse, JSONResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
import httpx
import logging
import psutil

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("tryak-Xray")

# psutil.cpu_percent با interval=0.1 هر بار event loop رو ۱۰۰ میلی‌ثانیه بلاک می‌کرد
# (یعنی هیچ درخواست دیگه‌ای توی اون لحظه سرویس‌دهی نمی‌شد). با interval=None یه بار
# اینجا "prime" می‌کنیم و بعدش هر فراخوانی غیربلاک‌کننده و آنی، نسبت به فراخوانی قبلی، مقدار رو برمی‌گردونه.
psutil.cpu_percent(interval=None)

# ───────── Platform Detection ─────────
def _detect_host() -> str:
    for env in ["RAILWAY_PUBLIC_DOMAIN", "RENDER_EXTERNAL_HOSTNAME", "KOYEB_PUBLIC_DOMAIN"]:
        h = os.environ.get(env)
        if h: return h
    h = os.environ.get("FLY_APP_NAME")
    if h: return f"{h}.fly.dev"
    h = os.environ.get("HEROKU_APP_DEFAULT_DOMAIN_NAME")
    if h: return h
    h = os.environ.get("PUBLIC_DOMAIN")
    if h: return h
    return "localhost"

def _detect_reality_public_port() -> int:
    """پورت خارجی TCP Proxy که کلاینت باید بهش وصل بشه.
    در Railway با TCP Proxy یه پورت رندوم میده — اون رو توی REALITY_PUBLIC_PORT بذار.
    اگه ست نشده، از همون پورت داخلی استفاده میکنه."""
    p = os.environ.get("REALITY_PUBLIC_PORT")
    if p: return int(p)
    return CONFIG["xray_reality_port"]

def _detect_reality_host() -> str:
    """دامنه TCP Proxy مخصوص Reality را برمی‌گرداند.
    در Railway باید REALITY_TCP_DOMAIN را دستی ست کنی (مثلاً xyz.railway.app:8443 بدون پورت).
    اگه ست نشده باشه، از همون دامنه عمومی استفاده می‌کنه."""
    h = os.environ.get("REALITY_TCP_DOMAIN")
    if h: return h.split(":")[0]  # فقط هاست، بدون پورت
    # fallback به دامنه عمومی
    return _detect_host()

def _detect_platform() -> str:
    if os.environ.get("RAILWAY_PUBLIC_DOMAIN") or os.environ.get("RAILWAY_ENVIRONMENT"):
        return "Railway"
    if os.environ.get("RENDER_EXTERNAL_HOSTNAME") or os.environ.get("RENDER"):
        return "Render"
    if os.environ.get("FLY_APP_NAME"): return "Fly.io"
    if os.environ.get("KOYEB_PUBLIC_DOMAIN"): return "Koyeb"
    return "Local"

_secret_env = os.environ.get("SECRET_KEY", "")
if not _secret_env:
    logger.warning("⚠️ SECRET_KEY تنظیم نشده! یک مقدار رندوم موقت استفاده می‌شود.")

CONFIG = {
    # FastAPI همیشه روی 8000 داخلی listen می‌کنه — Nginx روی $PORT گوش می‌ده
    "port":   8000,
    "secret": _secret_env or secrets.token_urlsafe(32),
    "host":   _detect_host(),
    # پورت‌های داخلی Xray (روی localhost) — پشت Nginx
    "xray_vless_port":    10000,
    "xray_trojan_port":   10001,
    "xray_xhttp_port":    10004,
    "xray_api_port":      10085,
    # پورت Reality — این یکی باید مستقیم (نه پشت Nginx) به بیرون اکسپوز بشه
    # چون Reality خودش handshake واقعی TLS رو هندل می‌کنه. در Railway باید
    # یه TCP Proxy جدا روی همین پورت بسازی (Settings → Networking → TCP Proxy).
    "xray_reality_port":  int(os.environ.get("REALITY_PORT", "8443")),
}

# دامنه‌ای که Reality وانمود می‌کنه بهش وصل شده (camouflage) — باید یه سایت واقعی
# با TLS1.3 و HTTP/2 باشه. قابل تنظیم با env REALITY_DEST / REALITY_SNI.
REALITY_DEST = os.environ.get("REALITY_DEST", "www.microsoft.com:443")
REALITY_SNI  = os.environ.get("REALITY_SNI", REALITY_DEST.split(":")[0])

# ───────── Persistence ─────────
_DATA_DIR = Path("/data") if Path("/data").exists() else Path("/tmp")
DATA_FILE  = _DATA_DIR / "xray_gateway_data.json"
XRAY_BIN   = Path(os.environ.get("XRAY_BIN", "/usr/local/bin/xray"))

# ───────── State ─────────
http_client: httpx.AsyncClient | None = None
xray_process: "asyncio.subprocess.Process | None" = None
keepalive_task: asyncio.Task | None  = None
scheduler_task: asyncio.Task | None  = None
traffic_task: asyncio.Task | None    = None

stats = {
    "total_bytes": 0,
    "total_requests": 0,
    "total_errors": 0,
    "start_time": time.time(),
}
error_logs: deque = deque(maxlen=50)
hourly_traffic: dict = defaultdict(int)
# آخرین مقدار تجمعی هر کاربر که از Xray API خونده شده — برای محاسبه‌ی دلتا
# (مصرف جدید بین این پول و پول قبلی) که به hourly_traffic اضافه می‌شه.
_last_usage_snapshot: dict = {}

# لینک‌ها  uid -> {label, protocol, limit_bytes, used_bytes, created_at, expires_at, active, password(trojan)}
LINKS: dict = {}
LINKS_LOCK = asyncio.Lock()
RELOAD_LOCK = asyncio.Lock()

# کلیدهای Reality (یک‌بار ساخته و persist می‌شن تا با ری‌استارت لینک‌های قبلی خراب نشن)
REALITY: dict = {"private_key": "", "public_key": "", "short_id": ""}

BLOCKED_IPS: set = set()

# ───────── Client IP Tracking (از روی accessLog خود Xray) ─────────
# uid -> { ip: {"country","country_code","city","first_seen","last_seen","hits"} }
link_clients: dict = defaultdict(dict)
LINK_CLIENTS_LOCK = asyncio.Lock()

_ip_geo_cache: dict = {}          # ip -> {"country","country_code","city"}
_IP_GEO_CACHE_MAX = 5000
# دیگه از فایل روی دیسک استفاده نمی‌کنیم؛ خروجی Xray مستقیم از stdout پروسه،
# به‌صورت stream و event-driven خونده می‌شه (نه polling روی فایل) — هم دیسک
# درگیر نمی‌شه، هم CPU کمتر مصرف می‌شه چون دیگه هر ۲ ثانیه open/seek نداریم.
_xray_stdout_task: "asyncio.Task | None" = None

# session
SESSION_COOKIE = "tryak_xray_session"
SESSION_TTL    = 60 * 60 * 24 * 7
SESSIONS: dict = {}
SESSIONS_LOCK  = asyncio.Lock()

# ───────── Auth helpers ─────────
def hash_password(pw: str) -> str:
    return hashlib.sha256(f"{pw}{CONFIG['secret']}".encode()).hexdigest()

_admin_pw = os.environ.get("ADMIN_PASSWORD", "").strip()
if not _admin_pw:
    _admin_pw = "admin"
    logger.warning("⚠️ ADMIN_PASSWORD تنظیم نشده! رمز پیش‌فرض 'admin' استفاده می‌شود.")

AUTH = {"password_hash": hash_password(_admin_pw)}

async def create_session() -> str:
    token = secrets.token_urlsafe(32)
    async with SESSIONS_LOCK:
        SESSIONS[token] = time.time() + SESSION_TTL
    return token

async def is_valid_session(token: str | None) -> bool:
    if not token: return False
    async with SESSIONS_LOCK:
        exp = SESSIONS.get(token)
        if exp is None: return False
        if exp < time.time():
            SESSIONS.pop(token, None)
            return False
        return True

async def destroy_session(token: str | None):
    if token:
        async with SESSIONS_LOCK:
            SESSIONS.pop(token, None)

async def require_auth(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    if not await is_valid_session(token):
        raise HTTPException(status_code=401, detail="unauthorized")
    return token

# ───────── UUID / helpers ─────────
def generate_uuid(seed: str | None = None) -> str:
    if seed is None:
        return str(_uuid_mod.uuid4())
    h = hashlib.sha256(f"{seed}{CONFIG['secret']}".encode()).hexdigest()
    return f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"

def uptime() -> str:
    secs = int(time.time() - stats["start_time"])
    h, m, s = secs // 3600, (secs % 3600) // 60, secs % 60
    return f"{h:02d}:{m:02d}:{s:02d}"

def fmt_bytes(b: int) -> str:
    if not b: return "نامحدود ♾️"
    if b >= 1024**3: return f"{b/1024**3:.1f} GB"
    if b >= 1024**2: return f"{b/1024**2:.1f} MB"
    return f"{b/1024:.1f} KB"

def parse_size_to_bytes(value: float, unit: str) -> int:
    u = unit.upper()
    if u == "GB": return int(value * 1024**3)
    if u == "MB": return int(value * 1024**2)
    if u == "KB": return int(value * 1024)
    return int(value)

def today() -> str:
    return datetime.now().strftime("%Y-%m-%d")

def now_hour() -> str:
    return datetime.now().strftime("%H:00")

def is_link_expired(link: dict) -> bool:
    exp = link.get("expires_at")
    if not exp: return False
    return datetime.fromisoformat(exp) <= datetime.now()

def get_container_memory_percent() -> float:
    """درصد واقعی مصرف RAM کانتینر را برمی‌گرداند (بر اساس محدودیت cgroup، نه کل سرور میزبان)."""
    # cgroup v2
    try:
        cur = Path("/sys/fs/cgroup/memory.current")
        lim = Path("/sys/fs/cgroup/memory.max")
        if cur.exists() and lim.exists():
            used = int(cur.read_text().strip())
            limit_raw = lim.read_text().strip()
            if limit_raw != "max":
                limit = int(limit_raw)
                if limit > 0:
                    return round(used / limit * 100, 1)
    except Exception:
        pass
    # cgroup v1
    try:
        cur = Path("/sys/fs/cgroup/memory/memory.usage_in_bytes")
        lim = Path("/sys/fs/cgroup/memory/memory.limit_in_bytes")
        if cur.exists() and lim.exists():
            used = int(cur.read_text().strip())
            limit = int(lim.read_text().strip())
            # یه محدودیت غیرفعال (خیلی بزرگ) معمولاً یعنی هیچ limit‌ای ست نشده
            if 0 < limit < (1 << 62):
                return round(used / limit * 100, 1)
    except Exception:
        pass
    # fallback: حافظه‌ی کل ماشین میزبان (دقیق نیست ولی بهتر از هیچی)
    try:
        return psutil.virtual_memory().percent
    except Exception:
        return 0.0

def flag(code: str) -> str:
    if not code or len(code) != 2: return "🌐"
    return chr(0x1F1E6 + ord(code[0].upper()) - 65) + chr(0x1F1E6 + ord(code[1].upper()) - 65)

_PRIVATE_IP_PREFIXES = ("10.", "127.", "192.168.", "169.254.", "::1", "fc", "fd")
def _is_private_ip(ip: str) -> bool:
    if ip.startswith("172."):
        try:
            second = int(ip.split(".")[1])
            if 16 <= second <= 31:
                return True
        except Exception:
            pass
    return ip.startswith(_PRIVATE_IP_PREFIXES)

async def get_ip_geo(ip: str) -> dict:
    """geo کش‌شده برای یک IP. روی fail یه dict خالی برمی‌گردونه."""
    if ip in _ip_geo_cache:
        return _ip_geo_cache[ip]
    if _is_private_ip(ip):
        return {}
    try:
        client = http_client or httpx.AsyncClient(timeout=5)
        r = await client.get(
            f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,city",
            timeout=5.0,
        )
        if r.status_code == 200:
            data = r.json()
            if data.get("status") == "success":
                info = {
                    "country": data.get("country", ""),
                    "country_code": data.get("countryCode", ""),
                    "city": data.get("city", ""),
                }
                if len(_ip_geo_cache) >= _IP_GEO_CACHE_MAX:
                    _ip_geo_cache.pop(next(iter(_ip_geo_cache)), None)
                _ip_geo_cache[ip] = info
                return info
    except Exception:
        pass
    return {}

# Xray با email روی هر کلاینت، در accessLog خطی شبیه این می‌نویسه (نسخه‌های جدید Xray-core
# پیشوند "tcp:" / "udp:" رو هم قبل از IP اضافه می‌کنن و گاهی email با کاما/کاراکترهای دیگه
# ادامه پیدا می‌کنه، مثلاً "email: , Domain: ..."):
# 2025/05/03 10:31:52.270544 from tcp:1.2.3.4:51514 accepted tcp:example.com:443 [vless-in >> direct] email: <uid>
# 2025/05/03 10:31:52.270544 from tcp::51514 accepted tcp:example.com:443 [vless-in >> direct] email: <uid>
import re as _re
_ACCESS_LOG_RE = _re.compile(
    r"from\s+(?:tcp|udp):?(?:\[(?P<ip6>[0-9a-fA-F:]+)\]|(?P<ip4>\d{1,3}(?:\.\d{1,3}){3}))?:\d*\s+accepted.*?email:\s*(?P<email>[\w-]+)"
)

async def _record_client_ip(uid: str, ip: str):
    now_iso = datetime.now().isoformat()
    async with LINK_CLIENTS_LOCK:
        bucket = link_clients[uid]
        entry = bucket.get(ip)
        if entry is None:
            entry = {
                "country": "", "country_code": "", "city": "",
                "first_seen": now_iso, "last_seen": now_iso, "hits": 0,
            }
            bucket[ip] = entry
        entry["last_seen"] = now_iso
        entry["hits"] = entry.get("hits", 0) + 1
        need_geo = not entry.get("country")
    if need_geo:
        info = await get_ip_geo(ip)
        if info:
            async with LINK_CLIENTS_LOCK:
                entry = link_clients.get(uid, {}).get(ip)
                if entry is not None:
                    entry["country"] = info.get("country", "")
                    entry["country_code"] = info.get("country_code", "")
                    entry["city"] = info.get("city", "")

async def xray_stdout_reader(proc: "asyncio.subprocess.Process"):
    """خط‌های stdout پروسه‌ی Xray رو همون لحظه که می‌رسن می‌خونه (event-driven، نه polling).
    دیگه هیچ فایلی روی دیسک نوشته/خونده نمی‌شه؛ هم سبک‌تره هم بدون تاخیر ۲ ثانیه‌ای.
    خط‌های غیر access (مثل خطاها/هشدارهای خود Xray) رو از طریق logger خودمون پاس می‌ده تا
    توی لاگ‌های Railway/Docker هم دیده بشن (چون دیگه stdout مستقیم به کانتینر وصل نیست)."""
    if not proc.stdout:
        return
    try:
        while True:
            line = await proc.stdout.readline()
            if not line:
                break
            text = line.decode(errors="ignore").rstrip("\n")
            if not text:
                continue
            m = _ACCESS_LOG_RE.search(text)
            if m:
                ip = m.group("ip4") or m.group("ip6")
                uid = m.group("email")
                # برخی خط‌ها (مثل اتصال داخلی به api-in یا UDP بدون IP مشخص، یعنی "tcp::port")
                # IP خالی دارن — این‌ها رو نادیده می‌گیریم، فقط IP واقعی ثبت می‌شه.
                if ip and uid and uid in LINKS:
                    asyncio.create_task(_record_client_ip(uid, ip))
            elif text.startswith("[Warning]") or text.startswith("[Error]") or "panic" in text.lower():
                # فقط خطاها/هشدارهای واقعی Xray رو به لاگ برنامه پاس می‌دیم؛ خط‌های Info
                # (که با loglevel=info بسیار پرحجم‌اند، مخصوصاً برای UDP) رو دیگه دوباره
                # از طریق logger پایتون چاپ نمی‌کنیم تا CPU/IO اضافه مصرف نشه.
                logger.warning(f"[xray] {text}")
    except asyncio.CancelledError:
        raise
    except Exception as e:
        logger.warning(f"⚠️ xray stdout reader error: {e}")

def link_protocols(link: dict) -> list:
    """لیست پروتکل‌های فعال یک لینک. از فیلد جدید protocols (چندتایی) پشتیبانی می‌کند
    و در صورت نبودش، به فیلد قدیمی protocol (تکی) fallback می‌کند تا داده‌های قبلی خراب نشن."""
    protos = link.get("protocols")
    if isinstance(protos, list) and protos:
        return protos
    single = link.get("protocol")
    return [single] if single else ["vless"]

# ───────── Xray Config Generator ─────────
SUPPORTED_PROTOCOLS = ["vless", "trojan", "vless-xhttp", "vless-reality"]

def build_xray_config() -> dict:
    """کانفیگ کامل Xray را بر اساس LINKS فعلی می‌سازد."""
    inbounds = []

    # ── VLESS + WebSocket (پورت داخلی) ──
    vless_clients = []
    for uid, link in LINKS.items():
        if "vless" in link_protocols(link) and link.get("active"):
            vless_clients.append({"id": uid, "email": uid})

    if vless_clients:
        inbounds.append({
            "tag": "vless-in",
            "listen": "127.0.0.1",
            "port": CONFIG["xray_vless_port"],
            "protocol": "vless",
            "settings": {
                "clients": vless_clients,
                "decryption": "none"
            },
            "streamSettings": {
                "network": "ws",
                "wsSettings": {"path": "/xray-ws"}
            },
            "sniffing": {"enabled": True, "destOverride": ["http", "tls"]}
        })

    # ── Trojan + WebSocket ──
    trojan_clients = []
    for uid, link in LINKS.items():
        if "trojan" in link_protocols(link) and link.get("active"):
            trojan_clients.append({
                "password": link.get("password", uid),
                "email": uid
            })

    if trojan_clients:
        inbounds.append({
            "tag": "trojan-in",
            "listen": "127.0.0.1",
            "port": CONFIG["xray_trojan_port"],
            "protocol": "trojan",
            "settings": {"clients": trojan_clients},
            "streamSettings": {
                "network": "ws",
                "wsSettings": {"path": "/xray-trojan"}
            },
            "sniffing": {"enabled": True, "destOverride": ["http", "tls"]}
        })

    # ── VLESS + XHTTP (پشت Nginx، مسیر /xray-xhttp) ──
    xhttp_clients = []
    for uid, link in LINKS.items():
        if "vless-xhttp" in link_protocols(link) and link.get("active"):
            xhttp_clients.append({"id": uid, "email": uid})

    if xhttp_clients:
        inbounds.append({
            "tag": "vless-xhttp-in",
            "listen": "127.0.0.1",
            "port": CONFIG["xray_xhttp_port"],
            "protocol": "vless",
            "settings": {
                "clients": xhttp_clients,
                "decryption": "none"
            },
            "streamSettings": {
                "network": "xhttp",
                "xhttpSettings": {"path": "/xray-xhttp", "mode": "auto"}
            },
            "sniffing": {"enabled": True, "destOverride": ["http", "tls"]}
        })

    # ── VLESS + Reality (مستقیم، بدون Nginx — به یه TCP Proxy جدا روی Railway نیاز داره) ──
    reality_clients = []
    for uid, link in LINKS.items():
        if "vless-reality" in link_protocols(link) and link.get("active"):
            reality_clients.append({"id": uid, "email": uid, "flow": "xtls-rprx-vision"})

    if reality_clients and REALITY.get("private_key"):
        inbounds.append({
            "tag": "vless-reality-in",
            "listen": "0.0.0.0",
            "port": CONFIG["xray_reality_port"],
            "protocol": "vless",
            "settings": {
                "clients": reality_clients,
                "decryption": "none"
            },
            "streamSettings": {
                "network": "tcp",
                "security": "reality",
                "realitySettings": {
                    "show": False,
                    "dest": REALITY_DEST,
                    "xver": 0,
                    "serverNames": [REALITY_SNI],
                    "privateKey": REALITY["private_key"],
                    "shortIds": [REALITY.get("short_id", "")],
                }
            },
            "sniffing": {"enabled": True, "destOverride": ["http", "tls"]}
        })
    elif reality_clients:
        logger.warning("⚠️ کلاینت Reality وجود دارد ولی کلید Reality ساخته نشده؛ این inbound نادیده گرفته شد.")




    # ── Outbound ──
    outbounds = [
        {"tag": "direct",  "protocol": "freedom",  "settings": {}},
        {"tag": "blocked", "protocol": "blackhole", "settings": {}},
    ]

    # ── Routing ──
    # اگه فایل‌های geoip/geosite موجود نباشن یا خراب باشن (مثلاً شکست دانلود موقع build)،
    # رفرنس به geoip:* باعث کرش Xray موقع start می‌شه. پس فقط وقتی فایل سالم هست اضافه‌شون می‌کنیم.
    routing_rules = []
    geoip_path = Path(os.environ.get("XRAY_LOCATION_ASSET", "/usr/local/share/xray")) / "geoip.dat"
    if geoip_path.exists() and geoip_path.stat().st_size > 0:
        routing_rules = [
            {"type": "field", "ip": ["geoip:private"], "outboundTag": "direct"},
            {"type": "field", "ip": ["geoip:cn"],      "outboundTag": "blocked"},
        ]
    else:
        logger.warning("⚠️ geoip.dat یافت نشد یا خالیه؛ قوانین routing مبتنی بر geoip غیرفعال شدن.")

    return {
        "log": {
            # نکته‌ی مهم: لاگ "accepted ... email: <uid>" که برای ردیابی IP کلاینت‌ها لازمه
            # توی Xray با سطح severity = Info نوشته می‌شه؛ پس loglevel باید info باشه.
            # "access" رو عمداً ست نمی‌کنیم (یا می‌ذاریمش خالی) تا Xray اون رو روی
            # stdout بنویسه، نه روی یه فایل جدا روی دیسک — برنامه مستقیم از stdout
            # خود پروسه می‌خونتش (xray_stdout_reader)، پس هیچ I/O دیسکی برای لاگ نداریم.
            "loglevel": "info",
            "access": "",
        },
        "api": {
            "tag":      "api",
            "services": ["HandlerService", "LoggerService", "StatsService"]
        },
        "stats": {},
        "policy": {
            "system": {
                "statsInboundUplink":   True,
                "statsInboundDownlink": True,
            },
            "levels": {
                "0": {
                    "statsUserUplink":   True,
                    "statsUserDownlink": True,
                }
            }
        },
        "inbounds": [
            {
                "tag":      "api-in",
                "listen":   "127.0.0.1",
                "port":     CONFIG["xray_api_port"],
                "protocol": "dokodemo-door",
                "settings": {"address": "127.0.0.1"},
            },
            *inbounds
        ],
        "outbounds": outbounds,
        "routing": {
            "domainStrategy": "IPIfNonMatch",
            "rules": [
                {"inboundTag": ["api-in"], "outboundTag": "api", "type": "field"},
                *routing_rules
            ]
        }
    }

# ───────── Xray Process Management ─────────
_XRAY_CONFIG_PATH = _DATA_DIR / "xray_config.json"

async def write_xray_config():
    async with LINKS_LOCK:
        cfg = build_xray_config()
    _XRAY_CONFIG_PATH.write_text(json.dumps(cfg, ensure_ascii=False, indent=2))
    logger.info(f"✅ Xray config written → {_XRAY_CONFIG_PATH}")

async def start_xray():
    global xray_process
    if not XRAY_BIN.exists():
        logger.error(f"❌ Xray binary not found at {XRAY_BIN}")
        return

    await write_xray_config()

    global _xray_stdout_task

    # اول پروسه قبلی رو می‌بندیم
    if xray_process and xray_process.returncode is None:
        xray_process.terminate()
        try:
            await asyncio.wait_for(xray_process.wait(), timeout=5)
        except Exception:
            xray_process.kill()
    if _xray_stdout_task:
        _xray_stdout_task.cancel()
        _xray_stdout_task = None

    xray_process = await asyncio.create_subprocess_exec(
        str(XRAY_BIN), "run", "-c", str(_XRAY_CONFIG_PATH),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
    )
    _xray_stdout_task = asyncio.create_task(xray_stdout_reader(xray_process))
    logger.info(f"🚀 Xray started (pid={xray_process.pid})")

async def query_xray_stats() -> dict:
    """مصرف هر کاربر را از Xray API می‌خونه (بدون نیاز به وابستگی جدید، با باینری خود xray)."""
    if not (xray_process and xray_process.returncode is None):
        return {}
    try:
        proc = await asyncio.create_subprocess_exec(
            str(XRAY_BIN), "api", "statsquery",
            f"--server=127.0.0.1:{CONFIG['xray_api_port']}",
            "-pattern", "user>>>",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
        )
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=8)
        data = json.loads(out.decode() or "{}")
    except Exception as e:
        logger.warning(f"⚠️ stats query failed: {e}")
        return {}
    usage: dict = defaultdict(int)
    for item in (data.get("stat") or []):
        parts = str(item.get("name", "")).split(">>>")
        if len(parts) >= 2:
            usage[parts[1]] += int(item.get("value", 0) or 0)
    return usage

async def capture_traffic_baseline():
    """قبل از ری‌استارت Xray، مصرف فعلی رو به‌عنوان baseline ذخیره می‌کنه تا با ری‌استارت صفر نشه."""
    global _last_usage_snapshot
    usage = await query_xray_stats()
    if not usage:
        _last_usage_snapshot = {}
        return
    async with LINKS_LOCK:
        for uid, link in LINKS.items():
            if uid in usage:
                link["baseline_bytes"] = link.get("baseline_bytes", 0) + usage[uid]
                link["used_bytes"] = link["baseline_bytes"]
    # بعد از ری‌استارت Xray شمارنده‌های API از صفر شروع می‌شن؛ snapshot رو پاک می‌کنیم
    # تا دور بعدی traffic_loop به‌جای محاسبه‌ی دلتای منفی، از صفر دلتا بگیره.
    _last_usage_snapshot = {}

async def reload_xray():
    """کانفیگ را دوباره می‌نویسد و Xray را restart می‌کند.
    توجه: Xray-core از SIGHUP پشتیبانی نمی‌کنه؛ باید کامل restart بشه.
    این تابع ممکنه از background task (بدون await در مسیر اصلی درخواست) صدا زده شه؛
    برای جلوگیری از race بین چند ری‌استارت هم‌زمان، با یک لاک serialize می‌شه."""
    async with RELOAD_LOCK:
        await capture_traffic_baseline()
        await start_xray()

def xray_status() -> dict:
    if xray_process is None:
        return {"running": False, "pid": None, "uptime": None}
    if xray_process.returncode is not None:
        return {"running": False, "pid": xray_process.pid, "uptime": None}
    return {"running": True, "pid": xray_process.pid}

# ───────── Persistence ─────────
async def save_data():
    try:
        async with LINKS_LOCK:
            data = {
                "links":       {k: dict(v) for k, v in LINKS.items()},
                "blocked_ips": list(BLOCKED_IPS),
                "reality":     dict(REALITY),
            }
        async with LINK_CLIENTS_LOCK:
            data["link_clients"] = {k: dict(v) for k, v in link_clients.items()}
        data["hourly_traffic"] = dict(hourly_traffic)
        data["total_bytes"]    = stats["total_bytes"]
        tmp = DATA_FILE.with_suffix(".tmp")
        await asyncio.to_thread(tmp.write_text, json.dumps(data, ensure_ascii=False, indent=2))
        tmp.replace(DATA_FILE)
    except Exception as e:
        logger.error(f"Save error: {e}")

def load_data():
    global LINKS, BLOCKED_IPS
    try:
        if DATA_FILE.exists():
            data = json.loads(DATA_FILE.read_text())
            LINKS.clear()
            LINKS.update(data.get("links", {}))
            BLOCKED_IPS.clear()
            BLOCKED_IPS.update(data.get("blocked_ips", []))
            for uid, clients in (data.get("link_clients") or {}).items():
                link_clients[uid].update(clients)
            saved_reality = data.get("reality") or {}
            if saved_reality.get("private_key"):
                REALITY.update(saved_reality)
            hourly_traffic.update(data.get("hourly_traffic") or {})
            stats["total_bytes"] = data.get("total_bytes", 0)
            logger.info(f"✅ Loaded {len(LINKS)} links")
    except Exception as e:
        logger.error(f"Load error: {e}")

async def ensure_reality_keys():
    """اگه کلید Reality قبلاً ساخته نشده، یه‌بار با باینری xray می‌سازدش و persist می‌کنه."""
    if REALITY.get("private_key") and REALITY.get("public_key"):
        return
    try:
        proc = await asyncio.create_subprocess_exec(
            str(XRAY_BIN), "x25519",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
        )
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
        text = out.decode()
        priv = pub = ""
        for line in text.splitlines():
            low = line.lower().replace(" ", "")
            if low.startswith("privatekey:"):
                priv = line.split(":", 1)[1].strip()
            elif low.startswith("publickey:") or "(publickey)" in low.split(":")[0]:
                pub = line.split(":", 1)[1].strip()
        if priv and pub:
            REALITY["private_key"] = priv
            REALITY["public_key"]  = pub
            REALITY["short_id"]    = secrets.token_hex(4)
            await save_data()
            logger.info("✅ کلیدهای Reality ساخته شد.")
        else:
            logger.warning(f"⚠️ خروجی xray x25519 نامعتبر بود: {text!r}")
    except Exception as e:
        logger.warning(f"⚠️ ساخت کلید Reality شکست خورد: {e}")


# ───────── Background loops ─────────
async def keepalive_loop():
    await asyncio.sleep(60)
    while True:
        try:
            host = _detect_host()
            if host and host != "localhost" and http_client:
                r = await http_client.get(f"https://{host}/health", timeout=20.0)
                logger.info(f"🔁 keepalive → {host} [{r.status_code}]")
        except Exception as exc:
            logger.warning(f"⚠️ keepalive failed: {exc}")
        await asyncio.sleep(10 * 60)

async def scheduler_loop():
    while True:
        await asyncio.sleep(60)
        async with LINKS_LOCK:
            changed = []
            for uid, link in LINKS.items():
                if is_link_expired(link) and link.get("active"):
                    link["active"] = False
                    changed.append(link.get("label", uid[:8]))
        if changed:
            await save_data()
            await reload_xray()
            for label in changed:
                logger.info(f"⏰ لینک '{label}' منقضی و غیرفعال شد.")
        # ── پاکسازی session های منقضی (جلوگیری از رشد بی‌رویه‌ی حافظه) ──
        now = time.time()
        async with SESSIONS_LOCK:
            expired = [tok for tok, exp in SESSIONS.items() if exp < now]
            for tok in expired:
                SESSIONS.pop(tok, None)

async def traffic_loop():
    """مصرف واقعی هر لینک رو هر ۳۰ ثانیه از Xray می‌خونه تا نمودار «ترافیک امروز» سریع آپدیت بشه.
    خود فراخوانی Xray API سبکه (یه pipe محلی)، پس این فاصله مشکلی برای CPU ایجاد نمی‌کنه؛
    اما برای جلوگیری از I/O زیاد دیسک، ذخیره‌سازی همچنان فقط هر ~۵ دقیقه (هر ۱۰ دور) یا
    وقتی سهمیه‌ای تموم بشه انجام می‌شه."""
    global _last_usage_snapshot
    await asyncio.sleep(20)
    poll_count = 0
    while True:
        try:
            usage = await query_xray_stats()
            if usage:
                # ── محاسبه‌ی دلتا نسبت به پول قبلی (usage از Xray API تجمعیه، نه افزایشی) ──
                delta_total = 0
                for uid, val in usage.items():
                    prev = _last_usage_snapshot.get(uid, val)  # دفعه‌ی اول دلتا صفر در نظر گرفته میشه
                    if val >= prev:
                        delta_total += val - prev
                    # اگه val < prev یعنی Xray ری‌استارت شده و شمارنده‌ها صفر شدن؛ این پول رو نادیده می‌گیریم
                _last_usage_snapshot = dict(usage)
                if delta_total > 0:
                    hour_key = datetime.now().strftime("%Y-%m-%d-%H")
                    hourly_traffic[hour_key] += delta_total
                    stats["total_bytes"] += delta_total
                    # حذف باکت‌های قدیمی‌تر از ۴۸ ساعت برای جلوگیری از رشد بی‌رویه‌ی حافظه/فایل
                    cutoff = datetime.now() - timedelta(hours=48)
                    old_keys = [k for k in hourly_traffic
                                if k < cutoff.strftime("%Y-%m-%d-%H")]
                    for k in old_keys:
                        hourly_traffic.pop(k, None)

                quota_hit = []
                async with LINKS_LOCK:
                    for uid, link in LINKS.items():
                        if uid in usage:
                            link["used_bytes"] = link.get("baseline_bytes", 0) + usage[uid]
                            if link["limit_bytes"] and link["used_bytes"] >= link["limit_bytes"] and link.get("active"):
                                link["active"] = False
                                quota_hit.append(link.get("label", uid[:8]))
                poll_count += 1
                if quota_hit or poll_count % 10 == 0:
                    await save_data()
                if quota_hit:
                    await reload_xray()
                    for label in quota_hit:
                        logger.info(f"📊 سهمیه لینک '{label}' تمام شد و غیرفعال شد.")
        except Exception as e:
            logger.warning(f"⚠️ traffic loop error: {e}")
        await asyncio.sleep(30)

# ───────── Link generation helpers ─────────
def generate_vless_link(uid: str, host: str, label: str = "tryak") -> str:
    path = "/xray-ws"
    params = {
        "encryption": "none", "security": "tls", "type": "ws",
        "host": host, "path": path, "sni": host, "fp": "chrome", "alpn": "http/1.1",
    }
    q = "&".join(f"{k}={quote(str(v))}" for k, v in params.items())
    return f"vless://{uid}@{host}:443?{q}#{quote(label)}"

def generate_trojan_link(password: str, host: str, label: str = "tryak") -> str:
    params = {"security": "tls", "type": "ws", "path": "/xray-trojan", "sni": host}
    q = "&".join(f"{k}={quote(str(v))}" for k, v in params.items())
    return f"trojan://{quote(password)}@{host}:443?{q}#{quote(label)}"


def generate_vless_xhttp_link(uid: str, host: str, label: str = "tryak") -> str:
    path = "/xray-xhttp"
    params = {
        "encryption": "none", "security": "tls", "type": "xhttp", "mode": "auto",
        "host": host, "path": path, "sni": host, "fp": "chrome", "alpn": "h2,http/1.1",
    }
    q = "&".join(f"{k}={quote(str(v))}" for k, v in params.items())
    return f"vless://{uid}@{host}:443?{q}#{quote(label)}"

def generate_vless_reality_link(uid: str, host: str, port: int, label: str = "tryak") -> str:
    params = {
        "encryption": "none", "security": "reality", "type": "tcp", "flow": "xtls-rprx-vision",
        "sni": REALITY_SNI, "fp": "chrome",
        "pbk": REALITY.get("public_key", ""), "sid": REALITY.get("short_id", ""),
    }
    q = "&".join(f"{k}={quote(str(v))}" for k, v in params.items())
    return f"vless://{uid}@{host}:{port}?{q}#{quote(label)}"

def get_connection_for_protocol(uid: str, link: dict, proto: str, host: str, index: int = 0) -> dict:
    if proto == "vless":
        return {
            "link":     generate_vless_link(uid, host, link.get("label", "tryak")),
            "protocol": "VLESS + WS + TLS",
            "server":   host, "port": 443,
            "path":     "/xray-ws",
        }
    elif proto == "trojan":
        return {
            "link":     generate_trojan_link(link.get("password", uid), host, link.get("label", "tryak")),
            "protocol": "Trojan + WS + TLS",
            "server":   host, "port": 443,
            "path":     "/xray-trojan",
        }
    elif proto == "vless-xhttp":
        return {
            "link":     generate_vless_xhttp_link(uid, host, link.get("label", "tryak")),
            "protocol": "VLESS + XHTTP + TLS",
            "server":   host, "port": 443,
            "path":     "/xray-xhttp",
        }
    elif proto == "vless-reality":
        reality_host = _detect_reality_host()
        public_port  = _detect_reality_public_port()
        return {
            "link":     generate_vless_reality_link(uid, reality_host, public_port, link.get("label", "tryak")),
            "protocol": "VLESS + Reality",
            "server":   reality_host, "port": public_port,
            "note":     "این پروتکل مستقیم و بدون Nginx کار می‌کنه؛ روی Railway باید پورت "
                        f"{public_port} رو جدا به‌صورت TCP Proxy اکسپوز کرده باشی.",
        }
    return {}

def get_link_connections(uid: str, link: dict, host: str) -> list:
    """برای همه‌ی پروتکل‌های انتخاب‌شده روی یک لینک (همون uid)، اطلاعات اتصال جدا برمی‌گردونه."""
    conns = []
    for proto in link_protocols(link):
        c = get_connection_for_protocol(uid, link, proto, host, 0)
        if c:
            c["proto_key"] = proto
            conns.append(c)
    return conns

def get_link_connection_info(uid: str, link: dict, host: str, index: int = 0) -> dict:
    """سازگاری روبه‌عقب: اولین اتصال (پروتکل اصلی) لینک رو برمی‌گردونه."""
    protos = link_protocols(link)
    if not protos:
        return {}
    return get_connection_for_protocol(uid, link, protos[0], host, index)

# ───────── Lifespan ─────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    global http_client, keepalive_task, scheduler_task, traffic_task
    limits  = httpx.Limits(max_connections=200, max_keepalive_connections=50)
    timeout = httpx.Timeout(30.0, connect=10.0)
    http_client = httpx.AsyncClient(limits=limits, timeout=timeout, follow_redirects=True)

    load_data()
    await ensure_reality_keys()
    await start_xray()   # خودش xray_stdout_reader رو هم استارت می‌کنه

    keepalive_task   = asyncio.create_task(keepalive_loop())
    scheduler_task   = asyncio.create_task(scheduler_loop())
    traffic_task     = asyncio.create_task(traffic_loop())

    logger.info(f"🚀 tryak-Xray Gateway started on port {CONFIG['port']}")
    yield

    for t in [keepalive_task, scheduler_task, traffic_task, _xray_stdout_task]:
        if t: t.cancel()
    if xray_process and xray_process.returncode is None:
        xray_process.terminate()
    await save_data()
    if http_client:
        await http_client.aclose()

app = FastAPI(title="tryak Xray Gateway", docs_url=None, redoc_url=None, lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True, allow_methods=["*"], allow_headers=["*"],
)

# ───────── Basic Endpoints ─────────
@app.get("/")
async def root():
    return {"service": "tryak Xray Gateway", "version": "1.0", "status": "active", "host": _detect_host()}

@app.get("/health")
async def health():
    x = xray_status()
    return {"status": "ok", "uptime": uptime(), "xray_running": x["running"], "xray_pid": x["pid"]}

# ───────── Auth ─────────
@app.post("/api/login")
async def api_login(request: Request):
    body = await request.json()
    pw = str(body.get("password") or "")
    if hash_password(pw) != AUTH["password_hash"]:
        raise HTTPException(status_code=401, detail="رمز عبور اشتباه است")
    token = await create_session()
    resp = JSONResponse({"ok": True})
    resp.set_cookie(key=SESSION_COOKIE, value=token, max_age=SESSION_TTL,
                    httponly=True, samesite="lax", path="/")
    return resp

@app.post("/api/logout")
async def api_logout(request: Request):
    await destroy_session(request.cookies.get(SESSION_COOKIE))
    resp = JSONResponse({"ok": True})
    resp.delete_cookie(SESSION_COOKIE, path="/")
    return resp

@app.get("/api/me")
async def api_me(request: Request):
    valid = await is_valid_session(request.cookies.get(SESSION_COOKIE))
    return {"authenticated": valid}

# ───────── Stats ─────────
@app.get("/stats")
async def get_stats(_=Depends(require_auth)):
    x = xray_status()
    async with LINKS_LOCK:
        lc = len(LINKS)
    return {
        "uptime":           uptime(),
        "platform":         _detect_platform(),
        "xray":             x,
        "links_count":      lc,
        "blocked_ips":      len(BLOCKED_IPS),
        "cpu_percent":      psutil.cpu_percent(interval=None),
        "memory_percent":   get_container_memory_percent(),
        "total_bytes":      stats["total_bytes"],
        "total_requests":   stats["total_requests"],
        "total_errors":     stats["total_errors"],
        "recent_errors":    list(error_logs)[-10:],
        "hourly":           dict(hourly_traffic),
    }

@app.get("/api/traffic/today")
async def get_traffic_today(_=Depends(require_auth)):
    """ترافیک امروز (از ساعت ۰۰:۰۰ تا الان) به تفکیک ساعت، برای رسم نمودار.
    خروجی همیشه ۲۴ نقطه (ساعت ۰ تا ۲۳) داره؛ ساعت‌های آینده/بدون داده مقدار صفر دارن."""
    today = datetime.now().strftime("%Y-%m-%d")
    points = []
    total_today = 0
    for h in range(24):
        key = f"{today}-{h:02d}"
        val = hourly_traffic.get(key, 0)
        total_today += val
        points.append({"hour": h, "bytes": val})
    return {"date": today, "points": points, "total_bytes": total_today}

# ───────── Link Management ─────────
@app.post("/api/links")
async def create_link(request: Request, _=Depends(require_auth)):
    body = await request.json()
    label = (body.get("label") or "لینک جدید").strip()[:60]

    # سازگار با فرانت قدیمی (یک پروتکل) و جدید (چند پروتکل هم‌زمان روی همون uuid)
    protocols = body.get("protocols")
    if not isinstance(protocols, list) or not protocols:
        single = body.get("protocol", "vless")
        protocols = [single]
    protocols = list(dict.fromkeys(protocols))  # حذف تکراری، حفظ ترتیب
    for p in protocols:
        if p not in SUPPORTED_PROTOCOLS:
            raise HTTPException(400, f"پروتکل نامعتبر: {p}. مجاز: {SUPPORTED_PROTOCOLS}")

    limit_value  = float(body.get("limit_value") or 0)
    limit_unit   = body.get("limit_unit") or "GB"
    expire_days  = float(body.get("expire_days") or 0)
    password     = body.get("password") or secrets.token_urlsafe(16)
    ss_method    = body.get("ss_method") or "aes-256-gcm"

    limit_bytes  = 0 if limit_value <= 0 else parse_size_to_bytes(limit_value, limit_unit)
    expires_at   = (datetime.now() + timedelta(days=expire_days)).isoformat() if expire_days > 0 else None
    uid          = str(_uuid_mod.uuid4())  # همیشه uuid4 تازه

    new_link = {
        "label":       label,
        "protocol":    protocols[0],   # سازگاری روبه‌عقب
        "protocols":   protocols,
        "limit_bytes": limit_bytes,
        "used_bytes":  0,
        "baseline_bytes": 0,
        "created_at":  datetime.now().isoformat(),
        "expires_at":  expires_at,
        "active":      True,
        "password":    password,
        "ss_method":   ss_method,
    }
    async with LINKS_LOCK:
        LINKS[uid] = new_link

    # نکته‌ی مهم: قبلاً اینجا reload_xray() (که خود Xray رو ری‌استارت می‌کنه و چند ثانیه طول
    # می‌کشه) await می‌شد و کلاینت تا اون موقع منتظر می‌ماند. این باعث می‌شد کاربر فکر کنه
    # درخواست گیر کرده، دکمه رو دوباره بزنه یا صفحه رو رفرش کنه و همون لینک دوبار ساخته شه.
    # حالا ابتدا داده ذخیره و پاسخ فوراً برگردونده می‌شه، و ری‌استارت Xray در پس‌زمینه انجام می‌شه.
    await save_data()
    asyncio.create_task(reload_xray())

    host  = _detect_host()
    conns = get_link_connections(uid, new_link, host)

    return {"uuid": uid, "label": label, "protocol": protocols[0], "protocols": protocols,
            "limit_bytes": limit_bytes, "used_bytes": 0, "active": True,
            "created_at": new_link["created_at"], "expires_at": expires_at,
            "connection": conns[0] if conns else {}, "connections": conns}

@app.get("/api/links")
async def list_links(_=Depends(require_auth)):
    host = _detect_host()
    now  = datetime.now()
    result = []
    async with LINKS_LOCK:
        for uid, data in LINKS.items():
            protos = link_protocols(data)
            conns  = get_link_connections(uid, data, host)

            expires_at  = data.get("expires_at")
            is_expired  = False
            days_left   = None
            if expires_at:
                exp_dt    = datetime.fromisoformat(expires_at)
                days_left = (exp_dt - now).total_seconds() / 86400
                if days_left <= 0:
                    is_expired = True; days_left = 0

            quota_exceeded = data["limit_bytes"] != 0 and data["used_bytes"] >= data["limit_bytes"]
            result.append({
                "uuid":           uid,
                "label":          data["label"],
                "protocol":       protos[0],
                "protocols":      protos,
                "limit_bytes":    data["limit_bytes"],
                "used_bytes":     data["used_bytes"],
                "active":         data["active"],
                "created_at":     data["created_at"],
                "expires_at":     expires_at,
                "days_left":      None if days_left is None else round(days_left, 1),
                "is_expired":     is_expired,
                "quota_exceeded": quota_exceeded,
                "connection":     conns[0] if conns else {},
                "connections":    conns,
            })
    result.sort(key=lambda x: x["created_at"], reverse=True)
    return {"links": result}

@app.get("/api/links/{uid}/clients")
async def get_link_clients(uid: str, _=Depends(require_auth)):
    async with LINK_CLIENTS_LOCK:
        clients = dict(link_clients.get(uid, {}))
    result = []
    for ip, info in clients.items():
        result.append({
            "ip": ip,
            "country": info.get("country") or "نامشخص",
            "country_code": info.get("country_code") or "",
            "flag": flag(info.get("country_code", "")),
            "city": info.get("city") or "",
            "first_seen": info.get("first_seen"),
            "last_seen": info.get("last_seen"),
            "hits": info.get("hits", 0),
        })
    result.sort(key=lambda c: c["last_seen"] or "", reverse=True)
    return {"clients": result}

@app.patch("/api/links/{uid}")
async def update_link(uid: str, request: Request, _=Depends(require_auth)):
    body = await request.json()
    async with LINKS_LOCK:
        if uid not in LINKS:
            raise HTTPException(404, "link not found")
        link = LINKS[uid]
        if "active"       in body: link["active"]    = bool(body["active"])
        if "label"        in body: link["label"]     = str(body["label"]).strip()[:60]
        if "protocols"    in body and isinstance(body["protocols"], list) and body["protocols"]:
            protos = list(dict.fromkeys(body["protocols"]))
            for p in protos:
                if p not in SUPPORTED_PROTOCOLS:
                    raise HTTPException(400, f"پروتکل نامعتبر: {p}")
            link["protocols"] = protos
            link["protocol"]  = protos[0]
        if "limit_value"  in body:
            lv = float(body.get("limit_value") or 0)
            lu = body.get("limit_unit") or "GB"
            link["limit_bytes"] = 0 if lv <= 0 else parse_size_to_bytes(lv, lu)
        if "reset_usage"  in body and body["reset_usage"]:
            link["used_bytes"] = 0
            link["baseline_bytes"] = 0
        if "expire_days"  in body:
            ed = float(body.get("expire_days") or 0)
            link["expires_at"] = (datetime.now() + timedelta(days=ed)).isoformat() if ed > 0 else None
        if "password"     in body: link["password"]  = str(body["password"])
        if "ss_method"    in body: link["ss_method"] = str(body["ss_method"])

    await save_data()
    asyncio.create_task(reload_xray())
    return {"ok": True}
async def delete_link(uid: str, _=Depends(require_auth)):
    async with LINKS_LOCK:
        LINKS.pop(uid, None)
    async with LINK_CLIENTS_LOCK:
        link_clients.pop(uid, None)
    await save_data()
    asyncio.create_task(reload_xray())
    return {"ok": True}

# ───────── Xray Control ─────────
@app.post("/api/xray/restart")
async def xray_restart(_=Depends(require_auth)):
    await reload_xray()
    return {"ok": True, "xray": xray_status()}

@app.get("/api/xray/config")
async def xray_config(_=Depends(require_auth)):
    async with LINKS_LOCK:
        cfg = build_xray_config()
    return cfg

@app.get("/api/xray/status")
async def get_xray_status(_=Depends(require_auth)):
    return xray_status()

# ───────── Blocked IPs ─────────
@app.get("/api/blocked")
async def get_blocked(_=Depends(require_auth)):
    return {"blocked_ips": list(BLOCKED_IPS)}

@app.post("/api/blocked")
async def block_ip(request: Request, _=Depends(require_auth)):
    body = await request.json()
    ip = str(body.get("ip", "")).strip()
    if not ip: raise HTTPException(400, "IP required")
    BLOCKED_IPS.add(ip)
    await save_data()
    return {"ok": True}

@app.delete("/api/blocked/{ip}")
async def unblock_ip(ip: str, _=Depends(require_auth)):
    BLOCKED_IPS.discard(ip)
    await save_data()
    return {"ok": True}

# ───────── Subscription Page ─────────
@app.get("/sub/{uid}/raw", response_class=Response)
async def subscription_raw(uid: str):
    """لینک سابسکریپشن استاندارد (Base64) برای وارد کردن مستقیم در کلاینت‌هایی مثل
    v2rayNG / v2rayN / NekoBox / Streisand و غیره. خروجی متن ساده‌ست: هر خط یک
    لینک (vless:// trojan:// ss://...)، که کل متن با Base64 استاندارد انکود شده.
    HTTP Proxy در این لیست نمیاد چون فرمت قابل‌import در کلاینت‌های VPN نیست."""
    async with LINKS_LOCK:
        link = LINKS.get(uid)
    if not link:
        raise HTTPException(404, "لینک یافت نشد")

    host     = _detect_host()
    conns    = get_link_connections(uid, link, host)

    importable = [c["link"] for c in conns if c.get("link", "").startswith(("vless://", "trojan://"))]
    raw_text = "\n".join(importable)
    encoded = base64.b64encode(raw_text.encode()).decode()
    return Response(content=encoded, media_type="text/plain; charset=utf-8")


@app.get("/sub/{uid}")
async def subscription_page(uid: str):
    return RedirectResponse(url=f"/sub/{uid}/raw", status_code=302)

@app.get("/sub/{uid}/page", response_class=HTMLResponse)
async def subscription_page_html(uid: str, request: Request):
    async with LINKS_LOCK:
        link = LINKS.get(uid)
    if not link:
        raise HTTPException(404, "لینک یافت نشد")

    host     = _detect_host()
    protos    = link_protocols(link)
    is_active = link.get("active", False) and not is_link_expired(link)
    label    = link.get("label", "کاربر")
    limit_b  = link.get("limit_bytes", 0)
    used_b   = link.get("used_bytes", 0)
    remaining_b = max(0, limit_b - used_b) if limit_b > 0 else 0

    used_fmt      = fmt_bytes(used_b)
    limit_fmt     = fmt_bytes(limit_b)
    remaining_fmt = fmt_bytes(remaining_b) if limit_b > 0 else "نامحدود ♾️"
    pct      = round(used_b / limit_b * 100, 1) if limit_b > 0 else 0

    conns    = get_link_connections(uid, link, host)

    exp = link.get("expires_at")
    never_expire = not exp
    exp_str = datetime.fromisoformat(exp).strftime("%Y/%m/%d") if exp else "—"
    days_left = 0
    hours_left = 0
    if exp:
        total_secs = max(0, (datetime.fromisoformat(exp) - datetime.now()).total_seconds())
        days_left  = int(total_secs // 86400)
        hours_left = int((total_secs % 86400) // 3600)

    _proto_names = {"vless": "VLESS · WS · TLS", "trojan": "Trojan · WS · TLS",
                   "vless-xhttp": "VLESS · XHTTP · TLS", "vless-reality": "VLESS · Reality"}
    proto_badges_html = "".join(f'<div class="proto-badge">{_proto_names.get(p,p)}</div>' for p in protos)
    proto_badge = " / ".join(_proto_names.get(p, p) for p in protos)

    if pct >= 90:
        bar = "#f56565"
        bar_glow = "rgba(245,101,101,0.4)"
    elif pct >= 70:
        bar = "#f0b14a"
        bar_glow = "rgba(240,177,74,0.4)"
    else:
        bar = "#6366f1"
        bar_glow = "rgba(99,102,241,0.4)"

    status_text = "فعال" if is_active else "غیرفعال"

    time_remaining_html = ""
    if not never_expire:
        if days_left > 0:
            time_remaining_html = f"{days_left} روز و {hours_left} ساعت"
        elif hours_left > 0:
            time_remaining_html = f"{hours_left} ساعت"
        else:
            time_remaining_html = "منقضی شده"
    else:
        time_remaining_html = "♾️ نامحدود"

    conn_sections_html = ""
    for i, conn in enumerate(conns):
        show_qr = conn.get("link", "").startswith(("vless://", "trojan://"))
        conn_sections_html += f"""
    <div class="conn-section" style="margin-top:{12 if i > 0 else 0}px">
      <div class="conn-label"><i class="ti ti-plug"></i> {conn.get('protocol','')}</div>
      <div class="conn-text" id="conn-link-{i}">{conn.get('link','')}</div>
      <div class="btn-row">
        <button class="btn btn-primary" onclick="copyLink({i})"><i class="ti ti-copy"></i> کپی لینک</button>
        {f'<button class="btn btn-outline" onclick="showQR({i})"><i class="ti ti-qrcode"></i> QR</button>' if show_qr else ''}
      </div>
    </div>"""

    conn_links_js = ",".join(json.dumps(c.get("link", "")) for c in conns)

    html = f"""<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1">
<title>پروفایل · {label}</title>
<link href="https://fonts.googleapis.com/css2?family=Vazirmatn:wght@400;600;700;800&display=swap" rel="stylesheet">
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@tabler/icons-webfont@3.19.0/dist/tabler-icons.min.css">
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
:root{{--accent:#6366f1;--accent2:#4f46e5;--accent-glow:rgba(99,102,241,0.35);--green:#4ce090;--red:#f56565;--amber:#f0b14a;--bg:#0a0e17;--card:#10172a;--card2:#151d33;--border:#1f2940;--text-1:#eef2ff;--text-2:#7b8aab;--text-3:#475370}}
body{{font-family:'Vazirmatn',sans-serif;background:radial-gradient(circle at 20% 20%,rgba(59,130,246,0.18),transparent 45%),radial-gradient(circle at 80% 80%,rgba(29,78,216,0.15),transparent 45%),var(--bg);min-height:100vh;display:flex;align-items:center;justify-content:center;padding:16px;color:var(--text-1)}}
.card{{background:var(--card);border-radius:20px;width:100%;max-width:420px;border:1px solid var(--border);overflow:hidden;box-shadow:0 24px 70px rgba(0,0,0,.55)}}
.card-header{{padding:22px 24px 18px;background:linear-gradient(135deg,rgba(99,102,241,0.15),rgba(29,78,216,0.08));border-bottom:1px solid var(--border)}}
.logo-row{{display:flex;align-items:center;gap:14px;margin-bottom:16px}}
.logo-icon{{font-size:46px;font-weight:900;color:#6366f1;font-family:'Vazirmatn',sans-serif;line-height:1}}
.logo-text .name{{font-size:17px;font-weight:800;color:#fff}}
.logo-text .sub{{font-size:11px;color:rgba(147,197,253,0.8);margin-top:2px}}
.user-section{{display:flex;align-items:center;gap:12px}}
.avatar{{width:44px;height:44px;border-radius:50%;background:rgba(99,102,241,0.18);border:2px solid rgba(99,102,241,0.3);display:flex;align-items:center;justify-content:center;font-size:20px;flex-shrink:0}}
.user-name{{font-size:16px;font-weight:700;color:#fff}}
.user-id{{font-size:10px;color:rgba(147,197,253,0.6);font-family:ui-monospace,monospace;margin-top:2px;word-break:break-all}}
.status-pill{{display:inline-flex;align-items:center;gap:6px;padding:4px 12px;border-radius:20px;font-size:11px;font-weight:600;background:rgba(76,224,144,0.1);border:1px solid rgba(76,224,144,0.2);color:var(--green);margin-top:8px}}
.status-pill.inactive{{background:rgba(245,101,101,0.1);border-color:rgba(245,101,101,0.2);color:var(--red)}}
.status-dot{{width:6px;height:6px;border-radius:50%;background:currentColor;animation:pulse 2s infinite}}
@keyframes pulse{{0%,100%{{opacity:1}}50%{{opacity:.35}}}}
.card-body{{padding:20px 22px 26px}}

/* ─── Stats Grid (2×2) ─── */
.stats-grid{{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:18px}}
.stat-box{{background:var(--card2);border-radius:13px;border:1px solid var(--border);padding:13px 15px;position:relative;overflow:hidden}}
.stat-box::before{{content:'';position:absolute;inset:0;background:linear-gradient(135deg,rgba(99,102,241,0.04),transparent);pointer-events:none}}
.stat-icon{{font-size:18px;color:var(--accent);margin-bottom:6px}}
.stat-label{{font-size:10px;color:var(--text-2);font-weight:600;text-transform:uppercase;letter-spacing:.06em;margin-bottom:4px}}
.stat-val{{font-size:18px;font-weight:700;color:var(--text-1);line-height:1.2}}
.stat-unit{{font-size:10px;color:var(--text-2);margin-top:3px}}
.stat-highlight{{color:var(--accent)}}

/* ─── Progress ─── */
.usage-section{{margin-bottom:18px}}
.usage-header{{display:flex;justify-content:space-between;align-items:baseline;margin-bottom:8px}}
.usage-title{{font-size:12px;font-weight:600;color:var(--text-2)}}
.usage-numbers span{{color:var(--text-1);font-weight:700;font-size:12px}}
.progress-wrap{{position:relative;height:12px;border-radius:8px;background:var(--card2);border:1px solid var(--border);overflow:hidden;margin-bottom:5px}}
.progress-fill{{height:100%;border-radius:8px;transition:width .6s;background:linear-gradient(90deg,{bar},{bar_glow});box-shadow:0 0 8px {bar_glow}}}
.progress-labels{{display:flex;justify-content:space-between;font-size:10px;color:var(--text-2)}}

/* ─── Info Rows ─── */
.info-rows{{margin-bottom:16px}}
.info-row{{display:flex;justify-content:space-between;align-items:center;padding:9px 0;border-bottom:1px solid var(--border);font-size:12px}}
.info-row:last-child{{border-bottom:none}}
.info-key{{color:var(--text-2);display:flex;align-items:center;gap:7px}}
.info-key i{{font-size:14px;color:var(--accent)}}
.info-val{{color:var(--text-1);font-weight:600;text-align:left}}

/* ─── Conn Section ─── */
.conn-section{{background:var(--card2);border-radius:12px;border:1px solid var(--border);padding:14px}}
.conn-label{{font-size:11px;font-weight:600;color:var(--text-2);margin-bottom:8px;display:flex;align-items:center;gap:6px}}
.conn-label i{{font-size:13px;color:var(--accent)}}
.conn-text{{font-family:ui-monospace,monospace;font-size:9.5px;color:#93c5fd;word-break:break-all;line-height:1.7;background:rgba(0,0,0,.25);border-radius:8px;padding:10px 12px;margin-bottom:10px;border:1px solid rgba(99,102,241,0.1)}}
.btn-row{{display:flex;gap:8px;flex-wrap:wrap}}
.btn{{font-family:inherit;font-size:12px;font-weight:600;border-radius:9px;padding:9px 14px;cursor:pointer;display:inline-flex;align-items:center;gap:6px;border:none;transition:.15s;flex:1;justify-content:center}}
.btn-primary{{background:linear-gradient(135deg,var(--accent),var(--accent2));color:#fff;box-shadow:0 2px 10px var(--accent-glow)}}
.btn-primary:hover{{filter:brightness(1.1)}}
.btn-outline{{background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.12);color:var(--text-1)}}
.btn-outline:hover{{background:rgba(255,255,255,.08)}}
.btn-success{{background:rgba(76,224,144,0.12);border:1px solid rgba(76,224,144,0.25);color:var(--green)}}
.proto-badge{{display:inline-block;font-size:10px;background:rgba(99,102,241,0.12);color:#a5b4fc;border:1px solid rgba(99,102,241,0.2);border-radius:6px;padding:2px 8px;font-weight:600;margin:2px 2px 0 0}}
.sub-section{{background:rgba(99,102,241,0.06);border-radius:12px;border:1px solid rgba(99,102,241,0.15);padding:14px;margin-bottom:12px}}
.all-configs-btn{{width:100%;margin-bottom:12px}}
.divider{{height:1px;background:var(--border);margin:14px 0}}
.section-title{{font-size:11px;font-weight:700;color:var(--text-2);text-transform:uppercase;letter-spacing:.08em;margin-bottom:12px;display:flex;align-items:center;gap:6px}}
.section-title i{{color:var(--accent);font-size:14px}}
.footer{{text-align:center;font-size:10px;color:var(--text-3);padding-top:14px}}
</style>
</head>
<body>
<div class="card">
  <div class="card-header">
    <div class="logo-row">
      <div class="logo-icon">T</div>
      <div class="logo-text"><div class="name">tryak</div><div class="sub">پروفایل اشتراک</div></div>
    </div>
    <div class="user-section">
      <div class="avatar"><i class="ti ti-user"></i></div>
      <div>
        <div class="user-name">{label}</div>
        <div class="user-id">{uid}</div>
        <div style="display:flex;gap:4px;flex-wrap:wrap;margin-top:6px">{proto_badges_html}</div>
        <div class="status-pill{'' if is_active else ' inactive'}">
          <span class="status-dot"></span>{status_text}
        </div>
      </div>
    </div>
  </div>
  <div class="card-body">

    <!-- ── Stats ── -->
    <div class="stats-grid">
      <div class="stat-box">
        <div class="stat-icon"><i class="ti ti-database"></i></div>
        <div class="stat-label">حجم باقی‌مانده</div>
        <div class="stat-val {'stat-highlight' if limit_b > 0 and remaining_b == 0 else ''}">{remaining_fmt.split()[0] if ' ' in remaining_fmt else remaining_fmt}</div>
        <div class="stat-unit">{"♾️ نامحدود" if limit_b == 0 else (remaining_fmt.split()[-1] if ' ' in remaining_fmt else '')}</div>
      </div>
      <div class="stat-box">
        <div class="stat-icon"><i class="ti ti-clock"></i></div>
        <div class="stat-label">زمان باقی‌مانده</div>
        <div class="stat-val" style="font-size:{'15px' if days_left > 0 else '14px'}">{days_left if not never_expire else '♾️'}</div>
        <div class="stat-unit">{'روز' if not never_expire else 'نامحدود'}{f' و {hours_left} ساعت' if not never_expire and hours_left > 0 else ''}</div>
      </div>
    </div>

    <!-- ── Progress Bar ── -->
    <div class="usage-section">
      <div class="usage-header">
        <div class="usage-title"><i class="ti ti-chart-bar" style="font-size:12px;margin-left:4px"></i>مصرف ترافیک</div>
        <div class="usage-numbers"><span>{used_fmt}</span> از {limit_fmt}</div>
      </div>
      <div class="progress-wrap">
        <div class="progress-fill" style="width:{min(pct, 100) if limit_b > 0 else 0}%"></div>
      </div>
      <div class="progress-labels">
        <span>{pct}٪ مصرف شده</span>
        <span>{remaining_fmt} مانده</span>
      </div>
    </div>

    <!-- ── Info Rows ── -->
    <div class="info-rows">
      <div class="info-row">
        <span class="info-key"><i class="ti ti-calendar"></i> تاریخ انقضا</span>
        <span class="info-val">{'بدون انقضا ♾️' if never_expire else exp_str}</span>
      </div>
      <div class="info-row">
        <span class="info-key"><i class="ti ti-hourglass"></i> زمان باقی‌مانده</span>
        <span class="info-val">{time_remaining_html}</span>
      </div>
      <div class="info-row">
        <span class="info-key"><i class="ti ti-server"></i> سرور</span>
        <span class="info-val" style="font-size:11px">{host}</span>
      </div>
      <div class="info-row">
        <span class="info-key"><i class="ti ti-shield-lock"></i> پروتکل</span>
        <span class="info-val" style="font-size:11px;text-align:left">{proto_badge}</span>
      </div>
    </div>

    <!-- ── Copy All ── -->
    <button class="btn btn-outline all-configs-btn" onclick="copyAllConfigs()">
      <i class="ti ti-copy"></i> کپی تمام کانفیگ‌ها ({len(conns)} کانفیگ)
    </button>

    <!-- ── Individual Configs ── -->
    <div class="section-title"><i class="ti ti-plug"></i>کانفیگ‌های اتصال</div>
    {conn_sections_html}

    <div class="footer">tryak · Xray Gateway</div>
  </div>
</div>
<script>
const ALL_LINKS=[{conn_links_js}];
function copyLink(i){{
  const t=document.getElementById('conn-link-'+i).textContent.trim();
  navigator.clipboard.writeText(t).then(()=>{{
    const b=event.currentTarget;const o=b.innerHTML;
    b.innerHTML='<i class="ti ti-check"></i> کپی شد!';
    b.classList.add('btn-success');
    setTimeout(()=>{{b.innerHTML=o;b.classList.remove('btn-success')}},2000);
  }});
}}
function showQR(i){{
  const t=document.getElementById('conn-link-'+i).textContent.trim();
  window.open('https://api.qrserver.com/v1/create-qr-code/?size=300x300&data='+encodeURIComponent(t),'_blank');
}}
function copySubLink(){{
  const t=document.getElementById('sub-link').textContent.trim();
  navigator.clipboard.writeText(t).then(()=>{{
    const b=event.currentTarget;const o=b.innerHTML;
    b.innerHTML='<i class="ti ti-check"></i> کپی شد!';
    b.classList.add('btn-success');
    setTimeout(()=>{{b.innerHTML=o;b.classList.remove('btn-success')}},2000);
  }});
}}
function copyAllConfigs(){{
  const t=ALL_LINKS.filter(Boolean).join('\\n');
  navigator.clipboard.writeText(t).then(()=>{{
    const b=event.currentTarget;const o=b.innerHTML;
    b.innerHTML='<i class="ti ti-check"></i> همه کپی شد!';
    b.classList.add('btn-success');
    setTimeout(()=>{{b.innerHTML=o;b.classList.remove('btn-success')}},2500);
  }});
}}
</script>
</body>
</html>"""
    return HTMLResponse(content=html)

# ───────── Login Page ─────────
LOGIN_HTML = r"""<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no">
<title>ورود · tryak Xray</title>
<link href="https://fonts.googleapis.com/css2?family=Vazirmatn:wght@400;600;700;800&display=swap" rel="stylesheet">
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@tabler/icons-webfont@3.19.0/dist/tabler-icons.min.css">
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{--accent:#6366f1;--accent2:#4f46e5;--accent-glow:rgba(99,102,241,0.35);--bg:#0a0e17;--card:#10172a;--card2:#151d33;--border:#1f2940;--text-1:#eef2ff;--text-2:#7b8aab;--red-bg:#2a1212;--red-text:#f5a3a3;--green-text:#7ee0a8}
html,body{height:100%}
body{font-family:'Vazirmatn',sans-serif;background:radial-gradient(circle at 18% 18%,rgba(59,130,246,0.16),transparent 42%),radial-gradient(circle at 85% 80%,rgba(29,78,216,0.16),transparent 45%),var(--bg);min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px;color:var(--text-1)}
.card{background:var(--card);border-radius:20px;padding:36px 30px;width:100%;max-width:380px;box-shadow:0 24px 70px rgba(0,0,0,.55);border:1px solid var(--border);position:relative;overflow:hidden}
.card::before{content:'';position:absolute;top:-60%;right:-40%;width:280px;height:280px;background:radial-gradient(circle,var(--accent-glow),transparent 70%);pointer-events:none}
.logo{display:flex;flex-direction:column;align-items:center;gap:12px;margin-bottom:24px;position:relative;z-index:1}
.logo-icon{font-size:68px;font-weight:900;color:#6366f1;line-height:1;font-family:'Vazirmatn',sans-serif}
.logo-name{font-size:20px;font-weight:800;color:var(--text-1)}
.logo-sub{font-size:11px;color:var(--accent);font-weight:600;letter-spacing:.04em}
.status-pill{display:flex;align-items:center;justify-content:center;gap:7px;font-size:11px;color:var(--green-text);background:rgba(76,224,144,0.08);border:1px solid rgba(76,224,144,0.18);border-radius:20px;padding:6px 14px;margin-bottom:20px;position:relative;z-index:1;font-weight:500}
.dot{width:6px;height:6px;border-radius:50%;background:#4ce090;animation:pulse 2s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.35}}
.form-group{margin-bottom:14px;position:relative;z-index:1}
.form-label{font-size:11.5px;font-weight:600;color:var(--text-2);margin-bottom:6px;display:block}
.form-input{width:100%;padding:13px 15px;border-radius:11px;border:1px solid var(--border);font-family:inherit;font-size:14px;outline:none;background:var(--card2);color:var(--text-1);transition:.15s}
.form-input:focus{border-color:var(--accent);box-shadow:0 0 0 3px var(--accent-glow)}
.btn-login{width:100%;padding:14px;border-radius:11px;border:none;cursor:pointer;background:linear-gradient(135deg,var(--accent),var(--accent2));color:#fff;font-family:inherit;font-size:14px;font-weight:700;display:flex;align-items:center;justify-content:center;gap:8px;transition:.15s;box-shadow:0 4px 20px var(--accent-glow);position:relative;z-index:1}
.btn-login:hover{filter:brightness(1.1)}
.btn-login:disabled{opacity:.6;cursor:not-allowed}
.error-box{background:var(--red-bg);color:var(--red-text);font-size:12.5px;padding:10px 13px;border-radius:9px;margin-bottom:14px;display:none;align-items:center;gap:8px;border:1px solid rgba(240,128,128,.2);position:relative;z-index:1}
.error-box.show{display:flex}
.footer{margin-top:18px;text-align:center;font-size:11px;color:var(--text-2);position:relative;z-index:1}
</style>
</head>
<body>
<div class="card">
  <div class="logo">
    <div class="logo-icon">T</div>
    <div style="text-align:center">
      <div class="logo-name">tryak</div>
      <div class="logo-sub">Xray Gateway · v1.0</div>
    </div>
  </div>
  <div class="status-pill"><span class="dot"></span>سیستم آنلاین · Xray Core</div>
  <div class="error-box" id="err"><i class="ti ti-alert-circle"></i><span id="err-text"></span></div>
  <div class="form-group">
    <label class="form-label">رمز عبور</label>
    <input class="form-input" type="password" id="pw" placeholder="••••••••" autofocus>
  </div>
  <button class="btn-login" id="btn" onclick="doLogin()"><i class="ti ti-login-2"></i> ورود</button>
  <div class="footer">tryak · Railway / Render</div>
</div>
<script>
const err=document.getElementById('err');
const errT=document.getElementById('err-text');
const btn=document.getElementById('btn');
document.getElementById('pw').addEventListener('keydown',e=>{if(e.key==='Enter')doLogin()});
async function doLogin(){
  err.classList.remove('show');
  btn.disabled=true;
  btn.innerHTML='<i class="ti ti-loader-2"></i> در حال ورود...';
  const pw=document.getElementById('pw').value;
  try{
    const r=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:pw})});
    if(!r.ok){const d=await r.json().catch(()=>({}));throw new Error(d.detail||'رمز اشتباه است');}
    location.href='/dashboard';
  }catch(e){
    errT.textContent=e.message;err.classList.add('show');
    btn.disabled=false;btn.innerHTML='<i class="ti ti-login-2"></i> ورود';
  }
}
</script>
</body>
</html>"""

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    if await is_valid_session(request.cookies.get(SESSION_COOKIE)):
        return RedirectResponse("/dashboard")
    return HTMLResponse(content=LOGIN_HTML)

# ───────── Dashboard ─────────
DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>tryak · Xray داشبورد</title>
<link href="https://fonts.googleapis.com/css2?family=Vazirmatn:wght@400;500;600;700&display=swap" rel="stylesheet">
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@tabler/icons-webfont@3.19.0/dist/tabler-icons.min.css">
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.js"></script>
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{
  --accent:#6366f1;--accent2:#4f46e5;--accent-glow:rgba(99,102,241,0.35);
  --green-text:#7ee0a8;--green-dot:#4ce090;--red-text:#f5a3a3;--red-dot:#f56565;
  --amber-text:#f0c878;--amber-dot:#f0b14a;
  --border:#1f2940;--bg:#0a0e17;--card:#10172a;--card2:#151d33;
  --text-1:#eef2ff;--text-2:#7b8aab;--text-3:#475370;
  --shadow:0 1px 2px rgba(0,0,0,.5),0 1px 16px rgba(0,0,0,.35);
}
html,body{height:100%}
body{font-family:'Vazirmatn',sans-serif;background:radial-gradient(circle at 15% 10%,rgba(59,130,246,.10),transparent 40%),radial-gradient(circle at 90% 85%,rgba(29,78,216,.10),transparent 45%),var(--bg);color:var(--text-1);min-height:100vh;display:flex;font-size:14px}
::-webkit-scrollbar{width:5px;height:5px}
::-webkit-scrollbar-thumb{background:var(--card2);border-radius:3px}

/* SIDEBAR */
.sidebar{width:232px;min-height:100vh;background:linear-gradient(180deg,var(--card) 0%,#070c18 100%);border-left:1px solid var(--border);display:flex;flex-direction:column;flex-shrink:0;position:fixed;right:0;top:0;bottom:0;z-index:200;transition:transform .25s}
.logo{display:flex;align-items:center;gap:10px;padding:20px 16px;border-bottom:1px solid var(--border)}
.logo-icon{font-size:38px;font-weight:900;color:#6366f1;line-height:1;font-family:'Vazirmatn',sans-serif}
.logo-name{color:#fff;font-size:15px;font-weight:700}
.logo-sub{color:var(--accent);font-size:10.5px;margin-top:1px}
.sidebar-close{display:none;position:absolute;left:12px;top:16px;background:var(--card2);border:none;color:#fff;width:32px;height:32px;border-radius:8px;font-size:17px;align-items:center;justify-content:center;cursor:pointer}
.nav-scroll{flex:1;overflow-y:auto;padding-bottom:10px}
.nav-label{color:var(--text-3);font-size:10px;letter-spacing:.1em;padding:16px 18px 5px;text-transform:uppercase;font-weight:600}
.nav-item{display:flex;align-items:center;gap:10px;padding:10px 18px;color:var(--text-2);font-size:13px;cursor:pointer;border-left:3px solid transparent;transition:.15s;user-select:none}
.nav-item i{font-size:17px;width:20px;text-align:center}
.nav-item:hover{background:rgba(255,255,255,.03);color:#fff}
.nav-item.active{background:linear-gradient(90deg,rgba(59,130,246,.16),rgba(59,130,246,.02));color:#fff;border-left-color:var(--accent)}
.sidebar-footer{padding:14px 16px;border-top:1px solid var(--border)}
.logout-btn{display:flex;align-items:center;justify-content:center;gap:8px;background:rgba(245,101,101,.1);color:var(--red-text);border-radius:10px;padding:10px;font-size:12.5px;font-weight:500;font-family:inherit;border:1px solid rgba(245,101,101,.2);cursor:pointer;width:100%;transition:.15s}
.logout-btn:hover{background:rgba(245,101,101,.2);color:#fff}

/* MOBILE */
.mobile-topbar{display:none;position:fixed;top:0;right:0;left:0;height:54px;background:linear-gradient(180deg,var(--card) 0%,#070c18 100%);border-bottom:1px solid var(--border);z-index:150;align-items:center;justify-content:space-between;padding:0 14px}
.mt-title{color:#fff;font-size:14px;font-weight:700}
.menu-btn{background:var(--card2);border:none;color:#fff;width:36px;height:36px;border-radius:9px;font-size:18px;display:flex;align-items:center;justify-content:center;cursor:pointer}
.sidebar-overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,.55);z-index:190;backdrop-filter:blur(2px)}
.sidebar-overlay.show{display:block}

/* MAIN */
.main{margin-right:232px;flex:1;padding:24px 26px 50px;max-width:calc(100% - 232px)}
.page{display:none}
.page.active{display:block;animation:fadeIn .22s ease}
@keyframes fadeIn{from{opacity:0;transform:translateY(5px)}to{opacity:1;transform:none}}
.topbar{display:flex;align-items:center;justify-content:space-between;margin-bottom:24px;flex-wrap:wrap;gap:10px}
.topbar-title{font-size:19px;font-weight:700;color:var(--text-1);display:flex;align-items:center;gap:8px}
.topbar-title i{color:var(--accent);font-size:21px}
.topbar-sub{font-size:12px;color:var(--text-2);margin-top:2px}

/* METRICS */
.metrics{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:20px}
.metric{background:var(--card);border-radius:13px;border:1px solid var(--border);padding:16px 18px;box-shadow:var(--shadow)}
.metric-label{font-size:10.5px;color:var(--text-2);font-weight:600;text-transform:uppercase;letter-spacing:.06em;margin-bottom:10px;display:flex;align-items:center;gap:6px}
.metric-label i{font-size:16px;color:var(--accent)}
.metric-val{font-size:24px;font-weight:700;color:var(--text-1);line-height:1}
.metric-sub{font-size:11px;color:var(--text-2);margin-top:4px}

/* CARDS */
.card{background:var(--card);border-radius:13px;border:1px solid var(--border);padding:18px 20px;box-shadow:var(--shadow)}
.card-title{font-size:13px;font-weight:700;color:var(--text-1);margin-bottom:14px;display:flex;align-items:center;gap:7px}
.card-title i{font-size:17px;color:var(--accent)}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:18px}

/* BUTTONS */
.btn{font-family:inherit;font-size:12.5px;font-weight:600;border-radius:9px;padding:8px 14px;cursor:pointer;display:inline-flex;align-items:center;gap:6px;border:none;transition:.15s}
.btn-primary{background:linear-gradient(135deg,var(--accent),var(--accent2));color:#fff;box-shadow:0 2px 10px var(--accent-glow)}
.btn-primary:hover{filter:brightness(1.1)}
.btn-outline{background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.15);color:var(--text-2)}
.btn-outline:hover{background:rgba(255,255,255,.08);color:#fff}
.btn-danger{background:rgba(245,101,101,.1);color:var(--red-text);border:1px solid rgba(245,101,101,.25)}
.btn-danger:hover{background:rgba(245,101,101,.2)}
.btn-sm{padding:5px 10px;font-size:11.5px;border-radius:7px}
.btn i{font-size:14px}
.btn:disabled{opacity:.5;cursor:not-allowed}

/* FORM */
.form-row{display:flex;gap:10px;flex-wrap:wrap;align-items:flex-end;margin-bottom:14px}
.form-group{display:flex;flex-direction:column;gap:5px}
.form-label{font-size:11px;color:var(--text-2);font-weight:600}
.form-input,.form-select{padding:9px 12px;border-radius:9px;border:1px solid var(--border);font-family:inherit;font-size:12.5px;outline:none;color:var(--text-1);background:var(--card2);min-width:110px;transition:.15s}
.form-input:focus,.form-select:focus{border-color:var(--accent);box-shadow:0 0 0 3px var(--accent-glow)}
.form-select option{background:var(--card2)}

/* TABLE */
.links-table{width:100%;border-collapse:collapse}
.links-table th{text-align:right;font-size:11px;color:var(--text-2);font-weight:600;padding:8px 7px;border-bottom:2px solid var(--border);white-space:nowrap}
.links-table td{padding:12px 7px;border-bottom:1px solid var(--border);font-size:12px;vertical-align:middle}
.links-table tr:last-child td{border-bottom:none}
.links-table tr:hover td{background:var(--card2)}
.usage-bar{height:6px;border-radius:3px;background:var(--card2);overflow:hidden;margin-bottom:3px;min-width:100px}
.usage-bar-fill{height:100%;border-radius:3px;transition:width .3s}
.usage-text{font-size:10px;color:var(--text-2)}
.empty-state{text-align:center;padding:44px 20px;color:var(--text-2)}
.empty-state i{font-size:40px;color:var(--border);margin-bottom:10px;display:block}

/* OVERVIEW CLIENTS LIST */
.ov-client-row{display:flex;align-items:center;justify-content:space-between;gap:10px;padding:10px 4px;border-top:1px solid var(--border)}
.ov-client-row:first-child{border-top:none}
.ov-client-left{display:flex;align-items:center;gap:8px;min-width:0}
.ov-client-name{font-weight:600;font-size:12.5px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:160px}
.ov-client-meta{font-size:10.5px;color:var(--text-2);white-space:nowrap}
.ov-client-right{display:flex;align-items:center;gap:8px;flex-shrink:0}

/* BADGES / PILLS */
.pill{display:inline-flex;align-items:center;gap:5px;padding:3px 10px;border-radius:20px;font-size:10.5px;font-weight:600}
.pill-green{background:rgba(76,224,144,.1);border:1px solid rgba(76,224,144,.2);color:var(--green-text)}
.pill-red{background:rgba(245,101,101,.1);border:1px solid rgba(245,101,101,.2);color:var(--red-text)}
.pill-amber{background:rgba(240,177,74,.1);border:1px solid rgba(240,177,74,.2);color:var(--amber-text)}
.pill-blue{background:rgba(59,130,246,.1);border:1px solid rgba(59,130,246,.2);color:#93c5fd}
.pill-dot{width:5px;height:5px;border-radius:50%;background:currentColor}
.proto-badge{display:inline-block;font-size:10px;background:rgba(99,102,241,.12);color:#a5b4fc;border:1px solid rgba(99,102,241,.2);border-radius:6px;padding:2px 7px;font-weight:600}

/* TOGGLE */
.toggle{width:36px;height:20px;border-radius:20px;background:var(--card2);position:relative;cursor:pointer;transition:.2s;flex-shrink:0;border:none}
.toggle::after{content:'';position:absolute;width:14px;height:14px;border-radius:50%;background:#fff;top:3px;right:3px;transition:.2s;box-shadow:0 1px 3px rgba(0,0,0,.4)}
.toggle.on{background:var(--green-dot)}
.toggle.on::after{right:19px}

/* TOAST */
.toast{position:fixed;bottom:26px;left:50%;transform:translateX(-50%) translateY(40px);background:var(--card);color:#fff;border:1px solid var(--border);border-radius:10px;padding:10px 20px;font-size:13px;opacity:0;transition:all .3s;z-index:999;pointer-events:none;display:flex;align-items:center;gap:8px;box-shadow:0 6px 24px rgba(0,0,0,.4)}
.toast.show{opacity:1;transform:translateX(-50%) translateY(0)}
.toast.err{background:#3b1515;border-color:var(--red-dot)}

/* MODAL */
.modal-overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,.65);z-index:500;align-items:center;justify-content:center;backdrop-filter:blur(2px);padding:16px}
.modal-overlay.show{display:flex}
.modal{background:var(--card);border-radius:16px;border:1px solid var(--border);padding:26px 24px;width:100%;max-width:480px;max-height:90vh;overflow-y:auto}
.modal-title{font-size:15px;font-weight:700;color:var(--text-1);margin-bottom:20px;display:flex;align-items:center;gap:8px}
.modal-title i{font-size:18px;color:var(--accent)}
.modal-footer{display:flex;gap:10px;justify-content:flex-end;margin-top:20px;padding-top:16px;border-top:1px solid var(--border)}

/* XRAY STATUS CARD */
.xray-status-card{background:linear-gradient(135deg,rgba(99,102,241,.12),rgba(29,78,216,.06));border:1px solid rgba(99,102,241,.2);border-radius:13px;padding:18px 20px;margin-bottom:18px;display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap}
.xray-info{display:flex;align-items:center;gap:12px}
.xray-icon{width:44px;height:44px;border-radius:12px;background:rgba(99,102,241,.15);display:flex;align-items:center;justify-content:center;font-size:22px;color:var(--accent)}
.xray-name{font-size:14px;font-weight:700;color:#fff;margin-bottom:3px}
.xray-pid{font-size:11px;color:var(--text-2);font-family:ui-monospace,monospace}

/* CONN DETAIL */
.conn-box{background:var(--card2);border-radius:10px;border:1px solid var(--border);padding:12px 14px;font-family:ui-monospace,monospace;font-size:10.5px;color:#93c5fd;word-break:break-all;line-height:1.8;margin-bottom:10px}

/* STATUS ROW */
.status-row{display:flex;align-items:center;justify-content:space-between;padding:9px 0;border-bottom:1px solid var(--border);font-size:12.5px}
.status-row:last-child{border-bottom:none}
.status-key{color:var(--text-2);display:flex;align-items:center;gap:7px}
.status-key i{font-size:14px}
.status-val{color:#93c5fd;font-weight:600}

/* RESPONSIVE */
@media(max-width:900px){
  .metrics{grid-template-columns:1fr 1fr}
  .sidebar{transform:translateX(100%)}
  .sidebar.open{transform:translateX(0)}
  .sidebar-close{display:flex}
  .main{margin-right:0;max-width:100%;padding:70px 14px 40px}
  .mobile-topbar{display:flex}
}
@media(max-width:560px){
  .metrics{grid-template-columns:1fr 1fr}
  .grid2{grid-template-columns:1fr}
  .links-table{display:block;overflow-x:auto}
}
</style>
</head>
<body>
<div class="sidebar" id="sidebar">
  <div class="logo">
    <div class="logo-icon">T</div>
    <div><div class="logo-name">tryak</div><div class="logo-sub">Xray Gateway</div></div>
  </div>
  <button class="sidebar-close" onclick="closeSidebar()"><i class="ti ti-x"></i></button>
  <div class="nav-scroll">
    <div class="nav-label">منو</div>
    <div class="nav-item active" onclick="showPage('overview')"><i class="ti ti-layout-dashboard"></i>داشبورد</div>
    <div class="nav-item" onclick="showPage('links')"><i class="ti ti-users"></i>لینک‌ها</div>
    <div class="nav-item" onclick="showPage('xray')"><i class="ti ti-cpu"></i>Xray Core</div>
    <div class="nav-item" onclick="showPage('blocked')"><i class="ti ti-shield-off"></i>بلاک‌ها</div>
  </div>
  <div class="sidebar-footer">
    <button class="logout-btn" onclick="doLogout()"><i class="ti ti-logout"></i>خروج</button>
  </div>
</div>
<div class="sidebar-overlay" id="overlay" onclick="closeSidebar()"></div>

<div class="mobile-topbar">
  <span class="mt-title">tryak · Xray</span>
  <button class="menu-btn" onclick="openSidebar()"><i class="ti ti-menu-2"></i></button>
</div>

<div class="main">

  <!-- OVERVIEW -->
  <div class="page active" id="page-overview">
    <div class="topbar">
      <div><div class="topbar-title"><i class="ti ti-layout-dashboard"></i>داشبورد</div>
      <div class="topbar-sub" id="uptime-text">در حال بارگذاری...</div></div>
      <button class="btn btn-outline btn-sm" onclick="loadStats()"><i class="ti ti-refresh"></i>بروزرسانی</button>
    </div>
    <div class="metrics">
      <div class="metric"><div class="metric-label"><i class="ti ti-users"></i>لینک‌ها</div><div class="metric-val" id="m-links">—</div><div class="metric-sub">تعداد کل</div></div>
      <div class="metric"><div class="metric-label"><i class="ti ti-cpu"></i>CPU</div><div class="metric-val" id="m-cpu">—</div><div class="metric-sub">درصد مصرف</div></div>
      <div class="metric"><div class="metric-label"><i class="ti ti-brain"></i>RAM</div><div class="metric-val" id="m-ram">—</div><div class="metric-sub">درصد مصرف</div></div>
      <div class="metric"><div class="metric-label"><i class="ti ti-shield"></i>بلاک‌شده</div><div class="metric-val" id="m-blocked">—</div><div class="metric-sub">IP</div></div>
    </div>
    <div class="grid2">
      <div class="card">
        <div class="card-title"><i class="ti ti-server"></i>وضعیت سیستم</div>
        <div id="sys-rows"><div style="color:var(--text-2);font-size:12px">در حال بارگذاری...</div></div>
      </div>
      <div class="card">
        <div class="card-title"><i class="ti ti-chart-bar"></i>ترافیک امروز</div>
        <div id="chart-today-total" style="font-size:22px;font-weight:700;margin:4px 0 14px">—</div>
        <div id="chart-today"><div style="color:var(--text-2);font-size:12px;padding:20px 0;text-align:center">در حال بارگذاری...</div></div>
      </div>
    </div>

    <div class="card" style="margin-top:16px">
      <div class="card-title"><i class="ti ti-users"></i>کلاینت‌های ساخته‌شده</div>
      <div id="overview-clients-list" style="margin-top:6px"><div style="color:var(--text-2);font-size:12px;padding:14px 0;text-align:center">در حال بارگذاری...</div></div>
    </div>
  </div>

  <!-- LINKS -->
  <div class="page" id="page-links">
    <div class="topbar">
      <div><div class="topbar-title"><i class="ti ti-users"></i>مدیریت لینک‌ها</div></div>
      <button class="btn btn-primary" onclick="showCreateModal()"><i class="ti ti-plus"></i>لینک جدید</button>
    </div>
    <div class="card" style="margin-bottom:16px;overflow-x:auto">
      <table class="links-table">
        <thead>
          <tr>
            <th>نام</th><th>پروتکل</th><th>مصرف</th><th>وضعیت</th><th>انقضا</th><th>عملیات</th>
          </tr>
        </thead>
        <tbody id="links-tbody"><tr><td colspan="6" class="empty-state"><i class="ti ti-loader-2"></i>در حال بارگذاری...</td></tr></tbody>
      </table>
    </div>
  </div>

  <!-- XRAY -->
  <div class="page" id="page-xray">
    <div class="topbar">
      <div><div class="topbar-title"><i class="ti ti-cpu"></i>Xray Core</div></div>
      <button class="btn btn-primary" onclick="restartXray()"><i class="ti ti-refresh"></i>ریستارت Xray</button>
    </div>
    <div class="xray-status-card">
      <div class="xray-info">
        <div class="xray-icon"><i class="ti ti-cpu"></i></div>
        <div>
          <div class="xray-name">Xray Core</div>
          <div class="xray-pid" id="xray-pid">در حال بررسی...</div>
        </div>
      </div>
      <div id="xray-pill"></div>
    </div>
    <div class="grid2">
      <div class="card">
        <div class="card-title"><i class="ti ti-network"></i>پورت‌های فعال</div>
        <div id="xray-ports"></div>
      </div>
      <div class="card">
        <div class="card-title"><i class="ti ti-code"></i>کانفیگ فعلی Xray</div>
        <button class="btn btn-outline btn-sm" style="margin-bottom:10px" onclick="loadXrayConfig()"><i class="ti ti-eye"></i>نمایش کانفیگ</button>
        <pre id="xray-config-view" style="font-size:10px;color:#93c5fd;background:var(--card2);border:1px solid var(--border);border-radius:8px;padding:12px;overflow-x:auto;white-space:pre-wrap;display:none;max-height:360px;overflow-y:auto"></pre>
      </div>
    </div>
  </div>

  <!-- BLOCKED -->
  <div class="page" id="page-blocked">
    <div class="topbar">
      <div><div class="topbar-title"><i class="ti ti-shield-off"></i>IP های بلاک‌شده</div></div>
    </div>
    <div class="card" style="margin-bottom:16px">
      <div class="form-row">
        <div class="form-group" style="flex:1"><div class="form-label">آدرس IP</div><input class="form-input" id="block-ip-input" placeholder="1.2.3.4" style="width:100%"></div>
        <button class="btn btn-danger" onclick="blockIP()"><i class="ti ti-shield-plus"></i>بلاک</button>
      </div>
      <div id="blocked-list" style="margin-top:8px"></div>
    </div>
  </div>

</div><!-- /main -->

<!-- TOAST -->
<div class="toast" id="toast"></div>

<!-- CREATE MODAL -->
<div class="modal-overlay" id="create-modal">
  <div class="modal">
    <div class="modal-title"><i class="ti ti-plus"></i>ایجاد لینک جدید</div>
    <div class="form-row">
      <div class="form-group" style="flex:1"><div class="form-label">نام / برچسب</div><input class="form-input" id="new-label" placeholder="کاربر جدید" style="width:100%"></div>
    </div>
    <div class="form-row">
      <div class="form-group" style="flex:1">
        <div class="form-label">پروتکل (می‌توانید چند مورد را با هم انتخاب کنید)</div>
        <div id="new-proto-group" style="display:flex;flex-wrap:wrap;gap:8px">
          <label style="display:flex;align-items:center;gap:5px;font-size:12.5px;background:var(--card2);border:1px solid var(--border);border-radius:8px;padding:6px 10px;cursor:pointer">
            <input type="checkbox" class="new-proto-cb" value="vless" checked onchange="onProtoChange()"> VLESS+WS
          </label>
          <label style="display:flex;align-items:center;gap:5px;font-size:12.5px;background:var(--card2);border:1px solid var(--border);border-radius:8px;padding:6px 10px;cursor:pointer">
            <input type="checkbox" class="new-proto-cb" value="vless-xhttp" onchange="onProtoChange()"> XHTTP
          </label>
          <label style="display:flex;align-items:center;gap:5px;font-size:12.5px;background:var(--card2);border:1px solid var(--border);border-radius:8px;padding:6px 10px;cursor:pointer">
            <input type="checkbox" class="new-proto-cb" value="vless-reality" onchange="onProtoChange()"> Reality
          </label>
          <label style="display:flex;align-items:center;gap:5px;font-size:12.5px;background:var(--card2);border:1px solid var(--border);border-radius:8px;padding:6px 10px;cursor:pointer">
            <input type="checkbox" class="new-proto-cb" value="trojan" onchange="onProtoChange()"> Trojan
          </label>
        </div>
      </div>
    </div>
    <div class="form-row" id="password-row">
      <div class="form-group" style="flex:1"><div class="form-label">رمز عبور (اختیاری — تولید خودکار)</div><input class="form-input" id="new-password" placeholder="خودکار" style="width:100%"></div>
    </div>
    <div class="form-row">
      <div class="form-group"><div class="form-label">حجم (۰=نامحدود)</div><input class="form-input" id="new-limit" type="number" value="0" min="0" style="width:90px"></div>
      <div class="form-group"><div class="form-label">واحد</div>
        <select class="form-select" id="new-unit"><option>GB</option><option>MB</option></select>
      </div>
      <div class="form-group"><div class="form-label">مدت (روز، ۰=نامحدود)</div><input class="form-input" id="new-expire" type="number" value="0" min="0" style="width:100px"></div>
    </div>
    <div class="modal-footer">
      <button class="btn btn-outline" onclick="hideCreateModal()">لغو</button>
      <button class="btn btn-primary" id="create-link-btn" onclick="createLink()"><i class="ti ti-plus"></i>ایجاد لینک</button>
    </div>
  </div>
</div>

<!-- DETAIL MODAL -->
<div class="modal-overlay" id="detail-modal">
  <div class="modal">
    <div class="modal-title"><i class="ti ti-link"></i><span id="detail-title">جزئیات لینک</span></div>
    <div id="detail-content"></div>
    <div class="modal-footer"><button class="btn btn-outline" onclick="hideDetailModal()">بستن</button></div>
  </div>
</div>

<script>
let allLinks=[];

// ── Navigation ──
function showPage(name){
  document.querySelectorAll('.page').forEach(p=>p.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(n=>n.classList.remove('active'));
  document.getElementById('page-'+name).classList.add('active');
  document.querySelector(`.nav-item[onclick="showPage('${name}')"]`).classList.add('active');
  closeSidebar();
  if(name==='overview') loadStats();
  if(name==='links') loadLinks();
  if(name==='xray') loadXrayStatus();
  if(name==='blocked') loadBlocked();
}
function openSidebar(){document.getElementById('sidebar').classList.add('open');document.getElementById('overlay').classList.add('show')}
function closeSidebar(){document.getElementById('sidebar').classList.remove('open');document.getElementById('overlay').classList.remove('show')}

// ── Toast ──
function toast(msg,err=false){
  const t=document.getElementById('toast');
  t.innerHTML=(err?'<i class="ti ti-alert-circle"></i>':'<i class="ti ti-check"></i>')+msg;
  t.className='toast show'+(err?' err':'');
  setTimeout(()=>t.classList.remove('show'),2800);
}

// ── Logout ──
async function doLogout(){
  await fetch('/api/logout',{method:'POST'});
  location.href='/login';
}

// ── Stats ──
async function loadStats(){
  try{
    const r=await fetch('/stats');
    if(!r.ok) return;
    const d=await r.json();
    document.getElementById('uptime-text').textContent='آپتایم: '+d.uptime+' · '+d.platform;
    document.getElementById('m-links').textContent=d.links_count;
    document.getElementById('m-cpu').textContent=d.cpu_percent+'%';
    document.getElementById('m-ram').textContent=d.memory_percent+'%';
    document.getElementById('m-blocked').textContent=d.blocked_ips;
    const xr=d.xray;
    let rows=`
      <div class="status-row"><span class="status-key"><i class="ti ti-brand-xing"></i>Xray</span><span class="status-val">${xr.running?'<span style="color:var(--green-text)">✅ در حال اجرا</span>':'<span style="color:var(--red-text)">❌ متوقف</span>'}</span></div>
      <div class="status-row"><span class="status-key"><i class="ti ti-cpu"></i>CPU</span><span class="status-val">${d.cpu_percent}%</span></div>
      <div class="status-row"><span class="status-key"><i class="ti ti-brain"></i>RAM</span><span class="status-val">${d.memory_percent}%</span></div>
      <div class="status-row"><span class="status-key"><i class="ti ti-clock"></i>آپتایم</span><span class="status-val">${d.uptime}</span></div>
      <div class="status-row"><span class="status-key"><i class="ti ti-cloud"></i>پلتفرم</span><span class="status-val">${d.platform}</span></div>
    `;
    document.getElementById('sys-rows').innerHTML=rows;
  }catch(e){console.error(e)}
  loadTrafficChart();
  loadOverviewClients();
}

// ── Traffic chart (امروز) ──
async function loadTrafficChart(){
  const totalEl=document.getElementById('chart-today-total');
  const box=document.getElementById('chart-today');
  try{
    const r=await fetch('/api/traffic/today');
    if(!r.ok) throw new Error();
    const d=await r.json();
    totalEl.textContent=fmtBytes(d.total_bytes)+' امروز';
    const points=d.points||[];
    const maxVal=Math.max(1,...points.map(p=>p.bytes));
    const nowHour=new Date().getHours();
    const W=300,H=110,padB=18,padT=4,barGap=2;
    const barW=(W/24)-barGap;
    let bars='';
    points.forEach((p,i)=>{
      const h=p.bytes>0?Math.max(2,Math.round((p.bytes/maxVal)*(H-padT-padB))):0;
      const x=i*(W/24)+barGap/2;
      const y=H-padB-h;
      const future=p.hour>nowHour;
      const fill=future?'rgba(255,255,255,.05)':'url(#barGrad)';
      bars+=`<rect x="${x.toFixed(1)}" y="${y}" width="${barW.toFixed(1)}" height="${h}" rx="2" fill="${fill}">
        <title>${String(p.hour).padStart(2,'0')}:00 — ${fmtBytes(p.bytes)}</title>
      </rect>`;
    });
    const labelEvery=4;
    let labels='';
    points.forEach((p,i)=>{
      if(p.hour%labelEvery===0){
        const x=i*(W/24)+(W/24)/2;
        labels+=`<text x="${x.toFixed(1)}" y="${H-4}" font-size="7" fill="var(--text-3)" text-anchor="middle">${String(p.hour).padStart(2,'0')}</text>`;
      }
    });
    box.innerHTML=`<svg viewBox="0 0 ${W} ${H}" style="width:100%;height:130px;overflow:visible">
      <defs><linearGradient id="barGrad" x1="0" y1="0" x2="0" y2="1">
        <stop offset="0%" stop-color="#6366f1"/><stop offset="100%" stop-color="#3b82f6"/>
      </linearGradient></defs>
      ${bars}${labels}
    </svg>`;
  }catch(e){
    box.innerHTML='<div style="color:var(--text-2);font-size:12px;padding:20px 0;text-align:center">خطا در دریافت ترافیک</div>';
  }
}

// ── Overview: clients summary ──
async function loadOverviewClients(){
  const box=document.getElementById('overview-clients-list');
  try{
    const r=await fetch('/api/links');
    if(!r.ok) throw new Error();
    const d=await r.json();
    const links=d.links||[];
    if(!links.length){
      box.innerHTML='<div style="color:var(--text-2);font-size:12px;padding:14px 0;text-align:center">هنوز کلاینتی ساخته نشده</div>';
      return;
    }
    box.innerHTML=links.map(l=>{
      const statusDot=l.active&&!l.is_expired&&!l.quota_exceeded?'pill-green':'pill-red';
      const protos=(l.protocols&&l.protocols.length?l.protocols:[l.protocol]);
      const protoStr=protos.map(p=>PROTO_LABELS[p]||p).join(' · ');
      return `<div class="ov-client-row">
        <div class="ov-client-left">
          <span class="pill ${statusDot}" style="padding:3px 6px"><span class="pill-dot"></span></span>
          <div>
            <div class="ov-client-name">${l.label}</div>
            <div class="ov-client-meta">${protoStr}</div>
          </div>
        </div>
        <div class="ov-client-right">
          <span class="ov-client-meta">${fmtBytes(l.used_bytes)}</span>
          <button class="btn btn-outline btn-sm" onclick='showDetail(${JSON.stringify(l)})'><i class="ti ti-eye"></i></button>
        </div>
      </div>`;
    }).join('');
  }catch(e){
    box.innerHTML='<div style="color:var(--text-2);font-size:12px;padding:14px 0;text-align:center">خطا در دریافت کلاینت‌ها</div>';
  }
}

// ── Links ──
async function loadLinks(){
  try{
    const r=await fetch('/api/links');
    if(!r.ok) return;
    const d=await r.json();
    allLinks=d.links;
    renderLinksTable(allLinks);
  }catch(e){console.error(e)}
}

const PROTO_LABELS={vless:'VLESS',trojan:'Trojan','vless-xhttp':'XHTTP','vless-reality':'Reality'};
const PROTO_COLORS={vless:'pill-blue',trojan:'pill-amber','vless-xhttp':'pill-blue','vless-reality':'pill-green'};

function renderLinksTable(links){
  const tbody=document.getElementById('links-tbody');
  if(!links.length){
    tbody.innerHTML='<tr><td colspan="6"><div class="empty-state"><i class="ti ti-users-minus"></i>هنوز لینکی ایجاد نشده</div></td></tr>';
    return;
  }
  tbody.innerHTML=links.map(l=>{
    const usedPct=l.limit_bytes>0?Math.min(100,Math.round(l.used_bytes/l.limit_bytes*100)):0;
    const barColor=usedPct<70?'#6366f1':usedPct<90?'#f0b14a':'#f56565';
    const usedStr=fmtBytes(l.used_bytes);
    const limitStr=l.limit_bytes>0?fmtBytes(l.limit_bytes):'♾️';
    const statusPill=l.active&&!l.is_expired&&!l.quota_exceeded
      ?'<span class="pill pill-green"><span class="pill-dot"></span>فعال</span>'
      :l.is_expired?'<span class="pill pill-red"><span class="pill-dot"></span>منقضی</span>'
      :l.quota_exceeded?'<span class="pill pill-amber"><span class="pill-dot"></span>تمام‌شده</span>'
      :'<span class="pill pill-red"><span class="pill-dot"></span>غیرفعال</span>';
    const expStr=l.expires_at?`${Math.max(0,Math.round(l.days_left))} روز`:'♾️';
    const protos=(l.protocols&&l.protocols.length?l.protocols:[l.protocol]);
    const protoBadges=protos.map(p=>`<span class="proto-badge">${PROTO_LABELS[p]||p}</span>`).join(' ');
    return `<tr>
      <td style="font-weight:600;max-width:140px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">${l.label}</td>
      <td><div style="display:flex;gap:4px;flex-wrap:wrap">${protoBadges}</div></td>
      <td>
        <div class="usage-bar"><div class="usage-bar-fill" style="width:${usedPct}%;background:${barColor}"></div></div>
        <div class="usage-text">${usedStr} / ${limitStr}</div>
      </td>
      <td>${statusPill}</td>
      <td style="font-size:11px;color:var(--text-2)">${expStr}</td>
      <td>
        <div style="display:flex;gap:6px;flex-wrap:wrap">
          <button class="btn btn-outline btn-sm" onclick='showDetail(${JSON.stringify(l)})'><i class="ti ti-eye"></i></button>
          <button class="btn btn-outline btn-sm" onclick="toggleLink('${l.uuid}',${!l.active})">${l.active?'<i class="ti ti-player-pause"></i>':'<i class="ti ti-player-play"></i>'}</button>
          <button class="btn btn-danger btn-sm" onclick="deleteLink('${l.uuid}')"><i class="ti ti-trash"></i></button>
        </div>
      </td>
    </tr>`;
  }).join('');
}

function fmtBytes(b){
  if(!b) return '0 B';
  if(b>=1024**3) return (b/1024**3).toFixed(1)+' GB';
  if(b>=1024**2) return (b/1024**2).toFixed(1)+' MB';
  return (b/1024).toFixed(1)+' KB';
}

// ── Create Link ──
function showCreateModal(){document.getElementById('create-modal').classList.add('show')}
function hideCreateModal(){document.getElementById('create-modal').classList.remove('show')}
function selectedProtocols(){
  return Array.from(document.querySelectorAll('.new-proto-cb:checked')).map(cb=>cb.value);
}
function onProtoChange(){
  const protos=selectedProtocols();
  document.getElementById('password-row').style.display=protos.includes('trojan')?'flex':'none';
}

let _creatingLink=false;
async function createLink(){
  if(_creatingLink) return;
  const protocols=selectedProtocols();
  if(!protocols.length){ toast('حداقل یک پروتکل را انتخاب کنید',true); return; }
  const label=document.getElementById('new-label').value.trim()||'لینک جدید';
  const password=document.getElementById('new-password').value.trim()||undefined;
  const limit_value=parseFloat(document.getElementById('new-limit').value)||0;
  const limit_unit=document.getElementById('new-unit').value;
  const expire_days=parseFloat(document.getElementById('new-expire').value)||0;

  const btn=document.getElementById('create-link-btn');
  _creatingLink=true;
  if(btn){ btn.disabled=true; btn.dataset.orig=btn.innerHTML; btn.innerHTML='<i class="ti ti-loader-2"></i> در حال ایجاد...'; }
  try{
    const r=await fetch('/api/links',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({label,protocols,password,limit_value,limit_unit,expire_days})});
    if(!r.ok) throw new Error((await r.json()).detail||'خطا');
    const d=await r.json();
    toast('لینک ایجاد شد ✅');
    hideCreateModal();
    // به‌جای صرفاً صدا زدن loadLinks() (که نتیجه‌اش ممکنه با تاخیر برسه)، لینک تازه‌ساخته‌شده
    // را فوری به لیست محلی اضافه می‌کنیم تا بدون نیاز به رفرش صفحه نمایش داده شود.
    allLinks.unshift(d);
    renderLinksTable(allLinks);
    loadLinks(); // هماهنگ‌سازی نهایی با سرور (idempotent، چیزی تکراری اضافه نمی‌کند)
    showDetail(d);
  }catch(e){toast(e.message,true)}
  finally{
    _creatingLink=false;
    if(btn){ btn.disabled=false; btn.innerHTML=btn.dataset.orig||'<i class="ti ti-plus"></i>ایجاد لینک'; }
  }
}

// ── Detail Modal ──
function showDetail(l){
  document.getElementById('detail-title').textContent=l.label||'جزئیات لینک';
  const conns=(l.connections&&l.connections.length)?l.connections:[l.connection||{}];
  let html='';
  conns.forEach((conn,i)=>{
    html+=`<div style="margin-bottom:14px;${i>0?'padding-top:14px;border-top:1px solid var(--border)':''}">
      <div style="margin-bottom:8px"><span class="proto-badge" style="font-size:11px;padding:4px 10px">${conn.protocol||''}</span></div>
      <div class="conn-box" id="modal-conn-link-${i}">${conn.link||'—'}</div>
      <div style="display:flex;gap:8px;margin-top:8px">
        <button class="btn btn-primary btn-sm" onclick="copyModalLink(${i})"><i class="ti ti-copy"></i>کپی</button>
        ${conn.link&&conn.protocol!=='HTTP Proxy'?`<button class="btn btn-outline btn-sm" onclick="showQRModal(${i})"><i class="ti ti-qrcode"></i>QR</button>`:''}
      </div>
      ${conn.server?`<div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;font-size:12px;margin-top:10px">
        <div><div class="form-label">سرور</div><div style="color:var(--text-1);margin-top:3px">${conn.server}</div></div>
        <div><div class="form-label">پورت</div><div style="color:var(--text-1);margin-top:3px">${conn.port}</div></div>
        ${conn.path?`<div><div class="form-label">مسیر</div><div style="color:var(--text-1);margin-top:3px">${conn.path}</div></div>`:''}
        ${conn.username?`<div><div class="form-label">نام کاربری</div><div style="color:var(--text-1);margin-top:3px">${conn.username}</div></div>`:''}
      </div>`:''}
    </div>`;
  });
  html+=`<div style="margin-top:6px;display:flex;flex-direction:column;gap:8px">
    <a href="/sub/${l.uuid}" target="_blank" class="btn btn-outline btn-sm" style="text-decoration:none;width:100%;justify-content:center"><i class="ti ti-external-link"></i>صفحه اشتراک (همه‌ی پروتکل‌ها)</a>
    <button class="btn btn-outline btn-sm" onclick="copySubscriptionLink('${l.uuid}')" style="width:100%;justify-content:center"><i class="ti ti-rss"></i>کپی لینک ساب (Import خودکار)</button>
  </div>`;
  document.getElementById('detail-content').innerHTML=html;
  document.getElementById('detail-modal').classList.add('show');
}
function copySubscriptionLink(uid){
  const t=window.location.origin+'/sub/'+uid+'/raw';
  navigator.clipboard.writeText(t).then(()=>toast('لینک ساب کپی شد ✅'));
}
function hideDetailModal(){document.getElementById('detail-modal').classList.remove('show')}
function copyModalLink(i){
  const t=document.getElementById('modal-conn-link-'+(i||0)).textContent.trim();
  navigator.clipboard.writeText(t).then(()=>toast('کپی شد ✅'));
}
function showQRModal(i){
  const t=document.getElementById('modal-conn-link-'+(i||0)).textContent.trim();
  window.open('https://api.qrserver.com/v1/create-qr-code/?size=300x300&data='+encodeURIComponent(t),'_blank');
}

// ── Toggle / Delete ──
async function toggleLink(uid,active){
  try{
    const r=await fetch('/api/links/'+uid,{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify({active})});
    if(!r.ok) throw new Error('خطا');
    toast(active?'لینک فعال شد':'لینک غیرفعال شد');
    loadLinks();
  }catch(e){toast(e.message,true)}
}
async function deleteLink(uid){
  if(!confirm('مطمئنی؟ این لینک حذف می‌شه و از Xray هم برداشته می‌شه.')) return;
  try{
    const r=await fetch('/api/links/'+uid,{method:'DELETE'});
    if(!r.ok) throw new Error('خطا');
    toast('لینک حذف شد');
    loadLinks();
  }catch(e){toast(e.message,true)}
}

// ── Xray ──
async function loadXrayStatus(){
  try{
    const r=await fetch('/api/xray/status');
    const d=await r.json();
    document.getElementById('xray-pid').textContent=d.running?`PID: ${d.pid} · در حال اجرا`:'متوقف';
    document.getElementById('xray-pill').innerHTML=d.running
      ?'<span class="pill pill-green"><span class="pill-dot"></span>Online</span>'
      :'<span class="pill pill-red"><span class="pill-dot"></span>Offline</span>';
    const ports=[
      {label:'VLESS WS',port:10000,proto:'vless'},
      {label:'Trojan WS',port:10001,proto:'trojan'},
      {label:'VLESS XHTTP',port:10004,proto:'vless-xhttp'},
      {label:'VLESS Reality',port:'8443',proto:'vless-reality'},
    ];
    document.getElementById('xray-ports').innerHTML=ports.map(p=>`
      <div class="status-row">
        <span class="status-key"><i class="ti ti-plug"></i>${p.label}</span>
        <span class="status-val">${p.port} (داخلی)</span>
      </div>`).join('');
  }catch(e){console.error(e)}
}
async function loadXrayConfig(){
  try{
    const r=await fetch('/api/xray/config');
    const d=await r.json();
    const el=document.getElementById('xray-config-view');
    el.textContent=JSON.stringify(d,null,2);
    el.style.display='block';
  }catch(e){toast('خطا در دریافت کانفیگ',true)}
}
async function restartXray(){
  try{
    const r=await fetch('/api/xray/restart',{method:'POST'});
    if(!r.ok) throw new Error('خطا');
    toast('Xray ریستارت شد ✅');
    loadXrayStatus();
  }catch(e){toast(e.message,true)}
}

// ── Blocked ──
async function loadBlocked(){
  try{
    const r=await fetch('/api/blocked');
    const d=await r.json();
    const ips=d.blocked_ips||[];
    document.getElementById('blocked-list').innerHTML=ips.length
      ?ips.map(ip=>`<div style="display:flex;align-items:center;justify-content:space-between;padding:8px 0;border-bottom:1px solid var(--border);font-size:12.5px">
          <span style="font-family:ui-monospace,monospace;color:#93c5fd">${ip}</span>
          <button class="btn btn-danger btn-sm" onclick="unblockIP('${ip}')"><i class="ti ti-shield-check"></i>آنبلاک</button>
        </div>`).join('')
      :'<div style="color:var(--text-2);font-size:12px;padding:10px 0">هیچ IP بلاک‌شده‌ای وجود ندارد.</div>';
  }catch(e){console.error(e)}
}
async function blockIP(){
  const ip=document.getElementById('block-ip-input').value.trim();
  if(!ip){toast('آدرس IP را وارد کن',true);return;}
  try{
    const r=await fetch('/api/blocked',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({ip})});
    if(!r.ok) throw new Error('خطا');
    document.getElementById('block-ip-input').value='';
    toast('IP بلاک شد');
    loadBlocked();
  }catch(e){toast(e.message,true)}
}
async function unblockIP(ip){
  try{
    const r=await fetch('/api/blocked/'+encodeURIComponent(ip),{method:'DELETE'});
    if(!r.ok) throw new Error('خطا');
    toast('IP آنبلاک شد');
    loadBlocked();
  }catch(e){toast(e.message,true)}
}

// ── Init ──
loadStats();
setInterval(loadStats,30000);
</script>
</body>
</html>"""

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):
    if not await is_valid_session(request.cookies.get(SESSION_COOKIE)):
        return RedirectResponse("/login")
    return HTMLResponse(content=DASHBOARD_HTML)

if __name__ == "__main__":
    uvicorn.run("main_xray:app", host="127.0.0.1", port=8000, log_level="info", workers=1)
