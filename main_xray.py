import asyncio
import json
import os
import re
import hashlib
import secrets
import time
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

logging.basicConfig(level=logging.WARNING, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("tryak-Xray")

# ───── CPU usage بر اساس cgroup خودِ کانتینر (بدون psutil) ─────
# Railway کانتینر رو با محدودیت cgroup اجرا می‌کنه؛ مصرف CPU رو مستقیم از همون
# cgroup می‌خونیم و دلتا می‌گیریم — سبک، بدون وابستگی باینری، بدون بلاک کردن event loop.
_cpu_last = {"t": None, "usage": None}

def _read_cgroup_cpu_usage_usec():
    p = Path("/sys/fs/cgroup/cpu.stat")          # cgroup v2
    if p.exists():
        for line in p.read_text().splitlines():
            if line.startswith("usage_usec"):
                return int(line.split()[1])
    for c in ("/sys/fs/cgroup/cpu/cpuacct.usage",  # cgroup v1 (ns → usec)
              "/sys/fs/cgroup/cpuacct/cpuacct.usage"):
        cp = Path(c)
        if cp.exists():
            return int(cp.read_text().strip()) // 1000
    return None

def _cgroup_ncpu():
    p = Path("/sys/fs/cgroup/cpu.max")            # cgroup v2 quota
    if p.exists():
        parts = p.read_text().split()
        if parts and parts[0] != "max":
            quota, period = int(parts[0]), int(parts[1])
            if quota > 0 and period > 0:
                return max(quota / period, 0.01)
    q  = Path("/sys/fs/cgroup/cpu/cpu.cfs_quota_us")   # cgroup v1 quota
    pe = Path("/sys/fs/cgroup/cpu/cpu.cfs_period_us")
    if q.exists() and pe.exists():
        quota = int(q.read_text().strip()); period = int(pe.read_text().strip())
        if quota > 0 and period > 0:
            return max(quota / period, 0.01)
    return os.cpu_count() or 1

def get_cpu_percent() -> float:
    """درصد مصرف CPU کانتینر (غیربلاک‌کننده). فراخوانی اول 0.0 برمی‌گردونه."""
    usage = _read_cgroup_cpu_usage_usec()
    now = time.monotonic()
    if usage is None:
        return 0.0
    last_t, last_u = _cpu_last["t"], _cpu_last["usage"]
    _cpu_last["t"], _cpu_last["usage"] = now, usage
    if last_t is None or last_u is None:
        return 0.0
    dt = now - last_t
    if dt <= 0:
        return 0.0
    busy = (usage - last_u) / 1e6
    pct = busy / (dt * _cgroup_ncpu()) * 100
    return round(max(0.0, min(pct, 100.0)), 1)

# prime اولیه تا اولین /stats مقدار معنادار بده
get_cpu_percent()

# ───────── Platform Detection ─────────
_HOST_CACHE: str | None = None
_PLATFORM_CACHE: str | None = None

def _detect_host() -> str:
    # دامنه‌ی عمومی در زمان اجرا تغییر نمی‌کنه؛ یک‌بار محاسبه و کش می‌شه
    # تا هر درخواست/دور حلقه env lookup تکراری انجام نشه.
    global _HOST_CACHE
    if _HOST_CACHE is not None:
        return _HOST_CACHE
    _HOST_CACHE = __detect_host_uncached()
    return _HOST_CACHE

def __detect_host_uncached() -> str:
    # فقط Railway — دامنه‌ی عمومی سرویس
    h = os.environ.get("RAILWAY_PUBLIC_DOMAIN")
    if h: return h
    h = os.environ.get("PUBLIC_DOMAIN")  # override دستی در صورت نیاز
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
    global _PLATFORM_CACHE
    if _PLATFORM_CACHE is not None:
        return _PLATFORM_CACHE
    _PLATFORM_CACHE = __detect_platform_uncached()
    return _PLATFORM_CACHE

def __detect_platform_uncached() -> str:
    # این پروژه فقط برای Railway ساخته شده
    if os.environ.get("RAILWAY_PUBLIC_DOMAIN") or os.environ.get("RAILWAY_ENVIRONMENT"):
        return "Railway"
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
# مجموع ترافیک هر روز (YYYY-MM-DD -> bytes) برای نمودار ۷ روزه؛ فقط چند روز اخیر نگه داشته می‌شه
daily_traffic: dict = defaultdict(int)
# آخرین مقدار تجمعی هر کاربر که از Xray API خونده شده — برای محاسبه‌ی دلتا
# (مصرف جدید بین این پول و پول قبلی) که به hourly_traffic اضافه می‌شه.
_last_usage_snapshot: dict = {}

# لینک‌ها  uid -> {label, protocol, limit_bytes, used_bytes, created_at, expires_at, active, password(trojan)}
LINKS: dict = {}
LINKS_LOCK = asyncio.Lock()
RELOAD_LOCK = asyncio.Lock()

# کلیدهای Reality (یک‌بار ساخته و persist می‌شن تا با ری‌استارت لینک‌های قبلی خراب نشن)
# dest/sni هم اینجا persist می‌شن تا از خود پنل قابل تنظیم باشن (نه فقط از env).
REALITY: dict = {"private_key": "", "public_key": "", "short_id": "", "dest": "", "sni": ""}

def reality_dest() -> str:
    """مقصد camouflage برای Reality (host:port). اولویت: مقدار ست‌شده در پنل ← env REALITY_DEST."""
    return (REALITY.get("dest") or "").strip() or REALITY_DEST

def reality_sni() -> str:
    """SNI که کلاینت Reality وانمود می‌کند به آن وصل شده.
    اولویت: مقدار ست‌شده در پنل ← env REALITY_SNI ← هاستِ dest."""
    s = (REALITY.get("sni") or "").strip()
    if s:
        return s
    if REALITY_SNI:
        return REALITY_SNI
    return reality_dest().split(":")[0]

BLOCKED_IPS: set = set()

# ───────── Client IP Tracking (از روی accessLog خود Xray) ─────────
# uid -> { ip: {"country","country_code","city","first_seen","last_seen","hits"} }
link_clients: dict = defaultdict(dict)
LINK_CLIENTS_LOCK = asyncio.Lock()

_ip_geo_cache: dict = {}          # ip -> {"country","country_code","city"}
_IP_GEO_CACHE_MAX = 10000
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
    """برای نمایش limit — صفر یعنی نامحدود"""
    if not b: return "نامحدود ♾️"
    if b >= 1024**3: return f"{b/1024**3:.1f} GB"
    if b >= 1024**2: return f"{b/1024**2:.1f} MB"
    return f"{b/1024:.1f} KB"

def fmt_usage(b: int) -> str:
    """برای نمایش مصرف واقعی — صفر یعنی 0 نه نامحدود"""
    if b >= 1024**3: return f"{b/1024**3:.1f} GB"
    if b >= 1024**2: return f"{b/1024**2:.1f} MB"
    if b >= 1024: return f"{b/1024:.1f} KB"
    return "0.0 MB"

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

def _normalize_tags(raw) -> list:
    """برچسب‌ها رو به لیست تمیز و یکتا تبدیل می‌کنه (از رشته‌ی کاما-جدا یا لیست)."""
    if raw is None:
        return []
    if isinstance(raw, str):
        items = re.split(r"[,،]", raw)
    elif isinstance(raw, (list, tuple)):
        items = raw
    else:
        return []
    out = []
    for t in items:
        if t is None:
            continue
        t = str(t).strip()[:30]
        if t and t not in out:
            out.append(t)
        if len(out) >= 12:
            break
    return out

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
    # fallback: مصرف از /proc/meminfo (بدون psutil)
    try:
        info = {}
        for line in Path("/proc/meminfo").read_text().splitlines():
            k, _, v = line.partition(":")
            info[k.strip()] = int(v.strip().split()[0])  # kB
        total = info.get("MemTotal", 0)
        avail = info.get("MemAvailable", info.get("MemFree", 0))
        if total > 0:
            return round((total - avail) / total * 100, 1)
    except Exception:
        pass
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
    # http_client در lifespan ساخته می‌شه؛ اگه هنوز آماده نیست، geo رو رد می‌کنیم
    # تا از ساخت کلاینت بدون بسته‌شدن (نشتی منابع) جلوگیری بشه.
    if http_client is None:
        return {}
    try:
        r = await http_client.get(
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
_ACCESS_LOG_RE = re.compile(
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
            elif text.startswith("[Error]") or "panic" in text.lower():
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
                    "dest": reality_dest(),
                    "xver": 0,
                    "serverNames": [reality_sni()],
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
    # geoip/geosite کاملاً حذف شدن؛ Xray دیگه هیچ فایل دیتای geo در حافظه لود نمی‌کنه (کاهش مصرف رم).
    routing_rules = []

    # ── بلاک سایت‌های +۱۸ / دسته‌های geosite حذف شد (برای کاهش مصرف رم؛ Xray دیگر geosite.dat را در حافظه لود نمی‌کند) ──

    # ── دامنه‌های سفارشی برای بلاک (env BLOCKED_DOMAINS، با کاما جدا شده) ──
    # نمونه: BLOCKED_DOMAINS="example.com,ads.test.com,keyword:tracker"
    custom_domains = [d.strip() for d in os.environ.get("BLOCKED_DOMAINS", "").split(",") if d.strip()]
    if custom_domains:
        routing_rules.append({
            "type": "field",
            "domain": custom_domains,
            "outboundTag": "blocked",
        })
        logger.warning(f"🚫 بلاک دامنه‌های سفارشی: {custom_domains}")

    # ── بلاک‌کردن IP کلاینت‌ها (source-based) ──
    # این قانون باعث می‌شه IPهای داخل BLOCKED_IPS واقعاً توی خود Xray به blackhole برن،
    # نه اینکه فقط توی دیتابیس ذخیره/نمایش داده بشن. قبل از بقیه‌ی قوانین قرار می‌گیره.
    if BLOCKED_IPS:
        routing_rules.insert(0, {
            "type": "field",
            "source": list(BLOCKED_IPS),
            "outboundTag": "blocked",
        })

    return {
        "log": {
            # لاگ کامل خاموش است (نیازی به لاگ نداریم). دیگه stdout هم خونده نمی‌شه،
            # پس نه I/O دیسک داریم، نه پردازش regex per-connection، نه task اضافه.
            # ⚠️ با loglevel=none ردیابی خودکار IP/کشورِ کلاینت‌ها غیرفعال می‌شه؛
            #    اگه روزی اون فیچر رو خواستی، این رو "info" کن و stdout reader رو برگردون.
            "loglevel": "none",
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

    # لاگ Xray کاملاً خاموشه (loglevel=none)، پس stdout/stderr رو مستقیم دور می‌ریزیم
    # و دیگه task خواننده‌ی stdout نمی‌سازیم — صرفه‌جویی در RAM/CPU.
    xray_process = await asyncio.create_subprocess_exec(
        str(XRAY_BIN), "run", "-c", str(_XRAY_CONFIG_PATH),
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.DEVNULL,
    )

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

# ───────── Xray User API (افزودن/حذف کاربر بدون ری‌استارت) ─────────
# نسخه‌های Xray-core از ~v25.8 به بعد دو دستور api adu (AddInboundUser) و
# api rmu (RemoveInboundUser) دارن که اجازه می‌دن کاربر رو روی یک inbound در
# حالِ اجرا اضافه/حذف کنیم — بدون restart کامل که همه‌ی اتصال‌های فعال رو قطع می‌کنه.
# اگه باینری این دستورها رو پشتیبانی نکنه، خودکار به reload کامل fallback می‌کنیم،
# پس رفتار بدترین‌حالت دقیقاً مثل قبل (reload) می‌مونه و هیچ‌چیز خراب نمی‌شه.
INBOUND_TAGS = {
    "vless":         "vless-in",
    "trojan":        "trojan-in",
    "vless-xhttp":   "vless-xhttp-in",
    "vless-reality": "vless-reality-in",
}
_userapi_supported: bool | None = None   # None = هنوز تشخیص داده نشده

async def _run_xray_api(*args: str, timeout: float = 8.0) -> tuple[int, str]:
    """یک دستور `xray api ...` اجرا می‌کنه و (returncode, خروجی متنی) برمی‌گردونه."""
    proc = await asyncio.create_subprocess_exec(
        str(XRAY_BIN), "api", *args,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
    )
    out, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    return (proc.returncode if proc.returncode is not None else -1), out.decode(errors="ignore")

async def detect_userapi_support() -> bool:
    """یک‌بار تشخیص می‌ده که باینری Xray دستورهای adu/rmu رو داره یا نه."""
    global _userapi_supported
    if _userapi_supported is not None:
        return _userapi_supported
    try:
        # بدون آرگومان صدا می‌زنیم؛ اگه دستور ناشناخته باشه Xray صراحتاً می‌گه.
        _, out = await _run_xray_api("adu", timeout=8.0)
        low = out.lower()
        _userapi_supported = ("unknown command" not in low
                              and "no such command" not in low
                              and "available commands" not in low)
    except Exception as e:
        logger.warning(f"⚠️ تشخیص پشتیبانی Xray User API شکست خورد: {e}")
        _userapi_supported = False
    if _userapi_supported:
        logger.warning("✅ Xray از adu/rmu پشتیبانی می‌کنه — افزودن/حذف کاربر بدون ری‌استارت فعال شد.")
    else:
        logger.warning("ℹ️ باینری Xray فاقد adu/rmu است؛ تغییرات کاربر با reload کامل اعمال می‌شن.")
    return _userapi_supported

def _api_client_for(uid: str, link: dict, proto: str) -> dict:
    """آبجکت کاربر برای یک پروتکل، مطابق همون چیزی که build_xray_config می‌سازه."""
    if proto == "trojan":
        return {"password": link.get("password", uid), "email": uid}
    if proto == "vless-reality":
        return {"id": uid, "email": uid, "flow": "xtls-rprx-vision"}
    # vless, vless-xhttp
    return {"id": uid, "email": uid}

def _api_inbound_for(proto: str, clients: list) -> dict | None:
    """یک inbound معتبر (InboundDetourConfig) با tag درست برای استفاده در `xray api adu`.
    فقط tag + protocol + settings.clients واقعاً توسط adu استفاده می‌شن، بقیه فقط برای
    معتبر بودن ساختار JSON هستن."""
    tag = INBOUND_TAGS.get(proto)
    if not tag:
        return None
    if proto == "trojan":
        return {"tag": tag, "protocol": "trojan", "port": CONFIG["xray_trojan_port"],
                "listen": "127.0.0.1", "settings": {"clients": clients}}
    if proto == "vless-reality":
        return {"tag": tag, "protocol": "vless", "port": CONFIG["xray_reality_port"],
                "listen": "0.0.0.0", "settings": {"clients": clients, "decryption": "none"}}
    if proto == "vless-xhttp":
        return {"tag": tag, "protocol": "vless", "port": CONFIG["xray_xhttp_port"],
                "listen": "127.0.0.1", "settings": {"clients": clients, "decryption": "none"}}
    # vless
    return {"tag": tag, "protocol": "vless", "port": CONFIG["xray_vless_port"],
            "listen": "127.0.0.1", "settings": {"clients": clients, "decryption": "none"}}

def _inbound_active_user_count(proto: str, exclude_uid: str | None = None) -> int:
    """تعداد کاربرهای فعالِ یک inbound (همین الان در کانفیگ در حال اجرا). برای تشخیص
    «اولین کاربر» که اون موقع inbound هنوز وجود نداره و باید reload بشه."""
    n = 0
    for uid, link in LINKS.items():
        if exclude_uid is not None and uid == exclude_uid:
            continue
        if proto in link_protocols(link) and link.get("active"):
            n += 1
    return n

async def xray_add_user(uid: str, link: dict) -> bool:
    """کاربر رو روی همه‌ی inboundهای پروتکل‌هاش از طریق Xray API اضافه می‌کنه (بدون restart).
    True یعنی همه‌ی پروتکل‌ها موفق اعمال شدن؛ False یعنی نیاز به reload کامل هست."""
    if not await detect_userapi_support():
        return False
    if not (xray_process and xray_process.returncode is None):
        return False
    server = f"127.0.0.1:{CONFIG['xray_api_port']}"
    ok_all = True
    for proto in link_protocols(link):
        tag = INBOUND_TAGS.get(proto)
        if not tag:
            ok_all = False
            continue
        # اگه این اولین کاربرِ این inbound باشه، inbound هنوز در کانفیگِ در حال اجرا نیست
        # (build_xray_config فقط inboundهایی رو می‌سازه که حداقل یک کلاینت دارن) → باید reload بشه.
        if _inbound_active_user_count(proto, exclude_uid=uid) == 0:
            ok_all = False
            continue
        if proto == "vless-reality" and not REALITY.get("private_key"):
            ok_all = False
            continue
        inbound = _api_inbound_for(proto, [_api_client_for(uid, link, proto)])
        if inbound is None:
            ok_all = False
            continue
        fpath = _DATA_DIR / f".adu_{uid[:8]}_{proto}.json"
        try:
            fpath.write_text(json.dumps({"inbounds": [inbound]}, ensure_ascii=False))
            rc, out = await _run_xray_api("adu", f"--server={server}", str(fpath))
            low = out.lower()
            # «already exists» یعنی کاربر از قبل هست = موفقیت (idempotent)
            if rc != 0 and "already exists" not in low:
                logger.warning(f"⚠️ adu برای {proto}/{uid[:8]} ناموفق: {out.strip()[:200]}")
                ok_all = False
        except Exception as e:
            logger.warning(f"⚠️ adu exception برای {proto}/{uid[:8]}: {e}")
            ok_all = False
        finally:
            try: fpath.unlink()
            except Exception: pass
    return ok_all

async def xray_remove_user(uid: str, link: dict) -> bool:
    """کاربر رو از همه‌ی inboundهای پروتکل‌هاش از طریق Xray API حذف می‌کنه (بدون restart)."""
    if not await detect_userapi_support():
        return False
    if not (xray_process and xray_process.returncode is None):
        return False
    server = f"127.0.0.1:{CONFIG['xray_api_port']}"
    ok_all = True
    for proto in link_protocols(link):
        tag = INBOUND_TAGS.get(proto)
        if not tag:
            ok_all = False
            continue
        # اگه inbound اصلاً وجود نداره (هیچ کاربر فعال دیگه‌ای نداره)، حذف بی‌معنیه و
        # نیازی هم نیست؛ موفق در نظر می‌گیریم تا reload الکی نشه.
        if _inbound_active_user_count(proto, exclude_uid=uid) == 0:
            continue
        try:
            rc, out = await _run_xray_api("rmu", f"--server={server}", f"-tag={tag}", uid)
            low = out.lower()
            # «not found» یعنی کاربر از قبل نبوده = همان نتیجه‌ی مطلوب
            if rc != 0 and "not found" not in low and "does not exist" not in low:
                logger.warning(f"⚠️ rmu برای {proto}/{uid[:8]} ناموفق: {out.strip()[:200]}")
                ok_all = False
        except Exception as e:
            logger.warning(f"⚠️ rmu exception برای {proto}/{uid[:8]}: {e}")
            ok_all = False
    return ok_all

async def apply_user_removals(uids: list[str], links_snapshot: dict) -> None:
    """چند کاربر رو حذف می‌کنه؛ اگه برای هرکدوم API در دسترس نبود، یک‌بار reload کامل می‌زنه."""
    if not uids:
        return
    need_reload = False
    for uid in uids:
        lk = links_snapshot.get(uid)
        if lk is None:
            continue
        if not await xray_remove_user(uid, lk):
            need_reload = True
    if need_reload:
        await reload_xray()

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
        data["daily_traffic"]  = dict(daily_traffic)
        data["total_bytes"]    = stats["total_bytes"]
        tmp = DATA_FILE.with_suffix(".tmp")
        await asyncio.to_thread(tmp.write_text, json.dumps(data, ensure_ascii=False, separators=(",", ":")))
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
            daily_traffic.update(data.get("daily_traffic") or {})
            stats["total_bytes"] = data.get("total_bytes", 0)
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
        except Exception as exc:
            logger.warning(f"⚠️ keepalive failed: {exc}")
        await asyncio.sleep(10 * 60)

async def reset_link_usage(uid: str, usage: dict | None = None) -> bool:
    """مصرف یک لینک را بدون ری‌استارت Xray صفر می‌کند.
    با ترفند baseline منفی: used = baseline + usage_جاری = 0 و از همین لحظه دوباره می‌شمارد.
    خروجی: آیا لینک (که به‌خاطر اتمام سهمیه خاموش بود) دوباره فعال شد؟ (نیاز به reload)."""
    if usage is None:
        usage = await query_xray_stats()
    cur = int(usage.get(uid, 0))
    reactivated = False
    async with LINKS_LOCK:
        link = LINKS.get(uid)
        if not link:
            return False
        link["baseline_bytes"] = -cur
        link["used_bytes"] = 0
        link["last_reset"] = datetime.now().isoformat()
        if link.get("limit_bytes") and not link.get("active") and not is_link_expired(link):
            link["active"] = True
            reactivated = True
    return reactivated

async def enforce_ip_limits():
    """برای هر لینک با max_ips>0: اگر تعداد IPهای فعال (last_seen در ۱۰ دقیقه‌ی اخیر) از حد
    مجاز بیشتر شد، IPهای تازه‌تر را بلاک می‌کند تا جلوی اشتراک‌گذاری بیش‌ازحد گرفته شود.
    IPهای قدیمی‌تر (بر اساس first_seen) مجاز می‌مانند."""
    window = datetime.now() - timedelta(minutes=10)
    async with LINKS_LOCK:
        limits = {uid: int(l.get("max_ips") or 0) for uid, l in LINKS.items()}
    to_block = set()
    async with LINK_CLIENTS_LOCK:
        for uid, mx in limits.items():
            if mx <= 0:
                continue
            active = []
            for ip, info in link_clients.get(uid, {}).items():
                if ip in BLOCKED_IPS:
                    continue
                ls = info.get("last_seen")
                try:
                    if ls and datetime.fromisoformat(ls) >= window:
                        active.append((ip, info.get("first_seen") or ls))
                except Exception:
                    pass
            if len(active) > mx:
                active.sort(key=lambda t: t[1])      # قدیمی‌ترها اول
                for ip, _ in active[mx:]:
                    to_block.add(ip)
    if to_block:
        BLOCKED_IPS.update(to_block)
        await save_data()
        await reload_xray()
        logger.warning(f"🚧 محدودیت IP: {len(to_block)} آی‌پی اضافه بلاک شد.")

async def scheduler_loop():
    while True:
        await asyncio.sleep(60)
        async with LINKS_LOCK:
            changed = []
            changed_uids = []
            changed_snapshot = {}
            for uid, link in LINKS.items():
                if is_link_expired(link) and link.get("active"):
                    link["active"] = False
                    changed.append(link.get("label", uid[:8]))
                    changed_uids.append(uid)
                    changed_snapshot[uid] = dict(link)
        if changed:
            await save_data()
            # حذف کاربرهای منقضی بدون ری‌استارت (در صورت عدم پشتیبانی، reload کامل)
            await apply_user_removals(changed_uids, changed_snapshot)
            for label in changed:
                logger.warning(f"⏰ لینک '{label}' منقضی و غیرفعال شد.")

        # ── ریست خودکار سهمیه‌ی دوره‌ای (reset_days) ──
        now_dt = datetime.now()
        due = []
        async with LINKS_LOCK:
            for uid, link in LINKS.items():
                rd = int(link.get("reset_days") or 0)
                if rd <= 0:
                    continue
                last = link.get("last_reset") or link.get("created_at")
                try:
                    last_dt = datetime.fromisoformat(last)
                except Exception:
                    last_dt = now_dt
                    link["last_reset"] = now_dt.isoformat()
                if now_dt - last_dt >= timedelta(days=rd):
                    due.append(uid)
        if due:
            usage = await query_xray_stats()
            reactivated_uids = []
            for uid in due:
                if await reset_link_usage(uid, usage):
                    reactivated_uids.append(uid)
            await save_data()
            if reactivated_uids:
                # لینک‌هایی که به‌خاطر اتمام سهمیه خاموش بودن دوباره فعال شدن →
                # کاربرشون رو بدون ری‌استارت اضافه می‌کنیم (در صورت نیاز reload کامل).
                need_reload = False
                async with LINKS_LOCK:
                    snap = {u: dict(LINKS[u]) for u in reactivated_uids if u in LINKS}
                for u in reactivated_uids:
                    if u in snap and not await xray_add_user(u, snap[u]):
                        need_reload = True
                if need_reload:
                    await reload_xray()
            logger.warning(f"🔄 ریست دوره‌ای سهمیه برای {len(due)} لینک انجام شد.")

        # ── اعمال محدودیت تعداد IP هم‌زمان ──
        try:
            await enforce_ip_limits()
        except Exception as e:
            logger.warning(f"⚠️ enforce_ip_limits error: {e}")

        # ── پاکسازی session های منقضی (جلوگیری از رشد بی‌رویه‌ی حافظه) ──
        now = time.time()
        async with SESSIONS_LOCK:
            expired = [tok for tok, exp in SESSIONS.items() if exp < now]
            for tok in expired:
                SESSIONS.pop(tok, None)

        # ── پاکسازی IPهای قدیمی کلاینت‌ها (تنها ساختار بدون سقف؛ مهار رشد رم/فایل دیتا) ──
        # IPی که PRUNE_AFTER دیده نشده حذف می‌شه. لینک‌های حذف‌شده هم کل سطلشون دور ریخته می‌شه.
        # (هیچ سقف تعدادی روی IPهای هر لینک گذاشته نمی‌شه — فقط مبنای زمانی.)
        PRUNE_AFTER = timedelta(days=3)
        ip_cutoff = datetime.now() - PRUNE_AFTER
        async with LINK_CLIENTS_LOCK:
            for uid in list(link_clients.keys()):
                if uid not in LINKS:
                    del link_clients[uid]
                    continue
                bucket = link_clients[uid]
                for ip in list(bucket.keys()):
                    ls = bucket[ip].get("last_seen")
                    try:
                        if ls and datetime.fromisoformat(ls) < ip_cutoff:
                            del bucket[ip]
                    except Exception:
                        pass

async def traffic_loop():
    """مصرف واقعی هر لینک رو هر ۳۰ ثانیه از Xray می‌خونه تا نمودار «ترافیک امروز» سریع آپدیت بشه.
    خود فراخوانی Xray API سبکه (یه pipe محلی)، پس این فاصله مشکلی برای CPU ایجاد نمی‌کنه؛
    اما برای جلوگیری از I/O زیاد دیسک، ذخیره‌سازی همچنان فقط هر ~۵ دقیقه (هر ۱۰ دور) یا
    وقتی سهمیه‌ای تموم بشه انجام می‌شه."""
    global _last_usage_snapshot
    await asyncio.sleep(20)
    poll_count = 0
    idle_streak = 0          # تعداد دورهای پشت‌سرهم بدون ترافیک
    BASE_SLEEP = 60          # فاصله‌ی پایه وقتی ترافیک فعاله
    MAX_SLEEP  = 300         # حداکثر فاصله وقتی همه‌چی idleه (۵ دقیقه)
    while True:
        try:
            # اگه اصلاً لینکی وجود نداره، اجرای subprocess (xray api statsquery)
            # بی‌فایده‌ست — رد می‌کنیم تا روی پنل‌های خلوت CPU الکی مصرف نشه.
            if not LINKS:
                idle_streak += 1
                await asyncio.sleep(min(MAX_SLEEP, BASE_SLEEP * 2))
                continue
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
                # ترافیک فعال → سریع بمون؛ بی‌ترافیک → کم‌کم فاصله رو باز کن
                idle_streak = 0 if delta_total > 0 else idle_streak + 1
                if delta_total > 0:
                    hour_key = datetime.now().strftime("%Y-%m-%d-%H")
                    hourly_traffic[hour_key] += delta_total
                    stats["total_bytes"] += delta_total
                    # تجمیع روزانه برای نمودار ۷ روزه + حذف روزهای قدیمی‌تر از ۸ روز
                    day_key = datetime.now().strftime("%Y-%m-%d")
                    daily_traffic[day_key] += delta_total
                    day_cutoff = (datetime.now() - timedelta(days=8)).strftime("%Y-%m-%d")
                    for k in [k for k in daily_traffic if k < day_cutoff]:
                        daily_traffic.pop(k, None)
                    # حذف باکت‌های قدیمی‌تر از ۴۸ ساعت برای جلوگیری از رشد بی‌رویه‌ی حافظه/فایل
                    cutoff = datetime.now() - timedelta(hours=48)
                    old_keys = [k for k in hourly_traffic
                                if k < cutoff.strftime("%Y-%m-%d-%H")]
                    for k in old_keys:
                        hourly_traffic.pop(k, None)

                quota_hit = []
                quota_hit_uids = []
                quota_snapshot = {}
                async with LINKS_LOCK:
                    for uid, link in LINKS.items():
                        if uid in usage:
                            link["used_bytes"] = link.get("baseline_bytes", 0) + usage[uid]
                            if link["limit_bytes"] and link["used_bytes"] >= link["limit_bytes"] and link.get("active"):
                                link["active"] = False
                                quota_hit.append(link.get("label", uid[:8]))
                                quota_hit_uids.append(uid)
                                quota_snapshot[uid] = dict(link)
                poll_count += 1
                if quota_hit or poll_count % 15 == 0:
                    await save_data()
                if quota_hit:
                    # حذف کاربرهای تمام‌سهمیه بدون ری‌استارت (در صورت عدم پشتیبانی، reload کامل)
                    await apply_user_removals(quota_hit_uids, quota_snapshot)
                    for label in quota_hit:
                        logger.warning(f"📊 سهمیه لینک '{label}' تمام شد و غیرفعال شد.")
        except Exception as e:
            logger.warning(f"⚠️ traffic loop error: {e}")
        # backoff تطبیقی: بعد از ۳ دور بی‌ترافیک فاصله رو پله‌پله تا MAX_SLEEP باز می‌کنیم.
        # به‌محض دیدن ترافیک، idle_streak صفر می‌شه و دوباره به BASE_SLEEP برمی‌گرده.
        if idle_streak >= 3:
            sleep_for = min(MAX_SLEEP, BASE_SLEEP * (1 + (idle_streak - 2)))
        else:
            sleep_for = BASE_SLEEP
        await asyncio.sleep(sleep_for)

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
        "sni": reality_sni(), "fp": "chrome",
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
    await start_xray()   # لاگ Xray خاموشه؛ دیگه stdout reader استارت نمی‌شه
    # تشخیص پشتیبانی adu/rmu (افزودن/حذف کاربر بدون ری‌استارت) — یک‌بار، غیرمسدودکننده
    asyncio.create_task(detect_userapi_support())

    keepalive_task   = asyncio.create_task(keepalive_loop())
    scheduler_task   = asyncio.create_task(scheduler_loop())
    traffic_task     = asyncio.create_task(traffic_loop())

    yield

    for t in [keepalive_task, scheduler_task, traffic_task, _xray_stdout_task]:
        if t: t.cancel()
    if xray_process and xray_process.returncode is None:
        xray_process.terminate()
    await save_data()
    if http_client:
        await http_client.aclose()

app = FastAPI(title="tryak Xray Gateway", docs_url=None, redoc_url=None, lifespan=lifespan)
# ───── CORS ─────
# origin=["*"] همراه allow_credentials=True هم نامعتبر است و هم خطرناک.
# داشبورد فقط از روی همان دامنه‌ی عمومی سرویس استفاده می‌شود، پس origin را
# به همان دامنه محدود می‌کنیم. در صورت نیاز می‌توان با env چند origin اضافه کرد:
#   CORS_ORIGINS="https://a.example.com,https://b.example.com"
def _build_cors_origins() -> list[str]:
    extra = [o.strip() for o in os.environ.get("CORS_ORIGINS", "").split(",") if o.strip()]
    host = _detect_host()
    auto = []
    if host and host != "localhost":
        auto = [f"https://{host}", f"http://{host}"]
    else:
        # محیط توسعه‌ی محلی
        auto = ["http://localhost:8000", "http://127.0.0.1:8000"]
    # حذف تکراری‌ها با حفظ ترتیب
    return list(dict.fromkeys(extra + auto))

app.add_middleware(
    CORSMiddleware,
    allow_origins=_build_cors_origins(),
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
    # secure=True تا کوکی نشست فقط روی HTTPS ارسال شود (اتصال عمومی Railway روی TLS است).
    # برای تست محلی روی HTTP می‌توان COOKIE_SECURE=0 گذاشت.
    cookie_secure = os.environ.get("COOKIE_SECURE", "1").strip().lower() not in ("0", "false", "no")
    resp.set_cookie(key=SESSION_COOKIE, value=token, max_age=SESSION_TTL,
                    httponly=True, secure=cookie_secure, samesite="lax", path="/")
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
        "cpu_percent":      get_cpu_percent(),
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

@app.get("/api/traffic/week")
async def get_traffic_week(_=Depends(require_auth)):
    """ترافیک ۷ روز اخیر به تفکیک روز، برای رسم نمودار هفتگی."""
    points = []
    total = 0
    for i in range(6, -1, -1):
        d = (datetime.now() - timedelta(days=i)).strftime("%Y-%m-%d")
        val = int(daily_traffic.get(d, 0))
        total += val
        points.append({"date": d, "label": d[5:], "bytes": val})
    return {"points": points, "total_bytes": total}

# ───────── Link Management ─────────
def _new_link_dict(label: str, protocols: list, limit_bytes: int, expires_at: str | None,
                   password: str, ss_method: str, reset_days: int, max_ips: int,
                   tags: list, note: str) -> dict:
    """دیکشنری یک لینک تازه با مصرف صفر — مشترک بین ساخت تکی/گروهی/کلون."""
    now = datetime.now().isoformat()
    return {
        "label":          label,
        "protocol":       protocols[0],
        "protocols":      protocols,
        "limit_bytes":    limit_bytes,
        "used_bytes":     0,
        "baseline_bytes": 0,
        "created_at":     now,
        "expires_at":     expires_at,
        "active":         True,
        "password":       password,
        "ss_method":      ss_method,
        "reset_days":     reset_days,
        "max_ips":        max_ips,
        "last_reset":     now,
        "tags":           tags,
        "note":           note,
    }

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

    reset_days   = int(float(body.get("reset_days") or 0))     # ریست خودکار سهمیه هر N روز (۰=غیرفعال)
    max_ips      = int(float(body.get("max_ips") or 0))        # حداکثر IP هم‌زمان (۰=نامحدود)

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
        "reset_days":  reset_days,
        "max_ips":     max_ips,
        "last_reset":  datetime.now().isoformat(),
        "tags":        _normalize_tags(body.get("tags")),
        "note":        str(body.get("note") or "").strip()[:500],
    }
    async with LINKS_LOCK:
        LINKS[uid] = new_link

    # نکته‌ی مهم: قبلاً اینجا reload_xray() (که خود Xray رو ری‌استارت می‌کنه و چند ثانیه طول
    # می‌کشه) await می‌شد و کلاینت تا اون موقع منتظر می‌ماند. این باعث می‌شد کاربر فکر کنه
    # درخواست گیر کرده، دکمه رو دوباره بزنه یا صفحه رو رفرش کنه و همون لینک دوبار ساخته شه.
    # حالا ابتدا داده ذخیره و پاسخ فوراً برگردونده می‌شه.
    # سپس سعی می‌کنیم کاربر رو بدون ری‌استارت اضافه کنیم (adu)؛ اگه نشد (مثلاً اولین کاربرِ
    # یک inbound یا باینری قدیمی)، در پس‌زمینه reload کامل می‌زنیم.
    await save_data()
    async def _apply_create():
        if not await xray_add_user(uid, new_link):
            await reload_xray()
    asyncio.create_task(_apply_create())

    host  = _detect_host()
    conns = get_link_connections(uid, new_link, host)

    return {"uuid": uid, "label": label, "protocol": protocols[0], "protocols": protocols,
            "limit_bytes": limit_bytes, "used_bytes": 0, "active": True,
            "created_at": new_link["created_at"], "expires_at": expires_at,
            "tags": new_link["tags"], "note": new_link["note"],
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
                "reset_days":     data.get("reset_days", 0),
                "max_ips":        data.get("max_ips", 0),
                "last_reset":     data.get("last_reset"),
                "tags":           data.get("tags", []),
                "note":           data.get("note", ""),
                "ips_count":      len(link_clients.get(uid, {})),
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
    do_reset = bool(body.get("reset_usage"))
    async with LINKS_LOCK:
        if uid not in LINKS:
            raise HTTPException(404, "link not found")
        link = LINKS[uid]
        # وضعیت قبلی برای تصمیم‌گیری درباره‌ی نحوه‌ی اعمال در Xray
        old_active   = bool(link.get("active"))
        old_protos   = set(link_protocols(link))
        old_password = link.get("password")
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
        if "reset_days"   in body:
            link["reset_days"] = int(float(body.get("reset_days") or 0))
        if "max_ips"      in body:
            link["max_ips"] = int(float(body.get("max_ips") or 0))
        if "expire_days"  in body:
            ed = float(body.get("expire_days") or 0)
            link["expires_at"] = (datetime.now() + timedelta(days=ed)).isoformat() if ed > 0 else None
        if "password"     in body: link["password"]  = str(body["password"])
        if "ss_method"    in body: link["ss_method"] = str(body["ss_method"])
        # برچسب/یادداشت (جستجو و دسته‌بندی)
        if "tags" in body:
            link["tags"] = _normalize_tags(body.get("tags"))
        if "note" in body:
            link["note"] = str(body.get("note") or "").strip()[:500]
        new_active   = bool(link.get("active"))
        new_protos   = set(link_protocols(link))
        new_password = link.get("password")
        link_copy    = dict(link)

    # ریست مصرف خارج از قفل و با روش درست (baseline منفی) انجام می‌شه تا واقعاً صفر شه
    reactivated = False
    if do_reset:
        reactivated = await reset_link_usage(uid)
        if reactivated:
            new_active = True

    await save_data()

    # تصمیم درباره‌ی نحوه‌ی اعمال در Xray:
    #  • تغییر پروتکل‌ها یا رمز Trojan ساختار inbound رو عوض می‌کنه → reload کامل.
    #  • فقط فعال/غیرفعال شدن → افزودن/حذف کاربر بدون ری‌استارت (adu/rmu).
    #  • تغییر حجم/مدت/ریست/max_ips/برچسب/یادداشت اصلاً روی کانفیگ Xray اثر نداره →
    #    هیچ ری‌استارتی لازم نیست (بهبود بزرگ کارایی: قبلاً هر تغییر کوچیک reload می‌کرد).
    struct_changed = (new_protos != old_protos) or (new_password != old_password)
    async def _apply_update():
        if struct_changed:
            await reload_xray()
        elif new_active and not old_active:
            if not await xray_add_user(uid, link_copy):
                await reload_xray()
        elif old_active and not new_active:
            if not await xray_remove_user(uid, link_copy):
                await reload_xray()
    asyncio.create_task(_apply_update())
    return {"ok": True}

@app.delete("/api/links/{uid}")
async def delete_link(uid: str, _=Depends(require_auth)):
    async with LINKS_LOCK:
        removed_link = LINKS.pop(uid, None)
    async with LINK_CLIENTS_LOCK:
        link_clients.pop(uid, None)
    await save_data()
    # تلاش برای حذف بدون ری‌استارت (rmu)؛ در صورت عدم پشتیبانی، reload کامل.
    async def _apply_delete():
        if not (removed_link and await xray_remove_user(uid, removed_link)):
            await reload_xray()
    asyncio.create_task(_apply_delete())
    return {"ok": True}

# ───────── کلون لینک (با یک کلیک) ─────────
@app.post("/api/links/{uid}/clone")
async def clone_link(uid: str, request: Request, _=Depends(require_auth)):
    """یک کپی از لینک می‌سازه: همون تنظیمات (پروتکل/حجم/مدت/IP/برچسب) ولی با
    uuid و رمز تازه و مصرف صفر."""
    try:
        body = await request.json()
    except Exception:
        body = {}
    async with LINKS_LOCK:
        src = LINKS.get(uid)
        if not src:
            raise HTTPException(404, "لینک یافت نشد")
        src = dict(src)
    protocols = link_protocols(src)
    new_uid   = str(_uuid_mod.uuid4())
    new_label = (str(body.get("label") or "").strip() or f"{src.get('label', 'لینک')} (کپی)")[:60]
    # رمز Trojan باید یکتا باشه وگرنه با لینک اصلی تداخل می‌کنه → رمز تازه می‌سازیم
    new_link = _new_link_dict(
        label=new_label, protocols=protocols,
        limit_bytes=int(src.get("limit_bytes", 0) or 0),
        expires_at=src.get("expires_at"),
        password=secrets.token_urlsafe(16),
        ss_method=src.get("ss_method", "aes-256-gcm"),
        reset_days=int(src.get("reset_days", 0) or 0),
        max_ips=int(src.get("max_ips", 0) or 0),
        tags=list(src.get("tags", []) or []),
        note=str(src.get("note", "") or ""),
    )
    async with LINKS_LOCK:
        LINKS[new_uid] = new_link
    await save_data()
    async def _apply():
        if not await xray_add_user(new_uid, new_link):
            await reload_xray()
    asyncio.create_task(_apply())
    host  = _detect_host()
    conns = get_link_connections(new_uid, new_link, host)
    return {"uuid": new_uid, "label": new_label, "protocol": protocols[0], "protocols": protocols,
            "limit_bytes": new_link["limit_bytes"], "used_bytes": 0, "active": True,
            "created_at": new_link["created_at"], "expires_at": new_link["expires_at"],
            "tags": new_link["tags"], "note": new_link["note"],
            "connection": conns[0] if conns else {}, "connections": conns}

# ───────── ساخت گروهی N لینک یک‌جا ─────────
@app.post("/api/links/bulk")
async def bulk_create_links(request: Request, _=Depends(require_auth)):
    body = await request.json()
    count = int(float(body.get("count") or 0))
    if count < 1 or count > 100:
        raise HTTPException(400, "تعداد باید بین ۱ تا ۱۰۰ باشد")
    prefix = (str(body.get("label_prefix") or body.get("label") or "کاربر").strip())[:50]
    protocols = body.get("protocols")
    if not isinstance(protocols, list) or not protocols:
        protocols = [body.get("protocol", "vless")]
    protocols = list(dict.fromkeys(protocols))
    for p in protocols:
        if p not in SUPPORTED_PROTOCOLS:
            raise HTTPException(400, f"پروتکل نامعتبر: {p}")
    limit_value = float(body.get("limit_value") or 0)
    limit_unit  = body.get("limit_unit") or "GB"
    expire_days = float(body.get("expire_days") or 0)
    reset_days  = int(float(body.get("reset_days") or 0))
    max_ips     = int(float(body.get("max_ips") or 0))
    ss_method   = body.get("ss_method") or "aes-256-gcm"
    tags        = _normalize_tags(body.get("tags"))
    note        = str(body.get("note") or "").strip()[:500]
    limit_bytes = 0 if limit_value <= 0 else parse_size_to_bytes(limit_value, limit_unit)

    created = []
    async with LINKS_LOCK:
        for i in range(count):
            expires_at = (datetime.now() + timedelta(days=expire_days)).isoformat() if expire_days > 0 else None
            new_uid = str(_uuid_mod.uuid4())
            nl = _new_link_dict(
                label=f"{prefix} {i+1}", protocols=list(protocols), limit_bytes=limit_bytes,
                expires_at=expires_at, password=secrets.token_urlsafe(16), ss_method=ss_method,
                reset_days=reset_days, max_ips=max_ips, tags=list(tags), note=note,
            )
            LINKS[new_uid] = nl
            created.append({"uuid": new_uid, "label": nl["label"]})
    await save_data()
    # برای چند لینک، یک reload واحد ساده‌تر و کم‌هزینه‌تر از N فراخوانی adu است.
    asyncio.create_task(reload_xray())
    return {"ok": True, "created": len(created), "links": created}

# ───────── عملیات گروهی: حذف/تمدید/فعال/غیرفعال/ریست دسته‌ای ─────────
@app.post("/api/links/bulk-action")
async def bulk_action_links(request: Request, _=Depends(require_auth)):
    body   = await request.json()
    uuids  = body.get("uuids") or []
    action = str(body.get("action") or "").strip()
    if not isinstance(uuids, list) or not uuids:
        raise HTTPException(400, "هیچ لینکی انتخاب نشده")
    if action not in ("delete", "activate", "deactivate", "renew", "reset"):
        raise HTTPException(400, f"عملیات نامعتبر: {action}")

    affected = 0
    if action == "renew":
        ed = float(body.get("expire_days") or 0)
        if ed <= 0:
            raise HTTPException(400, "مدت تمدید نامعتبر است")
        new_exp = (datetime.now() + timedelta(days=ed)).isoformat()
        async with LINKS_LOCK:
            for u in uuids:
                if u in LINKS:
                    LINKS[u]["expires_at"] = new_exp
                    LINKS[u]["active"] = True
                    affected += 1
    elif action in ("activate", "deactivate"):
        want = (action == "activate")
        async with LINKS_LOCK:
            for u in uuids:
                if u in LINKS:
                    LINKS[u]["active"] = want
                    affected += 1
    elif action == "delete":
        async with LINKS_LOCK:
            for u in uuids:
                if LINKS.pop(u, None) is not None:
                    affected += 1
        async with LINK_CLIENTS_LOCK:
            for u in uuids:
                link_clients.pop(u, None)
    elif action == "reset":
        usage = await query_xray_stats()
        for u in uuids:
            await reset_link_usage(u, usage)
            affected += 1

    await save_data()
    asyncio.create_task(reload_xray())   # یک reload واحد برای کل دسته
    return {"ok": True, "action": action, "affected": affected}

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
    st = xray_status()
    st["userapi"] = _userapi_supported   # adu/rmu فعاله یا نه (None=هنوز تشخیص داده نشده)
    return st

# ───────── Reality settings (dest / SNI از داخل پنل) ─────────
_HOSTPORT_RE = re.compile(r"^[A-Za-z0-9.\-]+(?::\d{1,5})?$")
_HOST_RE     = re.compile(r"^[A-Za-z0-9.\-]+$")

@app.get("/api/reality")
async def get_reality(_=Depends(require_auth)):
    """تنظیمات فعلی Reality. effective_* مقداری است که واقعاً در کانفیگ به‌کار می‌رود
    (پنل ← env ← پیش‌فرض)؛ مقادیر env هم برای نمایش برگردانده می‌شوند."""
    return {
        "dest":           REALITY.get("dest", ""),
        "sni":            REALITY.get("sni", ""),
        "effective_dest": reality_dest(),
        "effective_sni":  reality_sni(),
        "env_dest":       REALITY_DEST,
        "env_sni":        REALITY_SNI,
        "public_key":     REALITY.get("public_key", ""),
        "short_id":       REALITY.get("short_id", ""),
        "has_keys":       bool(REALITY.get("private_key")),
    }

@app.post("/api/reality")
async def set_reality(request: Request, _=Depends(require_auth)):
    """dest و/یا SNI را از پنل تنظیم می‌کند. مقدار خالی یعنی «به پیش‌فرض env برگرد».
    بعد از ذخیره، Xray در پس‌زمینه ری‌لود می‌شود تا تغییر اعمال شود."""
    body = await request.json()
    dest = str(body.get("dest", "")).strip()
    sni  = str(body.get("sni", "")).strip()

    if dest:
        # اگر پورت ذکر نشده باشد، :443 اضافه می‌کنیم (پیش‌فرض TLS)
        if ":" not in dest:
            dest = f"{dest}:443"
        if not _HOSTPORT_RE.match(dest):
            raise HTTPException(400, "مقصد (dest) نامعتبر است. نمونه‌ی درست: www.microsoft.com:443")
        host, _, port = dest.partition(":")
        if port and not (0 < int(port) <= 65535):
            raise HTTPException(400, "پورت dest باید بین ۱ تا ۶۵۵۳۵ باشد")
    if sni and not _HOST_RE.match(sni):
        raise HTTPException(400, "SNI نامعتبر است. فقط دامنه مجاز است، نمونه: www.microsoft.com")

    # اگر SNI خالی بماند ولی dest ست شده باشد، SNI را خودکار از هاستِ dest می‌گیریم
    if dest and not sni:
        sni = dest.split(":")[0]

    async with LINKS_LOCK:
        REALITY["dest"] = dest          # خالی = برگشت به env
        REALITY["sni"]  = sni
    await save_data()
    asyncio.create_task(reload_xray())  # غیرمسدودکننده؛ اتصال‌های فعلی موقتاً قطع و دوباره وصل می‌شوند
    return {
        "ok": True,
        "effective_dest": reality_dest(),
        "effective_sni":  reality_sni(),
    }

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
    asyncio.create_task(reload_xray())   # تا بلاک واقعاً در Xray اعمال بشه
    return {"ok": True}

@app.delete("/api/blocked/{ip}")
async def unblock_ip(ip: str, _=Depends(require_auth)):
    BLOCKED_IPS.discard(ip)
    await save_data()
    asyncio.create_task(reload_xray())   # آنبلاک هم باید در Xray اعمال بشه
    return {"ok": True}

# ───────── Export / Import (پشتیبان‌گیری) ─────────
@app.get("/api/export")
async def export_data(_=Depends(require_auth)):
    """کل کانفیگ (لینک‌ها، بلاک‌ها، کلیدهای Reality، تاریخچه) را به‌صورت JSON برمی‌گرداند."""
    async with LINKS_LOCK:
        data = {
            "links":       {k: dict(v) for k, v in LINKS.items()},
            "blocked_ips": list(BLOCKED_IPS),
            "reality":     dict(REALITY),
        }
    async with LINK_CLIENTS_LOCK:
        data["link_clients"] = {k: dict(v) for k, v in link_clients.items()}
    data["hourly_traffic"] = dict(hourly_traffic)
    data["daily_traffic"]  = dict(daily_traffic)
    data["total_bytes"]    = stats["total_bytes"]
    data["_exported_at"]   = datetime.now().isoformat()
    fname = f"tryak-backup-{datetime.now().strftime('%Y%m%d-%H%M')}.json"
    return JSONResponse(
        content=data,
        headers={"Content-Disposition": f'attachment; filename="{fname}"'},
    )

@app.post("/api/import")
async def import_data(request: Request, _=Depends(require_auth)):
    """کانفیگ را از یک فایل پشتیبان جایگزین می‌کند (لینک‌ها/بلاک‌ها/تاریخچه)."""
    try:
        data = await request.json()
    except Exception:
        raise HTTPException(400, "فایل JSON نامعتبر است")
    if not isinstance(data, dict) or "links" not in data:
        raise HTTPException(400, "ساختار فایل پشتیبان نامعتبر است (کلید links یافت نشد)")
    async with LINKS_LOCK:
        LINKS.clear()
        LINKS.update(data.get("links") or {})
    BLOCKED_IPS.clear()
    BLOCKED_IPS.update(data.get("blocked_ips") or [])
    async with LINK_CLIENTS_LOCK:
        link_clients.clear()
        for uid, clients in (data.get("link_clients") or {}).items():
            link_clients[uid].update(clients)
    hourly_traffic.clear(); hourly_traffic.update(data.get("hourly_traffic") or {})
    daily_traffic.clear();  daily_traffic.update(data.get("daily_traffic") or {})
    if isinstance(data.get("total_bytes"), (int, float)):
        stats["total_bytes"] = data["total_bytes"]
    saved_reality = data.get("reality") or {}
    if saved_reality.get("private_key"):
        REALITY.update(saved_reality)
    await save_data()
    asyncio.create_task(reload_xray())
    return {"ok": True, "links": len(LINKS)}

# ───────── Subscription helpers (هدر Userinfo + فرمت‌های Clash / sing-box) ─────────
def _sub_userinfo_headers(link: dict) -> dict:
    """هدر استاندارد Subscription-Userinfo که کلاینت‌هایی مثل v2rayNG / NekoBox /
    Streisand مصرف، سهمیه و تاریخ انقضا رو مستقیم داخل اپ نشون می‌دن.
    قالب: upload=..; download=..; total=..; expire=<unix>  (total=0 یعنی نامحدود)."""
    used  = int(link.get("used_bytes", 0) or 0)
    total = int(link.get("limit_bytes", 0) or 0)
    parts = ["upload=0", f"download={used}", f"total={total}"]
    exp = link.get("expires_at")
    if exp:
        try:
            parts.append(f"expire={int(datetime.fromisoformat(exp).timestamp())}")
        except Exception:
            pass
    h = {
        "Subscription-Userinfo":   "; ".join(parts),
        "Profile-Update-Interval": "12",          # ساعت
    }
    label = link.get("label")
    if label:
        try:
            h["Profile-Title"] = "base64:" + base64.b64encode(str(label).encode()).decode()
        except Exception:
            pass
    return h

_VPN_UA_MARKERS = ("v2ray", "clash", "sing-box", "singbox", "nekobox", "neko", "hiddify",
                   "shadowrocket", "quantumult", "surfboard", "streisand", "mihomo",
                   "stash", "loon", "python", "go-http", "okhttp", "curl", "wget", "axios")

def is_vpn_ua(ua: str) -> bool:
    return any(m in ua for m in _VPN_UA_MARKERS)

def _detect_sub_format(request: Request) -> str:
    """فرمت خروجی ساب رو تشخیص می‌ده: clash | singbox | base64.
    اولویت با پارامتر ?format= است، بعد User-Agent."""
    fmt = (request.query_params.get("format") or "").lower().strip()
    if fmt in ("clash", "clashmeta", "clash-meta", "meta"):
        return "clash"
    if fmt in ("singbox", "sing-box", "sing"):
        return "singbox"
    if fmt in ("v2ray", "v2rayng", "base64", "raw", "sub"):
        return "base64"
    ua = request.headers.get("user-agent", "").lower()
    if "clash" in ua or "mihomo" in ua or "stash" in ua:
        return "clash"
    if "sing-box" in ua or "singbox" in ua:
        return "singbox"
    return "base64"

def _yaml_q(s) -> str:
    """رشته رو برای YAML امن نقل‌قول می‌کنه."""
    return '"' + str(s).replace("\\", "\\\\").replace('"', '\\"') + '"'

def build_clash_yaml(uid: str, link: dict, host: str) -> str:
    """کانفیگ کامل و قابل‌استفاده‌ی Clash Meta (mihomo). فقط پروتکل‌های قابل پشتیبانی
    (VLESS+WS، Trojan+WS، VLESS+Reality) خروجی داده می‌شن؛ XHTTP که در کلاینت‌های Clash
    پشتیبانی فراگیر نداره نادیده گرفته می‌شه."""
    label = link.get("label", "tryak")
    proxies, names = [], []
    for proto in link_protocols(link):
        if proto == "vless":
            name = f"{label} · VLESS"
            block = [
                f"  - name: {_yaml_q(name)}", "    type: vless",
                f"    server: {_yaml_q(host)}", "    port: 443",
                f"    uuid: {_yaml_q(uid)}", "    udp: true", "    tls: true",
                f"    servername: {_yaml_q(host)}", "    network: ws",
                "    client-fingerprint: chrome", "    ws-opts:",
                f"      path: {_yaml_q('/xray-ws')}", "      headers:",
                f"        Host: {_yaml_q(host)}",
            ]
        elif proto == "trojan":
            name = f"{label} · Trojan"
            block = [
                f"  - name: {_yaml_q(name)}", "    type: trojan",
                f"    server: {_yaml_q(host)}", "    port: 443",
                f"    password: {_yaml_q(link.get('password', uid))}", "    udp: true",
                f"    sni: {_yaml_q(host)}", "    network: ws",
                "    client-fingerprint: chrome", "    ws-opts:",
                f"      path: {_yaml_q('/xray-trojan')}", "      headers:",
                f"        Host: {_yaml_q(host)}",
            ]
        elif proto == "vless-reality":
            if not REALITY.get("public_key"):
                continue
            rhost = _detect_reality_host()
            rport = _detect_reality_public_port()
            name = f"{label} · Reality"
            block = [
                f"  - name: {_yaml_q(name)}", "    type: vless",
                f"    server: {_yaml_q(rhost)}", f"    port: {rport}",
                f"    uuid: {_yaml_q(uid)}", "    udp: true", "    tls: true",
                "    flow: xtls-rprx-vision", f"    servername: {_yaml_q(reality_sni())}",
                "    client-fingerprint: chrome", "    reality-opts:",
                f"      public-key: {_yaml_q(REALITY.get('public_key', ''))}",
                f"      short-id: {_yaml_q(REALITY.get('short_id', ''))}",
            ]
        else:
            continue
        proxies.append("\n".join(block))
        names.append(name)

    out = [
        "# Clash Meta (mihomo) config — tryak", "mixed-port: 7890",
        "allow-lan: false", "mode: rule", "log-level: warning", "ipv6: true",
        "proxies:",
    ]
    if proxies:
        out.extend(proxies)
    out.append("proxy-groups:")
    out.append("  - name: PROXY")
    out.append("    type: select")
    out.append("    proxies:")
    for n in (names or ["DIRECT"]):
        out.append(f"      - {_yaml_q(n)}")
    out.append("rules:")
    out.append("  - GEOIP,private,DIRECT,no-resolve")
    out.append("  - MATCH,PROXY")
    return "\n".join(out) + "\n"

def build_singbox_json(uid: str, link: dict, host: str) -> str:
    """کانفیگ قابل‌استفاده‌ی sing-box با inbound mixed + dns + route. فقط
    VLESS+WS، Trojan+WS و VLESS+Reality خروجی داده می‌شن."""
    label = link.get("label", "tryak")
    outs, tags = [], []
    for proto in link_protocols(link):
        if proto == "vless":
            tag = f"{label} VLESS"
            o = {"type": "vless", "tag": tag, "server": host, "server_port": 443,
                 "uuid": uid,
                 "tls": {"enabled": True, "server_name": host,
                         "utls": {"enabled": True, "fingerprint": "chrome"}},
                 "transport": {"type": "ws", "path": "/xray-ws", "headers": {"Host": host}}}
        elif proto == "trojan":
            tag = f"{label} Trojan"
            o = {"type": "trojan", "tag": tag, "server": host, "server_port": 443,
                 "password": link.get("password", uid),
                 "tls": {"enabled": True, "server_name": host,
                         "utls": {"enabled": True, "fingerprint": "chrome"}},
                 "transport": {"type": "ws", "path": "/xray-trojan", "headers": {"Host": host}}}
        elif proto == "vless-reality":
            if not REALITY.get("public_key"):
                continue
            tag = f"{label} Reality"
            o = {"type": "vless", "tag": tag, "server": _detect_reality_host(),
                 "server_port": _detect_reality_public_port(), "uuid": uid,
                 "flow": "xtls-rprx-vision",
                 "tls": {"enabled": True, "server_name": reality_sni(),
                         "utls": {"enabled": True, "fingerprint": "chrome"},
                         "reality": {"enabled": True,
                                     "public_key": REALITY.get("public_key", ""),
                                     "short_id": REALITY.get("short_id", "")}}}
        else:
            continue
        outs.append(o)
        tags.append(tag)

    selector = {"type": "selector", "tag": "proxy", "outbounds": tags + ["direct"]}
    config = {
        "log": {"level": "warn"},
        "dns": {"servers": [{"tag": "google", "address": "tls://8.8.8.8"}]},
        "inbounds": [{"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": 2080}],
        "outbounds": [*outs, selector,
                      {"type": "direct", "tag": "direct"},
                      {"type": "block", "tag": "block"}],
        "route": {"final": "proxy", "auto_detect_interface": True,
                  "rules": [{"ip_is_private": True, "outbound": "direct"}]},
    }
    return json.dumps(config, ensure_ascii=False, indent=2)

def make_subscription_response(uid: str, link: dict, request: Request) -> Response:
    """خروجی ساب رو بر اساس فرمت درخواستی (clash/singbox/base64) می‌سازه و همیشه
    هدر Subscription-Userinfo (مصرف/سهمیه/انقضا) رو ضمیمه می‌کنه."""
    host    = _detect_host()
    fmt     = _detect_sub_format(request)
    headers = _sub_userinfo_headers(link)
    if fmt == "clash":
        headers["Content-Disposition"] = f'attachment; filename="{uid[:8]}.yaml"'
        return Response(content=build_clash_yaml(uid, link, host),
                        media_type="text/yaml; charset=utf-8", headers=headers)
    if fmt == "singbox":
        headers["Content-Disposition"] = f'attachment; filename="{uid[:8]}.json"'
        return Response(content=build_singbox_json(uid, link, host),
                        media_type="application/json; charset=utf-8", headers=headers)
    # base64 استاندارد (v2rayNG / NekoBox / Streisand ...)
    conns = get_link_connections(uid, link, host)
    importable = [c["link"] for c in conns if c.get("link", "").startswith(("vless://", "trojan://"))]
    encoded = base64.b64encode("\n".join(importable).encode()).decode()
    return Response(content=encoded, media_type="text/plain; charset=utf-8", headers=headers)

# ───────── Subscription Page ─────────
@app.get("/sub/{uid}/raw", response_class=Response)
async def subscription_raw(uid: str, request: Request):
    """لینک سابسکریپشن استاندارد (Base64) برای وارد کردن مستقیم در کلاینت‌هایی مثل
    v2rayNG / v2rayN / NekoBox / Streisand و غیره. خروجی متن ساده‌ست: هر خط یک
    لینک (vless:// trojan:// ss://...)، که کل متن با Base64 استاندارد انکود شده.
    HTTP Proxy در این لیست نمیاد چون فرمت قابل‌import در کلاینت‌های VPN نیست.
    با پارامتر ?format=clash یا ?format=singbox می‌شه خروجی Clash Meta یا sing-box گرفت."""
    async with LINKS_LOCK:
        link = LINKS.get(uid)
    if not link:
        raise HTTPException(404, "لینک یافت نشد")
    return make_subscription_response(uid, link, request)


@app.get("/sub/{uid}")
async def subscription_page(uid: str, request: Request):
    # کلاینت‌های VPN (v2rayNG، Nekobox، ویتوری، clash و ...) با User-Agent شناسایی میشن
    # و برای اونا مستقیم raw برمیگردونیم؛ مرورگر انسانی HTML زیبا می‌بینه
    ua = request.headers.get("user-agent", "").lower()
    # کلاینت VPN یا درخواست با ?format= → خروجی ساب (base64/clash/singbox) به‌همراه
    # هدر Subscription-Userinfo؛ مرورگر انسانی → صفحه‌ی HTML زیبا.
    if is_vpn_ua(ua) or not ua or request.query_params.get("format"):
        async with LINKS_LOCK:
            link_check = LINKS.get(uid)
        if not link_check:
            raise HTTPException(404, "لینک یافت نشد")
        return make_subscription_response(uid, link_check, request)

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

    used_fmt      = fmt_usage(used_b)
    limit_fmt     = fmt_bytes(limit_b)
    remaining_fmt = fmt_usage(remaining_b) if limit_b > 0 else "نامحدود ♾️"
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

    # نام کوتاه و خوانا برای هر کانفیگ (به‌جای نمایش کامل لینک)
    _short_proto_names = {
        "vless":         "VLESS · WS",
        "trojan":        "Trojan · WS",
        "vless-xhttp":   "VLESS · XHTTP",
        "vless-reality": "VLESS · Reality",
    }
    conn_sections_html = ""
    for i, conn in enumerate(conns):
        show_qr = conn.get("link", "").startswith(("vless://", "trojan://"))
        short_name = _short_proto_names.get(conn.get("proto_key", ""), conn.get("protocol", ""))
        conn_sections_html += f"""
    <div class="conn-section" style="margin-top:{12 if i > 0 else 0}px">
      <div class="conn-name"><i class="ti ti-plug"></i> {i + 1}. {short_name}</div>
      <div class="btn-row">
        <button class="btn btn-primary" onclick="copyLink({i})"><i class="ti ti-copy"></i> کپی لینک</button>
        {f'<button class="btn btn-outline" onclick="showQR({i})"><i class="ti ti-qrcode"></i> QR</button>' if show_qr else ''}
      </div>
    </div>"""

    conn_links_js = ",".join(json.dumps(c.get("link", "")) for c in conns)

    # لینک ساب raw (استاندارد base64) برای کپی مستقیم در کلاینت‌ها
    sub_link_url = f"https://{host}/sub/{uid}/raw"

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
:root{{--accent:#6366f1;--accent2:#4f46e5;--accent-glow:rgba(99,102,241,0.35);--green:#4ce090;--red:#f56565;--amber:#f0b14a;--bg:#070b14;--card:#10172a;--card2:#151d33;--border:rgba(255,255,255,0.10);--text-1:#eef2ff;--text-2:#9aa8c7;--text-3:#5a6b8c;--glass:rgba(255,255,255,0.05);--glass-strong:rgba(255,255,255,0.08);--glass-hi:rgba(255,255,255,0.10)}}
body{{font-family:'Vazirmatn',sans-serif;background:var(--bg);min-height:100vh;display:flex;align-items:center;justify-content:center;padding:16px;color:var(--text-1);position:relative;overflow-x:hidden}}
body::before{{content:'';position:fixed;inset:-25%;z-index:-1;background:radial-gradient(38% 38% at 22% 28%,rgba(99,102,241,.30),transparent 70%),radial-gradient(36% 36% at 80% 72%,rgba(56,189,248,.22),transparent 70%),radial-gradient(40% 40% at 62% 12%,rgba(168,85,247,.20),transparent 70%);filter:blur(46px);animation:aurora 26s ease-in-out infinite alternate;will-change:transform}}
@keyframes aurora{{0%{{transform:translate3d(-3%,-2%,0) scale(1)}}50%{{transform:translate3d(4%,3%,0) scale(1.08)}}100%{{transform:translate3d(-2%,3%,0) scale(1.05)}}}}
.card{{background:var(--glass);backdrop-filter:blur(22px) saturate(150%);-webkit-backdrop-filter:blur(22px) saturate(150%);border-radius:22px;width:100%;max-width:420px;border:1px solid var(--border);overflow:hidden;box-shadow:0 24px 70px rgba(0,0,0,.55),inset 0 1px 0 var(--glass-hi);animation:cardIn .55s cubic-bezier(.2,.7,.3,1)}}
@keyframes cardIn{{from{{opacity:0;transform:translateY(16px) scale(.985)}}to{{opacity:1;transform:none}}}}
.card-header{{padding:22px 24px 18px;background:linear-gradient(135deg,rgba(99,102,241,0.20),rgba(56,189,248,0.06));border-bottom:1px solid var(--border);position:relative}}
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
.stat-box{{background:var(--glass);backdrop-filter:blur(10px);-webkit-backdrop-filter:blur(10px);border-radius:14px;border:1px solid var(--border);padding:13px 15px;position:relative;overflow:hidden;transition:transform .25s ease,border-color .25s ease}}
.stat-box:hover{{transform:translateY(-3px);border-color:rgba(99,102,241,.4)}}
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
.progress-fill{{height:100%;border-radius:8px;transition:width .6s cubic-bezier(.2,.7,.3,1);background:linear-gradient(90deg,{bar},{bar_glow});box-shadow:0 0 12px {bar_glow};position:relative;overflow:hidden}}
.progress-fill::after{{content:'';position:absolute;inset:0;background:linear-gradient(90deg,transparent,rgba(255,255,255,.40),transparent);transform:translateX(-100%);animation:shimmer 2.8s ease-in-out infinite}}
@keyframes shimmer{{0%{{transform:translateX(-100%)}}55%,100%{{transform:translateX(100%)}}}}
.progress-labels{{display:flex;justify-content:space-between;font-size:10px;color:var(--text-2)}}

/* ─── Info Rows ─── */
.info-rows{{margin-bottom:16px}}
.info-row{{display:flex;justify-content:space-between;align-items:center;padding:9px 0;border-bottom:1px solid var(--border);font-size:12px}}
.info-row:last-child{{border-bottom:none}}
.info-key{{color:var(--text-2);display:flex;align-items:center;gap:7px}}
.info-key i{{font-size:14px;color:var(--accent)}}
.info-val{{color:var(--text-1);font-weight:600;text-align:left}}

/* ─── Conn Section ─── */
.conn-section{{background:var(--glass);backdrop-filter:blur(8px);-webkit-backdrop-filter:blur(8px);border-radius:14px;border:1px solid var(--border);padding:14px;transition:border-color .25s ease}}
.conn-section:hover{{border-color:rgba(99,102,241,.4)}}
.conn-label{{font-size:11px;font-weight:600;color:var(--text-2);margin-bottom:8px;display:flex;align-items:center;gap:6px}}
.conn-label i{{font-size:13px;color:var(--accent)}}
.conn-name{{font-size:13.5px;font-weight:700;color:var(--text-1);margin-bottom:12px;display:flex;align-items:center;gap:7px}}
.conn-name i{{font-size:15px;color:var(--accent)}}
.conn-text{{font-family:ui-monospace,monospace;font-size:9.5px;color:#93c5fd;word-break:break-all;line-height:1.7;background:rgba(0,0,0,.25);border-radius:8px;padding:10px 12px;margin-bottom:10px;border:1px solid rgba(99,102,241,0.1)}}
.btn-row{{display:flex;gap:8px;flex-wrap:wrap}}
.btn{{font-family:inherit;font-size:12px;font-weight:600;border-radius:9px;padding:9px 14px;cursor:pointer;display:inline-flex;align-items:center;gap:6px;border:none;transition:.15s;flex:1;justify-content:center}}
.btn-primary{{background:linear-gradient(135deg,var(--accent),var(--accent2));color:#fff;box-shadow:0 6px 18px var(--accent-glow),inset 0 1px 0 rgba(255,255,255,.25);transition:transform .2s ease,filter .2s ease,box-shadow .2s ease}}
.btn-primary:hover{{transform:translateY(-2px);box-shadow:0 10px 26px var(--accent-glow),inset 0 1px 0 rgba(255,255,255,.3)}}
.btn-primary:hover{{filter:brightness(1.1)}}
.btn-outline{{background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.12);color:var(--text-1)}}
.btn-outline:hover{{background:rgba(255,255,255,.08)}}
.btn-success{{background:rgba(76,224,144,0.12);border:1px solid rgba(76,224,144,0.25);color:var(--green)}}
.proto-badge{{display:inline-block;font-size:10px;background:rgba(99,102,241,0.16);color:#c7d2fe;border:1px solid rgba(99,102,241,0.30);border-radius:7px;padding:2px 8px;font-weight:600;margin:2px 2px 0 0}}
.sub-section{{background:rgba(99,102,241,0.06);border-radius:12px;border:1px solid rgba(99,102,241,0.15);padding:14px;margin-bottom:12px}}
.all-configs-btn{{width:100%;margin-bottom:12px}}
.divider{{height:1px;background:var(--border);margin:14px 0}}
.section-title{{font-size:11px;font-weight:700;color:var(--text-2);text-transform:uppercase;letter-spacing:.08em;margin-bottom:12px;display:flex;align-items:center;gap:6px}}
.section-title i{{color:var(--accent);font-size:14px}}
.footer{{text-align:center;font-size:10px;color:var(--text-3);padding-top:14px}}
.status-dot{{box-shadow:0 0 8px currentColor}}
@keyframes spin{{to{{transform:rotate(360deg)}}}}
.ti-loader-2{{display:inline-block;animation:spin 1s linear infinite}}
@media(prefers-reduced-motion:reduce){{*{{animation:none!important;transition:none!important}}body::before{{animation:none!important}}}}
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

    <!-- ── Subscription (raw) Link ── -->
    <div class="section-title"><i class="ti ti-rss"></i>لینک اشتراک</div>
    <div class="conn-section" style="margin-bottom:14px">
      <div class="conn-label"><i class="ti ti-link"></i> لینک ساب (Subscription)</div>
      <div class="conn-text" id="sub-link">{sub_link_url}</div>
      <div class="btn-row">
        <button class="btn btn-primary" onclick="copySubLink()"><i class="ti ti-copy"></i> کپی لینک ساب</button>
        <button class="btn btn-outline" onclick="showSubQR()"><i class="ti ti-qrcode"></i> QR</button>
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
  const t=(ALL_LINKS[i]||'').trim();
  navigator.clipboard.writeText(t).then(()=>{{
    const b=event.currentTarget;const o=b.innerHTML;
    b.innerHTML='<i class="ti ti-check"></i> کپی شد!';
    b.classList.add('btn-success');
    setTimeout(()=>{{b.innerHTML=o;b.classList.remove('btn-success')}},2000);
  }});
}}
function showQR(i){{
  const t=(ALL_LINKS[i]||'').trim();
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
function showSubQR(){{
  const t=document.getElementById('sub-link').textContent.trim();
  window.open('https://api.qrserver.com/v1/create-qr-code/?size=300x300&data='+encodeURIComponent(t),'_blank');
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
:root{--accent:#6366f1;--accent2:#4f46e5;--accent-glow:rgba(99,102,241,0.35);--bg:#070b14;--card:#10172a;--card2:#151d33;--border:rgba(255,255,255,0.10);--text-1:#eef2ff;--text-2:#9aa8c7;--red-bg:#2a1212;--red-text:#f5a3a3;--green-text:#7ee0a8;--glass:rgba(255,255,255,0.05);--glass-hi:rgba(255,255,255,0.10)}
html,body{height:100%}
body{font-family:'Vazirmatn',sans-serif;background:var(--bg);min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px;color:var(--text-1);position:relative;overflow:hidden}
body::before{content:'';position:fixed;inset:-25%;z-index:0;background:radial-gradient(38% 38% at 20% 22%,rgba(99,102,241,.32),transparent 70%),radial-gradient(36% 36% at 82% 78%,rgba(56,189,248,.24),transparent 70%),radial-gradient(40% 40% at 60% 12%,rgba(168,85,247,.20),transparent 70%);filter:blur(48px);animation:aurora 26s ease-in-out infinite alternate;will-change:transform}
@keyframes aurora{0%{transform:translate3d(-3%,-2%,0) scale(1)}50%{transform:translate3d(4%,3%,0) scale(1.08)}100%{transform:translate3d(-2%,3%,0) scale(1.05)}}
.card{background:var(--glass);backdrop-filter:blur(26px) saturate(150%);-webkit-backdrop-filter:blur(26px) saturate(150%);border-radius:24px;padding:36px 30px;width:100%;max-width:380px;box-shadow:0 24px 70px rgba(0,0,0,.55),inset 0 1px 0 var(--glass-hi);border:1px solid var(--border);position:relative;overflow:hidden;z-index:1;animation:cardIn .55s cubic-bezier(.2,.7,.3,1)}
@keyframes cardIn{from{opacity:0;transform:translateY(18px) scale(.98)}to{opacity:1;transform:none}}
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
.form-input{width:100%;padding:13px 15px;border-radius:12px;border:1px solid var(--border);font-family:inherit;font-size:14px;outline:none;background:rgba(255,255,255,.04);color:var(--text-1);transition:.18s}
.form-input:focus{border-color:var(--accent);box-shadow:0 0 0 3px var(--accent-glow)}
.btn-login{width:100%;padding:14px;border-radius:12px;border:none;cursor:pointer;background:linear-gradient(135deg,var(--accent),var(--accent2));color:#fff;font-family:inherit;font-size:14px;font-weight:700;display:flex;align-items:center;justify-content:center;gap:8px;transition:transform .2s ease,filter .2s ease,box-shadow .2s ease;box-shadow:0 6px 22px var(--accent-glow),inset 0 1px 0 rgba(255,255,255,.25);position:relative;z-index:1}
.btn-login:hover:not(:disabled){transform:translateY(-2px);box-shadow:0 10px 28px var(--accent-glow),inset 0 1px 0 rgba(255,255,255,.3)}
.btn-login:hover{filter:brightness(1.1)}
.btn-login:disabled{opacity:.6;cursor:not-allowed}
.error-box{background:var(--red-bg);color:var(--red-text);font-size:12.5px;padding:10px 13px;border-radius:9px;margin-bottom:14px;display:none;align-items:center;gap:8px;border:1px solid rgba(240,128,128,.2);position:relative;z-index:1}
.error-box.show{display:flex}
.footer{margin-top:18px;text-align:center;font-size:11px;color:var(--text-2);position:relative;z-index:1}
.dot{box-shadow:0 0 8px currentColor}
@keyframes spin{to{transform:rotate(360deg)}}
.ti-loader-2{display:inline-block;animation:spin 1s linear infinite}
@media(prefers-reduced-motion:reduce){*{animation:none!important;transition:none!important}body::before{animation:none!important}}
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
<script src="https://cdn.jsdelivr.net/gh/davidshimjs/qrcodejs@master/qrcode.min.js"></script>
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{
  --accent:#6366f1;--accent2:#4f46e5;--accent-glow:rgba(99,102,241,0.35);
  --green-text:#7ee0a8;--green-dot:#4ce090;--red-text:#f5a3a3;--red-dot:#f56565;
  --amber-text:#f0c878;--amber-dot:#f0b14a;
  --border:rgba(255,255,255,0.09);--bg:#070b14;--card:#10172a;--card2:#151d33;
  --text-1:#eef2ff;--text-2:#9aa8c7;--text-3:#5a6b8c;
  --shadow:0 8px 32px rgba(0,0,0,.38),inset 0 1px 0 rgba(255,255,255,.06);
  --glass:rgba(255,255,255,0.045);--glass-strong:rgba(255,255,255,0.07);--glass-hi:rgba(255,255,255,0.07);
}
html,body{height:100%}
body{font-family:'Vazirmatn',sans-serif;background:var(--bg);color:var(--text-1);min-height:100vh;display:flex;font-size:14px;position:relative}
body::before{content:'';position:fixed;inset:-20%;z-index:-1;background:radial-gradient(34% 34% at 16% 12%,rgba(99,102,241,.22),transparent 70%),radial-gradient(32% 32% at 88% 86%,rgba(56,189,248,.16),transparent 70%),radial-gradient(36% 36% at 70% 30%,rgba(168,85,247,.14),transparent 70%);filter:blur(50px);animation:aurora 30s ease-in-out infinite alternate;will-change:transform}
@keyframes aurora{0%{transform:translate3d(-2%,-2%,0) scale(1)}50%{transform:translate3d(3%,2%,0) scale(1.07)}100%{transform:translate3d(-1%,2%,0) scale(1.04)}}
::-webkit-scrollbar{width:5px;height:5px}
::-webkit-scrollbar-thumb{background:var(--card2);border-radius:3px}

/* SIDEBAR */
.sidebar{width:232px;min-height:100vh;background:linear-gradient(180deg,rgba(16,23,42,.72),rgba(7,12,24,.82));backdrop-filter:blur(20px) saturate(140%);-webkit-backdrop-filter:blur(20px) saturate(140%);border-left:1px solid var(--border);display:flex;flex-direction:column;flex-shrink:0;position:fixed;right:0;top:0;bottom:0;z-index:200;transition:transform .25s}
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
.metric{background:var(--glass);backdrop-filter:blur(16px) saturate(140%);-webkit-backdrop-filter:blur(16px) saturate(140%);border-radius:15px;border:1px solid var(--border);padding:16px 18px;box-shadow:var(--shadow);transition:transform .25s ease,border-color .25s ease}
.metric:hover{transform:translateY(-3px);border-color:rgba(99,102,241,.4)}
.metric-label{font-size:10.5px;color:var(--text-2);font-weight:600;text-transform:uppercase;letter-spacing:.06em;margin-bottom:10px;display:flex;align-items:center;gap:6px}
.metric-label i{font-size:16px;color:var(--accent)}
.metric-val{font-size:24px;font-weight:700;color:var(--text-1);line-height:1}
.metric-sub{font-size:11px;color:var(--text-2);margin-top:4px}

/* CARDS */
.card{background:var(--glass);backdrop-filter:blur(16px) saturate(140%);-webkit-backdrop-filter:blur(16px) saturate(140%);border-radius:15px;border:1px solid var(--border);padding:18px 20px;box-shadow:var(--shadow);transition:border-color .25s ease}
.card:hover{border-color:rgba(99,102,241,.28)}
.card-title{font-size:13px;font-weight:700;color:var(--text-1);margin-bottom:14px;display:flex;align-items:center;gap:7px}
.card-title i{font-size:17px;color:var(--accent)}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:18px}

/* BUTTONS */
.btn{font-family:inherit;font-size:12.5px;font-weight:600;border-radius:9px;padding:8px 14px;cursor:pointer;display:inline-flex;align-items:center;gap:6px;border:none;transition:.15s}
.btn-primary{background:linear-gradient(135deg,var(--accent),var(--accent2));color:#fff;box-shadow:0 6px 18px var(--accent-glow),inset 0 1px 0 rgba(255,255,255,.25);transition:transform .2s ease,filter .2s ease}
.btn-primary:hover{transform:translateY(-1px)}
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
.form-input,.form-select{padding:9px 12px;border-radius:10px;border:1px solid var(--border);font-family:inherit;font-size:12.5px;outline:none;color:var(--text-1);background:rgba(255,255,255,.04);min-width:110px;transition:.18s}
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
.modal{background:rgba(16,23,42,.82);backdrop-filter:blur(28px) saturate(150%);-webkit-backdrop-filter:blur(28px) saturate(150%);border-radius:18px;border:1px solid var(--border);padding:26px 24px;width:100%;max-width:480px;max-height:90vh;overflow-y:auto;box-shadow:0 24px 70px rgba(0,0,0,.5),inset 0 1px 0 var(--glass-hi);animation:modalIn .35s cubic-bezier(.2,.7,.3,1)}
@keyframes modalIn{from{opacity:0;transform:translateY(14px) scale(.98)}to{opacity:1;transform:none}}
.modal-title{font-size:15px;font-weight:700;color:var(--text-1);margin-bottom:20px;display:flex;align-items:center;gap:8px}
.modal-title i{font-size:18px;color:var(--accent)}
.modal-footer{display:flex;gap:10px;justify-content:flex-end;margin-top:20px;padding-top:16px;border-top:1px solid var(--border)}

/* XRAY STATUS CARD */
.xray-status-card{background:linear-gradient(135deg,rgba(99,102,241,.16),rgba(56,189,248,.05));backdrop-filter:blur(14px) saturate(140%);-webkit-backdrop-filter:blur(14px) saturate(140%);border:1px solid rgba(99,102,241,.28);border-radius:15px;padding:18px 20px;margin-bottom:18px;display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap}
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
/* glass finishing touches */
.links-table tr:hover td{background:rgba(255,255,255,.035)}
.conn-box{background:rgba(255,255,255,.04)}
.nav-item.active{box-shadow:inset 2px 0 14px -8px var(--accent)}
.status-dot,.dot,.pill-dot{box-shadow:0 0 7px currentColor}
@keyframes spin{to{transform:rotate(360deg)}}
.ti-loader-2{display:inline-block;animation:spin 1s linear infinite}
@media(prefers-reduced-motion:reduce){*{animation:none!important;transition:none!important}body::before{animation:none!important}}
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
    <div class="nav-item" onclick="showPage('backup')"><i class="ti ti-database-export"></i>پشتیبان</div>
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

    <div class="grid2" style="margin-top:16px">
      <div class="card">
        <div class="card-title"><i class="ti ti-calendar-stats"></i>ترافیک ۷ روز اخیر</div>
        <div id="chart-week-total" style="font-size:22px;font-weight:700;margin:4px 0 14px">—</div>
        <div id="chart-week"><div style="color:var(--text-2);font-size:12px;padding:20px 0;text-align:center">در حال بارگذاری...</div></div>
      </div>
      <div class="card">
        <div class="card-title"><i class="ti ti-flame"></i>بیشترین مصرف (به تفکیک لینک)</div>
        <div id="top-consumers" style="margin-top:6px"><div style="color:var(--text-2);font-size:12px;padding:14px 0;text-align:center">در حال بارگذاری...</div></div>
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
      <div style="display:flex;gap:8px;flex-wrap:wrap">
        <button class="btn btn-outline" onclick="showBulkModal()"><i class="ti ti-layers-subtract"></i>ساخت گروهی</button>
        <button class="btn btn-primary" onclick="showCreateModal()"><i class="ti ti-plus"></i>لینک جدید</button>
      </div>
    </div>
    <!-- جستجو / فیلتر -->
    <div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:12px">
      <input id="link-search" class="form-input" placeholder="🔍 جستجو در نام، برچسب، یادداشت یا UUID..." oninput="applyLinkFilter()" style="flex:1;min-width:200px">
      <select id="link-filter" class="form-select" onchange="applyLinkFilter()" style="min-width:120px">
        <option value="all">همه‌ی لینک‌ها</option>
        <option value="active">فعال</option>
        <option value="inactive">غیرفعال</option>
        <option value="expired">منقضی</option>
        <option value="quota">سهمیه تمام‌شده</option>
      </select>
    </div>
    <!-- نوار عملیات گروهی -->
    <div id="bulk-bar" class="card" style="display:none;margin-bottom:12px;flex-wrap:wrap;gap:8px;align-items:center">
      <span id="bulk-count" style="font-weight:600;font-size:13px;margin-inline-end:auto"></span>
      <button class="btn btn-outline btn-sm" onclick="bulkAction('activate')"><i class="ti ti-player-play"></i>فعال</button>
      <button class="btn btn-outline btn-sm" onclick="bulkAction('deactivate')"><i class="ti ti-player-pause"></i>غیرفعال</button>
      <button class="btn btn-outline btn-sm" onclick="bulkRenew()"><i class="ti ti-calendar-plus"></i>تمدید</button>
      <button class="btn btn-outline btn-sm" onclick="bulkAction('reset')"><i class="ti ti-refresh"></i>ریست مصرف</button>
      <button class="btn btn-danger btn-sm" onclick="bulkAction('delete')"><i class="ti ti-trash"></i>حذف</button>
    </div>
    <div class="card" style="margin-bottom:16px;overflow-x:auto">
      <table class="links-table">
        <thead>
          <tr>
            <th style="width:34px"><input type="checkbox" id="sel-all" onclick="toggleSelectAll(this)" title="انتخاب همه"></th>
            <th>نام</th><th>پروتکل</th><th>مصرف</th><th>وضعیت</th><th>انقضا</th><th>عملیات</th>
          </tr>
        </thead>
        <tbody id="links-tbody"><tr><td colspan="7" class="empty-state"><i class="ti ti-loader-2"></i>در حال بارگذاری...</td></tr></tbody>
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

    <!-- Reality SNI / dest -->
    <div class="card" style="margin-top:16px">
      <div class="card-title"><i class="ti ti-mask"></i>تنظیمات Reality (SNI / مقصد camouflage)</div>
      <div style="color:var(--text-2);font-size:12px;margin-bottom:12px;line-height:1.7">
        دامنه‌ای که اتصال Reality وانمود می‌کند به آن وصل شده. باید یک سایت واقعی با TLS 1.3 و HTTP/2 باشد
        (مثلاً <code>www.microsoft.com</code>). خالی‌گذاشتن = برگشت به مقدار پیش‌فرض env.
      </div>
      <div class="form-row">
        <div class="form-group" style="flex:1">
          <div class="form-label">مقصد (dest) — host:port</div>
          <input class="form-input" id="reality-dest-input" placeholder="www.microsoft.com:443" style="width:100%">
        </div>
        <div class="form-group" style="flex:1">
          <div class="form-label">SNI (اختیاری — خالی = از روی dest)</div>
          <input class="form-input" id="reality-sni-input" placeholder="www.microsoft.com" style="width:100%">
        </div>
      </div>
      <div id="reality-effective" style="color:var(--text-2);font-size:12px;margin:6px 0 12px"></div>
      <button class="btn btn-primary" onclick="saveReality()"><i class="ti ti-device-floppy"></i>ذخیره و اعمال</button>
      <span style="color:var(--text-2);font-size:11px;margin-right:10px">با ذخیره، Xray ری‌لود می‌شود و اتصال‌های فعلی لحظه‌ای قطع و دوباره وصل می‌شوند.</span>
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

  <!-- BACKUP -->
  <div class="page" id="page-backup">
    <div class="topbar">
      <div><div class="topbar-title"><i class="ti ti-database-export"></i>پشتیبان‌گیری و بازیابی</div>
      <div class="topbar-sub">دانلود یا بازگردانی کل کانفیگ (لینک‌ها، بلاک‌ها، کلیدهای Reality و تاریخچه)</div></div>
    </div>
    <div class="grid2">
      <div class="card">
        <div class="card-title"><i class="ti ti-download"></i>دانلود پشتیبان</div>
        <div style="font-size:12px;color:var(--text-2);margin-bottom:14px;line-height:1.7">یک فایل JSON شامل تمام لینک‌ها و تنظیمات دریافت می‌کنید. آن را جای امنی نگه دارید.</div>
        <button class="btn btn-primary" onclick="exportBackup()"><i class="ti ti-download"></i>دانلود فایل پشتیبان</button>
      </div>
      <div class="card">
        <div class="card-title"><i class="ti ti-upload"></i>بازگردانی پشتیبان</div>
        <div style="font-size:12px;color:var(--red-text);margin-bottom:14px;line-height:1.7">⚠️ هشدار: این کار تمام لینک‌های فعلی را با محتوای فایل جایگزین می‌کند.</div>
        <input type="file" id="import-file" accept="application/json,.json" style="display:none" onchange="importBackup(event)">
        <button class="btn btn-danger" onclick="document.getElementById('import-file').click()"><i class="ti ti-upload"></i>انتخاب و بازگردانی فایل</button>
      </div>
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
    <div class="form-row">
      <div class="form-group"><div class="form-label">ریست خودکار سهمیه (هر چند روز، ۰=خاموش)</div><input class="form-input" id="new-reset-days" type="number" value="0" min="0" style="width:130px"></div>
      <div class="form-group"><div class="form-label">حداکثر IP هم‌زمان (۰=نامحدود)</div><input class="form-input" id="new-max-ips" type="number" value="0" min="0" style="width:130px"></div>
    </div>
    <div class="form-row">
      <div class="form-group" style="flex:1"><div class="form-label">برچسب‌ها (با کاما جدا کنید)</div><input class="form-input" id="new-tags" placeholder="مثلاً: vip، ماهانه" style="width:100%"></div>
    </div>
    <div class="form-row">
      <div class="form-group" style="flex:1"><div class="form-label">یادداشت (اختیاری)</div><input class="form-input" id="new-note" placeholder="یادداشت داخلی..." style="width:100%"></div>
    </div>
    <div class="modal-footer">
      <button class="btn btn-outline" onclick="hideCreateModal()">لغو</button>
      <button class="btn btn-primary" id="create-link-btn" onclick="createLink()"><i class="ti ti-plus"></i>ایجاد لینک</button>
    </div>
  </div>
</div>

<!-- BULK CREATE MODAL -->
<div class="modal-overlay" id="bulk-modal">
  <div class="modal">
    <div class="modal-title"><i class="ti ti-layers-subtract"></i>ساخت گروهی لینک</div>
    <div class="form-row">
      <div class="form-group"><div class="form-label">تعداد (۱ تا ۱۰۰)</div><input class="form-input" id="bulk-count" type="number" value="5" min="1" max="100" style="width:110px"></div>
      <div class="form-group" style="flex:1"><div class="form-label">پیشوند نام</div><input class="form-input" id="bulk-prefix" placeholder="کاربر" style="width:100%"></div>
    </div>
    <div class="form-row">
      <div class="form-group" style="flex:1">
        <div class="form-label">پروتکل (می‌توانید چند مورد را انتخاب کنید)</div>
        <div id="bulk-proto-group" style="display:flex;flex-wrap:wrap;gap:8px">
          <label style="display:flex;align-items:center;gap:5px;font-size:12.5px;background:var(--card2);border:1px solid var(--border);border-radius:8px;padding:6px 10px;cursor:pointer"><input type="checkbox" class="bulk-proto-cb" value="vless" checked> VLESS+WS</label>
          <label style="display:flex;align-items:center;gap:5px;font-size:12.5px;background:var(--card2);border:1px solid var(--border);border-radius:8px;padding:6px 10px;cursor:pointer"><input type="checkbox" class="bulk-proto-cb" value="vless-xhttp"> XHTTP</label>
          <label style="display:flex;align-items:center;gap:5px;font-size:12.5px;background:var(--card2);border:1px solid var(--border);border-radius:8px;padding:6px 10px;cursor:pointer"><input type="checkbox" class="bulk-proto-cb" value="vless-reality"> Reality</label>
          <label style="display:flex;align-items:center;gap:5px;font-size:12.5px;background:var(--card2);border:1px solid var(--border);border-radius:8px;padding:6px 10px;cursor:pointer"><input type="checkbox" class="bulk-proto-cb" value="trojan"> Trojan</label>
        </div>
      </div>
    </div>
    <div class="form-row">
      <div class="form-group"><div class="form-label">حجم (۰=نامحدود)</div><input class="form-input" id="bulk-limit" type="number" value="0" min="0" style="width:90px"></div>
      <div class="form-group"><div class="form-label">واحد</div><select class="form-select" id="bulk-unit"><option>GB</option><option>MB</option></select></div>
      <div class="form-group"><div class="form-label">مدت (روز، ۰=نامحدود)</div><input class="form-input" id="bulk-expire" type="number" value="0" min="0" style="width:100px"></div>
    </div>
    <div class="form-row">
      <div class="form-group"><div class="form-label">ریست خودکار (هر چند روز)</div><input class="form-input" id="bulk-reset-days" type="number" value="0" min="0" style="width:130px"></div>
      <div class="form-group"><div class="form-label">حداکثر IP هم‌زمان</div><input class="form-input" id="bulk-max-ips" type="number" value="0" min="0" style="width:130px"></div>
    </div>
    <div class="form-row">
      <div class="form-group" style="flex:1"><div class="form-label">برچسب‌ها (با کاما)</div><input class="form-input" id="bulk-tags" placeholder="مثلاً: گروه فروردین" style="width:100%"></div>
    </div>
    <div class="modal-footer">
      <button class="btn btn-outline" onclick="hideBulkModal()">لغو</button>
      <button class="btn btn-primary" id="bulk-create-btn" onclick="bulkCreate()"><i class="ti ti-layers-subtract"></i>ساخت گروهی</button>
    </div>
  </div>
</div>

<!-- QR MODAL -->
<div class="modal-overlay" id="qr-modal">
  <div class="modal" style="max-width:340px;text-align:center">
    <div class="modal-title" style="justify-content:center"><i class="ti ti-qrcode"></i>اسکن کنید</div>
    <div id="qr-box" style="background:#fff;padding:16px;border-radius:12px;display:inline-flex;align-items:center;justify-content:center;min-height:236px"></div>
    <div class="modal-footer" style="justify-content:center"><button class="btn btn-outline" onclick="hideQR()">بستن</button></div>
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
  loadWeekChart();
  loadTopConsumers();
  loadOverviewClients();
}

// ── Traffic chart (۷ روز اخیر) ──
async function loadWeekChart(){
  const totalEl=document.getElementById('chart-week-total');
  const box=document.getElementById('chart-week');
  if(!box) return;
  try{
    const r=await fetch('/api/traffic/week');
    if(!r.ok) throw new Error();
    const d=await r.json();
    if(totalEl) totalEl.textContent=fmtBytes(d.total_bytes)+' در ۷ روز';
    const points=d.points||[];
    const maxVal=Math.max(1,...points.map(p=>p.bytes));
    const W=300,H=110,padB=22,padT=4,barGap=8;
    const slot=W/points.length, barW=slot-barGap;
    let bars='',labels='';
    points.forEach((p,i)=>{
      const h=p.bytes>0?Math.max(2,Math.round((p.bytes/maxVal)*(H-padT-padB))):0;
      const x=i*slot+barGap/2, y=H-padB-h;
      bars+=`<rect x="${x.toFixed(1)}" y="${y}" width="${barW.toFixed(1)}" height="${h}" rx="3" fill="url(#wkGrad)"><title>${p.date} — ${fmtBytes(p.bytes)}</title></rect>`;
      labels+=`<text x="${(x+barW/2).toFixed(1)}" y="${H-8}" font-size="7.5" fill="var(--text-3)" text-anchor="middle">${p.label}</text>`;
    });
    box.innerHTML=`<svg viewBox="0 0 ${W} ${H}" style="width:100%;height:130px;overflow:visible">
      <defs><linearGradient id="wkGrad" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stop-color="#4ce090"/><stop offset="100%" stop-color="#22a96b"/></linearGradient></defs>
      ${bars}${labels}</svg>`;
  }catch(e){ box.innerHTML='<div style="color:var(--text-2);font-size:12px;padding:20px 0;text-align:center">خطا در دریافت ترافیک هفتگی</div>'; }
}

// ── Top consumers (بیشترین مصرف per-link) ──
async function loadTopConsumers(){
  const box=document.getElementById('top-consumers');
  if(!box) return;
  try{
    const r=await fetch('/api/links');
    if(!r.ok) throw new Error();
    const d=await r.json();
    const links=(d.links||[]).filter(l=>l.used_bytes>0).sort((a,b)=>b.used_bytes-a.used_bytes).slice(0,5);
    if(!links.length){ box.innerHTML='<div style="color:var(--text-2);font-size:12px;padding:14px 0;text-align:center">هنوز مصرفی ثبت نشده</div>'; return; }
    const maxU=Math.max(...links.map(l=>l.used_bytes));
    box.innerHTML=links.map(l=>{
      const pct=Math.max(3,Math.round(l.used_bytes/maxU*100));
      return `<div style="margin:9px 0">
        <div style="display:flex;justify-content:space-between;font-size:12px;margin-bottom:4px">
          <span style="font-weight:600;max-width:150px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">${l.label}</span>
          <span style="color:var(--text-2)">${fmtBytes(l.used_bytes)}</span>
        </div>
        <div class="usage-bar" style="min-width:0"><div class="usage-bar-fill" style="width:${pct}%;background:linear-gradient(90deg,#6366f1,#3b82f6)"></div></div>
      </div>`;
    }).join('');
  }catch(e){ box.innerHTML='<div style="color:var(--text-2);font-size:12px;padding:14px 0;text-align:center">خطا در دریافت مصرف‌ها</div>'; }
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
    applyLinkFilter();
  }catch(e){console.error(e)}
}

const PROTO_LABELS={vless:'VLESS',trojan:'Trojan','vless-xhttp':'XHTTP','vless-reality':'Reality'};
const PROTO_COLORS={vless:'pill-blue',trojan:'pill-amber','vless-xhttp':'pill-blue','vless-reality':'pill-green'};

let selectedUids=new Set();

function escAttr(s){return String(s==null?'':s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;')}

// فیلتر + جستجو روی لیست محلی (بدون نیاز به رفت‌وبرگشت سرور)
function applyLinkFilter(){
  const q=(document.getElementById('link-search')?.value||'').trim().toLowerCase();
  const f=document.getElementById('link-filter')?.value||'all';
  let arr=allLinks.slice();
  if(f!=='all'){
    arr=arr.filter(l=>{
      if(f==='active')   return l.active&&!l.is_expired&&!l.quota_exceeded;
      if(f==='inactive') return !l.active&&!l.is_expired;
      if(f==='expired')  return l.is_expired;
      if(f==='quota')    return l.quota_exceeded;
      return true;
    });
  }
  if(q){
    arr=arr.filter(l=>{
      const hay=[l.label,l.uuid,(l.note||''),((l.tags||[]).join(' '))].join(' ').toLowerCase();
      return hay.includes(q);
    });
  }
  renderLinksTable(arr);
}

function renderLinksTable(links){
  const tbody=document.getElementById('links-tbody');
  if(!links.length){
    tbody.innerHTML='<tr><td colspan="7"><div class="empty-state"><i class="ti ti-users-minus"></i>لینکی مطابق فیلتر یافت نشد</div></td></tr>';
    updateBulkBar();
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
    const tagBadges=(l.tags||[]).map(t=>`<span class="proto-badge" style="background:rgba(99,102,241,.12);color:#a5b4fc">#${escAttr(t)}</span>`).join(' ');
    const noteHtml=l.note?`<div style="font-size:10.5px;color:var(--text-2);max-width:140px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis" title="${escAttr(l.note)}"><i class="ti ti-note"></i> ${escAttr(l.note)}</div>`:'';
    const checked=selectedUids.has(l.uuid)?'checked':'';
    return `<tr>
      <td><input type="checkbox" class="row-sel" ${checked} onclick="onRowSelect('${l.uuid}',this)"></td>
      <td style="font-weight:600;max-width:150px">
        <div style="white-space:nowrap;overflow:hidden;text-overflow:ellipsis">${escAttr(l.label)}</div>
        ${tagBadges?`<div style="display:flex;gap:3px;flex-wrap:wrap;margin-top:3px">${tagBadges}</div>`:''}
        ${noteHtml}
      </td>
      <td><div style="display:flex;gap:4px;flex-wrap:wrap">${protoBadges}</div></td>
      <td>
        <div class="usage-bar"><div class="usage-bar-fill" style="width:${usedPct}%;background:${barColor}"></div></div>
        <div class="usage-text">${usedStr} / ${limitStr}</div>
      </td>
      <td>${statusPill}</td>
      <td style="font-size:11px;color:var(--text-2)">${expStr}</td>
      <td>
        <div style="display:flex;gap:6px;flex-wrap:wrap">
          <button class="btn btn-outline btn-sm" onclick='showDetail(${JSON.stringify(l)})' title="جزئیات"><i class="ti ti-eye"></i></button>
          <button class="btn btn-outline btn-sm" onclick="copySub('${l.uuid}')" title="کپی لینک ساب"><i class="ti ti-link"></i></button>
          <button class="btn btn-outline btn-sm" onclick="cloneLink('${l.uuid}')" title="کلون"><i class="ti ti-copy"></i></button>
          <button class="btn btn-outline btn-sm" onclick="renewLink('${l.uuid}')" title="تمدید"><i class="ti ti-calendar-plus"></i></button>
          <button class="btn btn-outline btn-sm" onclick="toggleLink('${l.uuid}',${!l.active})" title="${l.active?'غیرفعال':'فعال'}">${l.active?'<i class="ti ti-player-pause"></i>':'<i class="ti ti-player-play"></i>'}</button>
          <button class="btn btn-danger btn-sm" onclick="deleteLink('${l.uuid}')" title="حذف"><i class="ti ti-trash"></i></button>
        </div>
      </td>
    </tr>`;
  }).join('');
  updateBulkBar();
}

// ── انتخاب گروهی ──
function onRowSelect(uid,cb){ if(cb.checked) selectedUids.add(uid); else selectedUids.delete(uid); updateBulkBar(); }
function toggleSelectAll(cb){
  document.querySelectorAll('#links-tbody .row-sel').forEach(el=>{
    el.checked=cb.checked;
    const uid=el.getAttribute('onclick').match(/'([^']+)'/)[1];
    if(cb.checked) selectedUids.add(uid); else selectedUids.delete(uid);
  });
  updateBulkBar();
}
function updateBulkBar(){
  const bar=document.getElementById('bulk-bar');
  const cnt=document.getElementById('bulk-count');
  // فقط uidهایی که هنوز در لیست هستن
  const valid=new Set(allLinks.map(l=>l.uuid));
  selectedUids=new Set([...selectedUids].filter(u=>valid.has(u)));
  if(selectedUids.size>0){ bar.style.display='flex'; if(cnt) cnt.textContent=`${selectedUids.size} لینک انتخاب شده`; }
  else { bar.style.display='none'; }
  const all=document.getElementById('sel-all'); if(all) all.checked=false;
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
  const reset_days=parseInt(document.getElementById('new-reset-days').value)||0;
  const max_ips=parseInt(document.getElementById('new-max-ips').value)||0;
  const tags=document.getElementById('new-tags').value.trim();
  const note=document.getElementById('new-note').value.trim();

  const btn=document.getElementById('create-link-btn');
  _creatingLink=true;
  if(btn){ btn.disabled=true; btn.dataset.orig=btn.innerHTML; btn.innerHTML='<i class="ti ti-loader-2"></i> در حال ایجاد...'; }
  try{
    const r=await fetch('/api/links',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({label,protocols,password,limit_value,limit_unit,expire_days,reset_days,max_ips,tags,note})});
    if(!r.ok) throw new Error((await r.json()).detail||'خطا');
    const d=await r.json();
    toast('لینک ایجاد شد ✅');
    hideCreateModal();
    document.getElementById('new-tags').value='';
    document.getElementById('new-note').value='';
    // به‌جای صرفاً صدا زدن loadLinks() (که نتیجه‌اش ممکنه با تاخیر برسه)، لینک تازه‌ساخته‌شده
    // را فوری به لیست محلی اضافه می‌کنیم تا بدون نیاز به رفرش صفحه نمایش داده شود.
    allLinks.unshift(d);
    applyLinkFilter();
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
  const resetTxt=(l.reset_days&&l.reset_days>0)?`هر ${l.reset_days} روز`:'خاموش';
  const maxTxt=(l.max_ips&&l.max_ips>0)?`${l.ips_count||0} / ${l.max_ips}`:`${l.ips_count||0} / ∞`;
  html+=`<div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;font-size:12px;margin:6px 0 12px;padding-top:12px;border-top:1px solid var(--border)">
    <div><div class="form-label">ریست خودکار سهمیه</div><div style="color:var(--text-1);margin-top:3px"><i class="ti ti-refresh" style="font-size:13px"></i> ${resetTxt}</div></div>
    <div><div class="form-label">IP فعال / حداکثر</div><div style="color:var(--text-1);margin-top:3px"><i class="ti ti-device-laptop" style="font-size:13px"></i> ${maxTxt}</div></div>
  </div>`;
  if((l.tags&&l.tags.length)||l.note){
    const tagB=(l.tags||[]).map(t=>`<span class="proto-badge" style="background:rgba(99,102,241,.12);color:#a5b4fc">#${escAttr(t)}</span>`).join(' ');
    html+=`<div style="margin:0 0 12px;font-size:12px">
      ${tagB?`<div style="margin-bottom:6px"><div class="form-label" style="margin-bottom:4px">برچسب‌ها</div><div style="display:flex;gap:4px;flex-wrap:wrap">${tagB}</div></div>`:''}
      ${l.note?`<div><div class="form-label" style="margin-bottom:4px">یادداشت</div><div style="color:var(--text-1)">${escAttr(l.note)}</div></div>`:''}
    </div>`;
  }
  html+=`<div style="margin-top:6px;display:flex;gap:8px">
    <button class="btn btn-outline btn-sm" style="flex:1;justify-content:center" onclick="copySub('${l.uuid}')"><i class="ti ti-link"></i>کپی ساب</button>
    <button class="btn btn-outline btn-sm" style="flex:1;justify-content:center" onclick="renewLink('${l.uuid}')"><i class="ti ti-calendar-plus"></i>تمدید</button>
  </div>`;
  html+=`<div style="margin-top:8px">
    <a href="/sub/${l.uuid}" target="_blank" class="btn btn-outline btn-sm" style="text-decoration:none;width:100%;justify-content:center"><i class="ti ti-external-link"></i>صفحه اشتراک (همه‌ی پروتکل‌ها)</a>
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
  showQR(t);
}
function showQR(text){
  const box=document.getElementById('qr-box');
  box.innerHTML='';
  try{
    // تولید محلی QR (بدون نیاز به سرویس خارجی)
    new QRCode(box,{text:text,width:204,height:204,correctLevel:QRCode.CorrectLevel.M});
  }catch(e){
    // fallback به سرویس آنلاین اگر کتابخانه لود نشده بود
    box.innerHTML='<img alt="QR" style="width:204px;height:204px" src="https://api.qrserver.com/v1/create-qr-code/?size=240x240&data='+encodeURIComponent(text)+'">';
  }
  document.getElementById('qr-modal').classList.add('show');
}
function hideQR(){document.getElementById('qr-modal').classList.remove('show')}

// ── کپی لینک ساب + تمدید سریع ──
function copySub(uid){
  const t=window.location.origin+'/sub/'+uid+'/raw';
  navigator.clipboard.writeText(t).then(()=>toast('لینک ساب کپی شد ✅'));
}
async function renewLink(uid){
  const days=prompt('لینک برای چند روز از همین حالا تمدید شود؟','30');
  if(days===null) return;
  const ed=parseFloat(days);
  if(isNaN(ed)||ed<=0){ toast('عدد معتبر وارد کنید',true); return; }
  try{
    const r=await fetch('/api/links/'+uid,{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify({expire_days:ed})});
    if(!r.ok) throw new Error('خطا');
    toast(`لینک ${ed} روز تمدید شد ✅`);
    loadLinks();
  }catch(e){toast(e.message,true)}
}

// ── کلون لینک ──
async function cloneLink(uid){
  try{
    const r=await fetch('/api/links/'+uid+'/clone',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({})});
    if(!r.ok) throw new Error((await r.json()).detail||'خطا');
    const d=await r.json();
    toast('کلون ساخته شد ✅');
    allLinks.unshift(d);
    applyLinkFilter();
    loadLinks();
  }catch(e){toast(e.message,true)}
}

// ── ساخت گروهی ──
function showBulkModal(){document.getElementById('bulk-modal').classList.add('show')}
function hideBulkModal(){document.getElementById('bulk-modal').classList.remove('show')}
let _bulkCreating=false;
async function bulkCreate(){
  if(_bulkCreating) return;
  const protocols=Array.from(document.querySelectorAll('.bulk-proto-cb:checked')).map(cb=>cb.value);
  if(!protocols.length){ toast('حداقل یک پروتکل را انتخاب کنید',true); return; }
  const count=parseInt(document.getElementById('bulk-count').value)||0;
  if(count<1||count>100){ toast('تعداد باید بین ۱ تا ۱۰۰ باشد',true); return; }
  const payload={
    count,
    label_prefix:document.getElementById('bulk-prefix').value.trim()||'کاربر',
    protocols,
    limit_value:parseFloat(document.getElementById('bulk-limit').value)||0,
    limit_unit:document.getElementById('bulk-unit').value,
    expire_days:parseFloat(document.getElementById('bulk-expire').value)||0,
    reset_days:parseInt(document.getElementById('bulk-reset-days').value)||0,
    max_ips:parseInt(document.getElementById('bulk-max-ips').value)||0,
    tags:document.getElementById('bulk-tags').value.trim(),
  };
  const btn=document.getElementById('bulk-create-btn');
  _bulkCreating=true;
  if(btn){ btn.disabled=true; btn.dataset.orig=btn.innerHTML; btn.innerHTML='<i class="ti ti-loader-2"></i> در حال ساخت...'; }
  try{
    const r=await fetch('/api/links/bulk',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});
    if(!r.ok) throw new Error((await r.json()).detail||'خطا');
    const d=await r.json();
    toast(`${d.created} لینک ساخته شد ✅`);
    hideBulkModal();
    loadLinks();
  }catch(e){toast(e.message,true)}
  finally{ _bulkCreating=false; if(btn){ btn.disabled=false; btn.innerHTML=btn.dataset.orig||'ساخت گروهی'; } }
}

// ── عملیات گروهی ──
async function bulkAction(action){
  const uuids=[...selectedUids];
  if(!uuids.length){ toast('هیچ لینکی انتخاب نشده',true); return; }
  const labels={delete:'حذف',activate:'فعال‌سازی',deactivate:'غیرفعال‌سازی',reset:'ریست مصرف'};
  if(action==='delete'&&!confirm(`${uuids.length} لینک حذف شوند؟ این عمل قابل بازگشت نیست.`)) return;
  if(action==='reset'&&!confirm(`مصرف ${uuids.length} لینک صفر شود؟`)) return;
  try{
    const r=await fetch('/api/links/bulk-action',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({uuids,action})});
    if(!r.ok) throw new Error((await r.json()).detail||'خطا');
    const d=await r.json();
    toast(`${labels[action]||action}: ${d.affected} لینک ✅`);
    selectedUids.clear();
    loadLinks();
  }catch(e){toast(e.message,true)}
}
async function bulkRenew(){
  const uuids=[...selectedUids];
  if(!uuids.length){ toast('هیچ لینکی انتخاب نشده',true); return; }
  const days=prompt(`${uuids.length} لینک برای چند روز تمدید شوند؟`,'30');
  if(days===null) return;
  const ed=parseFloat(days);
  if(isNaN(ed)||ed<=0){ toast('عدد معتبر وارد کنید',true); return; }
  try{
    const r=await fetch('/api/links/bulk-action',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({uuids,action:'renew',expire_days:ed})});
    if(!r.ok) throw new Error((await r.json()).detail||'خطا');
    const d=await r.json();
    toast(`${d.affected} لینک ${ed} روز تمدید شد ✅`);
    selectedUids.clear();
    loadLinks();
  }catch(e){toast(e.message,true)}
}

// ── Backup ──
function exportBackup(){
  const a=document.createElement('a');
  a.href='/api/export'; a.download='';
  document.body.appendChild(a); a.click(); a.remove();
  toast('در حال دانلود پشتیبان...');
}
async function importBackup(ev){
  const file=ev.target.files[0];
  if(!file) return;
  if(!confirm('بازگردانی این فایل تمام لینک‌های فعلی را جایگزین می‌کند. مطمئنید؟')){ ev.target.value=''; return; }
  try{
    const text=await file.text();
    const data=JSON.parse(text);
    const r=await fetch('/api/import',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(data)});
    if(!r.ok) throw new Error((await r.json()).detail||'خطا');
    const d=await r.json();
    toast(`بازگردانی شد ✅ (${d.links} لینک)`);
    loadStats();
  }catch(e){ toast('خطا در بازگردانی: '+e.message,true); }
  finally{ ev.target.value=''; }
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
    loadReality();
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

// ── Reality (SNI / dest) ──
async function loadReality(){
  try{
    const r=await fetch('/api/reality');
    if(!r.ok) return;
    const d=await r.json();
    const di=document.getElementById('reality-dest-input');
    const si=document.getElementById('reality-sni-input');
    if(di && document.activeElement!==di) di.value=d.dest||'';
    if(si && document.activeElement!==si) si.value=d.sni||'';
    const eff=document.getElementById('reality-effective');
    if(eff){
      eff.innerHTML=`در حال استفاده: <b>dest=</b>${d.effective_dest||'-'} · <b>SNI=</b>${d.effective_sni||'-'}`
        + (d.has_keys?'':' · <span style="color:#f87171">کلید Reality ساخته نشده</span>');
    }
  }catch(e){console.error(e)}
}
async function saveReality(){
  const dest=document.getElementById('reality-dest-input').value.trim();
  const sni=document.getElementById('reality-sni-input').value.trim();
  try{
    const r=await fetch('/api/reality',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({dest,sni})});
    const d=await r.json();
    if(!r.ok) throw new Error(d.detail||'خطا در ذخیره');
    toast('تنظیمات Reality ذخیره و اعمال شد ✅');
    loadReality();
    setTimeout(loadXrayStatus,1500);
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
