#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
جمع‌آوری کانفیگ‌های v2ray از چنل‌های عمومی تلگرام بدون نیاز به لاگین یا API.

روش کار: استفاده از نسخه‌ی وب عمومی تلگرام (https://t.me/s/<channel>) که
HTML پیام‌ها را بدون احراز هویت برمی‌گرداند.

مدل اجرا «بدون حالت» (stateless) است: هر بار اجرا کاملاً از نو شروع می‌شود،
خروجی قبلی نادیده گرفته/جایگزین می‌شود و از هر چنل تا سقف PER_CHANNEL
کانفیگِ *اخیر* (جدیدترین‌ها اول) برداشته می‌شود. تشخیص تکراری فقط در
محدوده‌ی همین اجرا انجام می‌شود (هم درون یک چنل و هم بین چنل‌ها) تا یک
کانفیگ دوبار در خروجی نیاید؛ هیچ هشی بین اجراها ذخیره نمی‌شود.

قابلیت‌های افزوده:
  • تشخیص کشورِ هر کانفیگ (با ip-api.com، بدون کلید) و افزودن پرچم + کد کشور،
    آیدی کانال مبدأ، و شماره‌ی per-channel به نامِ (remark) هر کانفیگ.
  • دسته‌بندی خروجی بر اساس نوع پروتکل (vmess/vless/trojan/...) + reality + all،
    هرکدام در دو قالب متن خام و base64 (لینک اشتراک).
  • تولید خودکار صفحه‌ی اصلی ریپو (README.md) با جدول لینک‌های اشتراک،
    نمودار پروتکل‌ها، و آمار کشورها/کانال‌ها که هر اجرا به‌روز می‌شود.
"""

import argparse
import base64
import binascii
import gzip
import hashlib
import html
import io
import json
import os
import re
import socket
import sys
import time
import urllib.parse
import urllib.request
import zlib
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

# اطمینان از خروجی UTF-8 روی هر سیستم‌عاملی (مثلاً کنسول ویندوز با cp1252)
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8")
    except Exception:  # noqa: BLE001
        pass


def _env_int(name, default):
    """خواندن یک عدد صحیح از env با fallback امن.

    اگر متغیر تعریف نشده، خالی، یا نامعتبر باشد مقدار پیش‌فرض برگردانده می‌شود
    تا اجرای زمان‌بندی‌شده (که ورودی دستی ندارد) هرگز با ValueError نیفتد.
    """
    raw = os.environ.get(name, "")
    try:
        value = int(str(raw).strip())
        return value if value > 0 else default
    except (TypeError, ValueError):
        return default


# ----------------------------- تنظیمات ------------------------------------
# این‌ها مقادیر پیش‌فرض‌اند؛ آرگومان‌های خط فرمان (در main) می‌توانند بازنویسی‌شان کنند.
PER_CHANNEL = _env_int("PER_CHANNEL", 20)        # تعداد کانفیگ از هر چنل
MAX_PAGES = _env_int("MAX_PAGES", 15)            # سقف صفحات برای هر چنل
REQUEST_TIMEOUT = _env_int("REQUEST_TIMEOUT", 30)
RETRIES = _env_int("RETRIES", 3)
# تعداد چنل‌هایی که هم‌زمان واکشی می‌شوند. مقدار بزرگ‌تر سریع‌تر است ولی ریسک
# throttle شدن توسط t.me را بالا می‌برد؛ ۱۰ تعادلِ امن است.
WORKERS = _env_int("WORKERS", 10)

ROOT = os.path.dirname(os.path.abspath(__file__))
CHANNELS_FILE = os.path.join(ROOT, "channels.txt")
DATA_DIR = os.path.join(ROOT, "data")
SUB_DIR = os.path.join(ROOT, "sub")
README_FILE = os.path.join(ROOT, "README.md")
RAW_FILE = os.path.join(DATA_DIR, "all_configs.txt")   # اسنپ‌شات کانفیگ‌های همین اجرا
# فایل‌های قدیمی (برای سازگاری با ساب‌های قبلی حفظ می‌شوند؛ معادل دسته‌ی «all»)
SUB_PLAIN = os.path.join(SUB_DIR, "configs.txt")
SUB_B64 = os.path.join(SUB_DIR, "sub.txt")

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"
)

# پروتکل‌هایی که پشتیبانی می‌شوند (همه‌ی فرمت‌های رایج کلاینت v2ray/xray)
PROTOCOLS = (
    "vmess", "vless", "trojan", "ss", "ssr",
    "hysteria", "hysteria2", "hy2", "tuic", "juicity",
    "wireguard", "warp", "socks", "http",
)

# الگوی استخراج لینک کانفیگ از داخل متن (با هر اسکیمی از لیست بالا)
_SCHEME_GROUP = "|".join(re.escape(p) for p in PROTOCOLS)
CONFIG_RE = re.compile(r"\b(?:" + _SCHEME_GROUP + r")://[^\s<>\"'`]+", re.IGNORECASE)

# الگوی استخراج بلوک‌های base64 که ممکن است چندین کانفیگ در خود داشته باشند
B64_BLOCK_RE = re.compile(r"[A-Za-z0-9+/=_\-]{40,}")

# الگوی تشخیص host:port برای فیلتر کردن لینک‌های غیرکانفیگ (مثل http://example.com)
PORT_RE = re.compile(r":\d{2,5}\b")

# ----------------------------- دسته‌بندی ----------------------------------
# هر دسته: key -> (نام نمایشی، ایموجی). ترتیب همین‌جا ترتیب نمایش در README است.
CATEGORY_META = OrderedDict([
    ("all",         ("همه", "🌐")),
    ("vmess",       ("VMess", "🟢")),
    ("vless",       ("VLESS", "⚡")),
    ("reality",     ("Reality", "🛡️")),
    ("trojan",      ("Trojan", "🐴")),
    ("shadowsocks", ("Shadowsocks", "🔒")),
    ("hysteria",    ("Hysteria", "🚀")),
    ("tuic",        ("TUIC", "🧊")),
    ("wireguard",   ("WireGuard", "🪱")),
    ("others",      ("سایر", "📦")),
])

# نگاشت اسکیمِ هر کانفیگ به دسته‌ی اصلی‌اش.
PROTOCOL_CATEGORY = {
    "vmess": "vmess",
    "vless": "vless",
    "trojan": "trojan",
    "ss": "shadowsocks",
    "ssr": "shadowsocks",
    "hysteria": "hysteria",
    "hysteria2": "hysteria",
    "hy2": "hysteria",
    "tuic": "tuic",
    "juicity": "tuic",
    "wireguard": "wireguard",
    "warp": "wireguard",
    "socks": "others",
    "http": "others",
}

# پروتکل‌هایی که در نمودار توزیع نشان داده می‌شوند (reality و all کنار گذاشته می‌شوند چون هم‌پوشانی دارند)
CHART_CATEGORIES = (
    "vmess", "vless", "trojan", "shadowsocks", "hysteria", "tuic", "wireguard", "others",
)

# آدرس پایه‌ی raw برای ساخت لینک اشتراک در README (روی Actions از env پر می‌شود).
_REPO = os.environ.get("GITHUB_REPOSITORY", "").strip()
_BRANCH = (os.environ.get("GITHUB_REF_NAME", "") or "main").strip()
RAW_BASE = f"https://raw.githubusercontent.com/{_REPO}/{_BRANCH}/" if _REPO else ""

# امکان خاموش‌کردن تشخیص کشور (مثلاً برای تستِ آفلاین): GEOIP_ENABLED=0
GEOIP_ENABLED = os.environ.get("GEOIP_ENABLED", "1").strip().lower() not in ("0", "false", "no")


# ----------------------------- ابزار شبکه ---------------------------------
def _decode_response(resp):
    """خواندن بدنه‌ی پاسخ با درنظرگرفتن Content-Encoding (gzip/deflate).

    تلگرام در صورت ارسال هدر Accept-Encoding، HTML را فشرده برمی‌گرداند که
    حجم انتقال را به‌شکل محسوسی کم می‌کند. اگر هدر فشرده‌سازی نبود یا ناشناخته
    بود، داده خام برگردانده می‌شود.
    """
    data = resp.read()
    encoding = (resp.headers.get("Content-Encoding") or "").lower().strip()
    try:
        if encoding == "gzip":
            data = gzip.GzipFile(fileobj=io.BytesIO(data)).read()
        elif encoding == "deflate":
            try:
                data = zlib.decompress(data)
            except zlib.error:
                data = zlib.decompress(data, -zlib.MAX_WBITS)  # deflate خام (بدون هدر zlib)
    except (OSError, zlib.error):
        pass  # اگر دیکُد فشرده‌سازی شکست خورد، با داده‌ی خام ادامه می‌دهیم
    return data.decode("utf-8", errors="replace")


def fetch(url):
    """دریافت محتوای یک URL با چند بار تلاش مجدد (با backoff فزاینده).

    پس از آخرین تلاشِ ناموفق دیگر مکث نمی‌کند (sleepِ بی‌فایده حذف شده) و در
    صورت پشتیبانی سرور، پاسخ را به‌صورت gzip فشرده دریافت می‌کند.
    """
    last_err = None
    for attempt in range(1, RETRIES + 1):
        try:
            req = urllib.request.Request(
                url,
                headers={
                    "User-Agent": USER_AGENT,
                    "Accept-Encoding": "gzip, deflate",
                },
            )
            with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
                return _decode_response(resp)
        except Exception as e:  # noqa: BLE001
            last_err = e
            if attempt < RETRIES:
                time.sleep(2 * attempt)  # فقط بین تلاش‌ها مکث می‌کنیم، نه بعد از آخرین
    print(f"    ! خطا در دریافت {url}: {last_err}", file=sys.stderr)
    return None


# ----------------------------- پارس چنل‌ها --------------------------------
def normalize_channel(line):
    """تبدیل هر فرمت ورودی به نام کاربری خالص چنل."""
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    line = line.split()[0]
    line = line.replace("https://", "").replace("http://", "")
    line = line.replace("t.me/s/", "").replace("t.me/", "")
    line = line.lstrip("@/")
    line = line.split("/")[0].split("?")[0]
    return line or None


def load_channels():
    if not os.path.exists(CHANNELS_FILE):
        print(f"فایل {CHANNELS_FILE} پیدا نشد.", file=sys.stderr)
        return []
    seen = OrderedDict()
    with open(CHANNELS_FILE, "r", encoding="utf-8") as f:
        for line in f:
            ch = normalize_channel(line)
            if ch:
                seen[ch.lower()] = ch
    return list(seen.values())


# ----------------------------- استخراج کانفیگ -----------------------------
def html_to_text(raw_html):
    """تبدیل HTML پیام تلگرام به متن خام قابل پردازش.

    تگ‌های <br> و انتهای بلوک‌ها به newline تبدیل می‌شوند تا کانفیگ‌هایی که
    در خطوط جدا داخل code/pre هستند از هم جدا بمانند، سپس همه‌ی تگ‌ها حذف و
    موجودیت‌های HTML (مثل &amp; &lt;) به کاراکتر اصلی برگردانده می‌شوند.
    """
    text = raw_html
    text = re.sub(r"(?i)<br\s*/?>", "\n", text)
    text = re.sub(r"(?i)</(div|p|pre|code|blockquote|li)>", "\n", text)
    text = re.sub(r"(?s)<[^>]+>", " ", text)
    text = html.unescape(text)
    return text


def split_message_blocks(page_html):
    """جداکردن HTML صفحه به بلوک هر پیام (برای آینده/دیباگ نگه داشته شده)."""
    return re.split(r'class="tgme_widget_message_text', page_html)


def is_valid_config(cfg):
    """فیلترِ سبک برای رد کردن لینک‌هایی که کانفیگ پروکسی نیستند.

    لینک‌هایی مثل http://example.com یا https://t.me/... که اسکیمشان با
    پروتکل‌های مجاز هم‌پوشانی دارد ولی پروکسی نیستند را حذف می‌کند:
      - اگر host:port (مثل :443) داشته باشد، معتبر است.
      - فرم‌های کاملاً base64 (vmess/ss/ssr) که پورت در ظاهرشان نیست، اگر
        قابل دیکُد باشند معتبرند.
    """
    scheme, sep, rest = cfg.partition("://")
    if not sep or not rest:
        return False
    if PORT_RE.search(rest):
        return True
    if scheme.lower() in ("vmess", "ss", "ssr"):
        return try_b64_decode(rest.split("#", 1)[0]) is not None
    return False


def try_b64_decode(s):
    """تلاش برای دیکُد base64 (استاندارد و urlsafe، با/بدون padding)."""
    s = s.strip()
    if len(s) < 16:
        return None
    candidate = s.replace("-", "+").replace("_", "/")
    candidate += "=" * (-len(candidate) % 4)
    for variant in (candidate, s + "=" * (-len(s) % 4)):
        try:
            decoded = base64.b64decode(variant, validate=False)
            txt = decoded.decode("utf-8", errors="strict")
            return txt
        except (binascii.Error, UnicodeDecodeError, ValueError):
            continue
    return None


def extract_configs_from_text(text):
    """استخراج تمام کانفیگ‌ها از یک متن.

    سه منبع را پوشش می‌دهد:
      1) لینک‌های مستقیم با اسکیم شناخته‌شده.
      2) بلوک‌های base64 که خودشان شامل یک ساب‌اسکریپشن (چند کانفیگ) هستند.
      3) لینک‌های موجود داخل بلوک‌های base64 دیکُدشده.
    """
    found = []

    # ۱) لینک‌های مستقیم
    for m in CONFIG_RE.finditer(text):
        cfg = m.group(0).strip().rstrip('.,،;)]}>"\'')
        if is_valid_config(cfg):
            found.append(cfg)

    # ۲و۳) بلوک‌های base64
    for block in B64_BLOCK_RE.findall(text):
        decoded = try_b64_decode(block)
        if not decoded:
            continue
        # اگر خودِ بلوک یک کانفیگ vmess باشد (vmess://<base64>) قبلاً در مرحله ۱ گرفته شده.
        for m in CONFIG_RE.finditer(decoded):
            cfg = m.group(0).strip().rstrip('.,،;)]}>"\'')
            if is_valid_config(cfg):
                found.append(cfg)

    return found


# ----------------------------- نرمال‌سازی و هش ----------------------------
def canonical_config(cfg):
    """تولید شکل یکتا (canonical) از یک کانفیگ برای تشخیص تکراری.

    نام/remark (بخش بعد از #) و ترتیب پارامترهای کوئری در تشخیص تکراری بی‌اثر
    می‌شوند تا دو کانفیگِ یکسان با اسم متفاوت، تکراری حساب شوند.
    برای vmess که بدنه‌اش JSON داخل base64 است، فیلد ps (نام) حذف می‌شود.
    """
    cfg = cfg.strip()
    scheme = cfg.split("://", 1)[0].lower()

    if scheme == "vmess":
        body = cfg[len("vmess://"):]
        decoded = try_b64_decode(body)
        if decoded:
            try:
                obj = json.loads(decoded)
                obj.pop("ps", None)  # حذف نام
                canon = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
                return "vmess://" + canon
            except (json.JSONDecodeError, AttributeError):
                pass
        return cfg.split("#", 1)[0]

    # سایر پروتکل‌ها: حذف remark و مرتب‌سازی query
    base = cfg.split("#", 1)[0]
    if "?" in base:
        head, query = base.split("?", 1)
        params = urllib.parse.parse_qsl(query, keep_blank_values=True)
        params.sort()
        query = urllib.parse.urlencode(params)
        base = head + "?" + query
    return base.lower() if scheme in ("ss", "ssr") else base


def config_hash(cfg):
    canon = canonical_config(cfg)
    return hashlib.sha256(canon.encode("utf-8")).hexdigest()


# ----------------------------- استخراج host/port --------------------------
def _split_hostport(hp):
    """جداکردن host و port از رشته‌ی host:port (با پشتیبانی IPv6 داخل [])."""
    hp = hp.strip().strip("/")
    if not hp:
        return None, None
    if hp.startswith("["):  # IPv6 مثل [2001:db8::1]:443
        end = hp.find("]")
        if end != -1:
            host = hp[1:end]
            port = hp[end + 2:] if hp[end + 1:end + 2] == ":" else None
            return host or None, (port or None)
    if ":" in hp:
        host, port = hp.rsplit(":", 1)
        return (host or None), (port or None)
    return hp, None


def extract_host_port(cfg):
    """استخراج (host, port) از یک کانفیگ، مستقل از پروتکل.

    برای vmess بدنه‌ی JSON دیکُد و فیلدهای add/port خوانده می‌شوند؛ برای ss/ssr
    شکل‌های base64 پشتیبانی می‌شوند؛ برای بقیه از فرم proto://...@host:port استفاده می‌شود.
    در صورت خطا (None, None) برمی‌گرداند تا اجرا متوقف نشود.
    """
    scheme, _, rest = cfg.partition("://")
    scheme = scheme.lower()
    if not rest:
        return None, None
    try:
        if scheme == "vmess":
            decoded = try_b64_decode(rest.split("#", 1)[0])
            if decoded:
                obj = json.loads(decoded)
                host = str(obj.get("add", "")).strip()
                port = str(obj.get("port", "")).strip()
                return (host or None), (port or None)
            return None, None

        body = rest.split("#", 1)[0]

        if scheme == "ssr":
            decoded = try_b64_decode(body)
            if decoded:
                # ssr://base64(host:port:proto:method:obfs:passbase64/?params)
                host = decoded.split(":", 1)[0]
                return (host or None), None
            return None, None

        if scheme == "ss":
            b = body.split("?", 1)[0]
            if "@" in b:
                return _split_hostport(b.rsplit("@", 1)[1])
            decoded = try_b64_decode(b)
            if decoded and "@" in decoded:
                return _split_hostport(decoded.rsplit("@", 1)[1])
            return None, None

        # vless/trojan/hysteria*/tuic/juicity/socks/http/wireguard
        b = body.split("?", 1)[0]
        if "@" in b:
            b = b.rsplit("@", 1)[1]
        return _split_hostport(b)
    except Exception:  # noqa: BLE001
        return None, None


# ----------------------------- تشخیص کشور (GeoIP) -------------------------
def is_ip(host):
    """آیا رشته یک آدرس IP (v4 یا v6) است؟"""
    for fam in (socket.AF_INET, socket.AF_INET6):
        try:
            socket.inet_pton(fam, host)
            return True
        except OSError:
            continue
    return False


def _resolve_one(host):
    try:
        return socket.gethostbyname(host)
    except Exception:  # noqa: BLE001
        return None


def country_flag(cc):
    """تبدیل کد دو حرفی کشور (ISO-3166) به ایموجی پرچم."""
    if not cc or len(cc) != 2 or not cc.isalpha():
        return ""
    cc = cc.upper()
    return chr(0x1F1E6 + ord(cc[0]) - 65) + chr(0x1F1E6 + ord(cc[1]) - 65)


def geo_lookup(ips):
    """نگاشت IP → کد کشور با استفاده از endpoint دسته‌ای ip-api.com (بدون کلید).

    تا ۱۰۰ IP در هر درخواست؛ بین درخواست‌ها مکث کوتاه برای رعایت محدودیت نرخ.
    """
    out = {}
    for i in range(0, len(ips), 100):
        chunk = ips[i:i + 100]
        try:
            payload = json.dumps([{"query": ip} for ip in chunk]).encode("utf-8")
            req = urllib.request.Request(
                "http://ip-api.com/batch?fields=status,countryCode,query",
                data=payload,
                headers={"User-Agent": USER_AGENT, "Content-Type": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
                arr = json.loads(resp.read().decode("utf-8", errors="replace"))
            for item in arr:
                if isinstance(item, dict) and item.get("status") == "success":
                    cc = item.get("countryCode") or ""
                    out[item.get("query")] = cc
        except Exception as e:  # noqa: BLE001
            print(f"    ! خطا در GeoIP دسته‌ای: {e}", file=sys.stderr)
        if i + 100 < len(ips):
            time.sleep(1.5)
    return out


def annotate_countries(records):
    """افزودن کلید 'cc' (کد کشور) به هر رکورد.

    مراحل: استخراج host هر کانفیگ → resolve دامنه‌ها به IP (موازی) →
    lookup دسته‌ایِ کشور. در صورت هر خطایی، بی‌صدا با cc خالی ادامه می‌دهد تا
    جمع‌آوری هرگز به‌خاطر شبکه‌ی GeoIP خراب نشود.
    """
    for r in records:
        r["host"], _ = extract_host_port(r["cfg"])
        r["cc"] = ""

    if not GEOIP_ENABLED:
        return

    hosts = {r["host"] for r in records if r.get("host")}
    if not hosts:
        return

    try:
        ip_by_host = {}
        to_resolve = []
        for h in hosts:
            if is_ip(h):
                ip_by_host[h] = h
            else:
                to_resolve.append(h)

        if to_resolve:
            old_to = socket.getdefaulttimeout()
            socket.setdefaulttimeout(5)
            try:
                with ThreadPoolExecutor(max_workers=20) as ex:
                    for h, ip in zip(to_resolve, ex.map(_resolve_one, to_resolve)):
                        if ip:
                            ip_by_host[h] = ip
            finally:
                socket.setdefaulttimeout(old_to)

        ips = sorted({ip for ip in ip_by_host.values()})
        if not ips:
            return
        cc_by_ip = geo_lookup(ips)

        for r in records:
            ip = ip_by_host.get(r.get("host"))
            if ip:
                r["cc"] = cc_by_ip.get(ip, "")
    except Exception as e:  # noqa: BLE001
        print(f"    ! تشخیص کشور انجام نشد: {e}", file=sys.stderr)


# ----------------------------- بازنویسی نام (remark) ----------------------
def set_remark(cfg, remark):
    """جایگزینی نام/remark یک کانفیگ با رشته‌ی دلخواه.

    برای vmess فیلد ps در JSON تنظیم و دوباره base64 می‌شود؛ برای بقیه، بخش بعد
    از # با نسخه‌ی percent-encode شده‌ی remark جایگزین می‌شود (کلاینت‌ها decode می‌کنند).
    """
    scheme = cfg.split("://", 1)[0].lower()
    if scheme == "vmess":
        body = cfg[len("vmess://"):].split("#", 1)[0]
        decoded = try_b64_decode(body)
        if decoded:
            try:
                obj = json.loads(decoded)
                obj["ps"] = remark
                raw = json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
                return "vmess://" + base64.b64encode(raw).decode("ascii")
            except (json.JSONDecodeError, AttributeError, TypeError):
                return cfg
        return cfg
    base = cfg.split("#", 1)[0]
    return base + "#" + urllib.parse.quote(remark, safe="")


def is_reality(cfg):
    """آیا این کانفیگ vless از نوع reality است؟ (روی بخش پیش از # بررسی می‌شود)"""
    base = cfg.split("#", 1)[0].lower()
    return "security=reality" in base or "type=reality" in base


# ----------------------------- جمع‌آوری از یک چنل -------------------------
def collect_from_channel(channel, per_channel, max_pages):
    """تا per_channel کانفیگِ *اخیرِ* غیرتکراری از یک چنل برمی‌گرداند.

    در صفحه‌ی web تلگرام پیام‌ها از قدیمی (بالا) به جدید (پایین) مرتب‌اند، پس
    برای رسیدن به «جدیدترین‌ها» کانفیگ‌های هر صفحه معکوس می‌شوند (جدید اول).
    اگر صفحه‌ی نخست به per_channel نرسد، با پارامتر before صفحات قدیمی‌تر هم
    خوانده می‌شوند.

    تشخیص تکراری در اینجا فقط *درون همین چنل* انجام می‌شود (با مجموعه‌ی محلی)؛
    تابع هیچ حالتِ مشترکی با چنل‌های دیگر ندارد تا بتوان آن را به‌صورت موازی و
    کاملاً مستقل اجرا کرد. dedup بین‌کانالی بعداً و به‌صورت قطعی روی نتیجه‌ی همه
    اعمال می‌شود (نگاه کنید به collect_all).
    """
    collected = []          # جدیدترین‌ها اول
    local_seen = set()      # فقط برای جلوگیری از تکرار درون همین چنل
    before = None
    pages = 0

    while len(collected) < per_channel and pages < max_pages:
        url = f"https://t.me/s/{channel}"
        if before:
            url += f"?before={before}"
        page = fetch(url)
        pages += 1
        if not page:
            break

        # کوچک‌ترین شناسه‌ی پیام در این صفحه را برای صفحه‌ی بعدی نگه می‌داریم
        msg_ids = re.findall(r'data-post="[^"]+/(\d+)"', page)
        text = html_to_text(page)
        # configs به ترتیب قدیمی→جدید است؛ معکوس می‌کنیم تا جدیدترین‌ها اول بیایند
        configs = list(reversed(extract_configs_from_text(text)))

        for cfg in configs:
            if len(collected) >= per_channel:
                break
            h = config_hash(cfg)
            if h in local_seen:
                continue
            local_seen.add(h)
            collected.append(cfg)

        if len(collected) >= per_channel:
            break

        if msg_ids:
            new_before = min(int(x) for x in msg_ids)
            if before is not None and new_before >= before:
                break  # دیگر به عقب نمی‌رویم
            before = new_before
        else:
            break  # صفحه‌ای برای ادامه نیست

    return collected


def collect_all(channels, per_channel, max_pages, workers, progress_cb=None):
    """واکشی موازیِ همه‌ی چنل‌ها و سپس dedup قطعیِ بین‌کانالی.

    هر چنل در یک ترد مستقل واکشی می‌شود (تا سقف workers هم‌زمان). نتایج به‌محض
    آماده‌شدن برای نمایش پیشرفت گزارش می‌شوند، اما dedup نهایی و ترتیب خروجی
    *مستقل از ترتیب اتمام تردها* است: کانال‌ها دقیقاً به ترتیبِ channels.txt
    پردازش می‌شوند تا خروجی قطعی (deterministic) بماند و diffهای git نویزی نشوند.

    خروجی: لیست [(channel, [configs...]), ...] به همان ترتیب ورودی، که در آن یک
    کانفیگِ مشترک فقط به اولین کانالی (به ترتیب فایل) که آن را داشته نسبت می‌یابد.
    """
    # ۱) واکشی موازی؛ نتیجه‌ی هر چنل را در دیکشنری بر اساس نام نگه می‌داریم.
    #    از as_completed استفاده می‌کنیم تا نوار پیشرفت به‌محض اتمامِ *هر* چنل
    #    پیش برود (نه به ترتیب ورودی)؛ ترتیب نهاییِ خروجی در مرحله‌ی ۲ مستقل از
    #    این بازسازی می‌شود، پس قطعی‌بودن حفظ می‌شود.
    raw_by_channel = {}
    done = 0

    def _work(ch):
        try:
            return collect_from_channel(ch, per_channel, max_pages)
        except Exception as e:  # noqa: BLE001
            print(f"\n  [{ch}] خطا: {e}", file=sys.stderr, flush=True)
            return []

    # max_workers هرگز از تعداد چنل‌ها بیشتر نمی‌شود (جلوگیری از تردِ بی‌کار)
    n_workers = max(1, min(workers, len(channels)))
    with ThreadPoolExecutor(max_workers=n_workers) as ex:
        future_to_ch = {ex.submit(_work, ch): ch for ch in channels}
        for fut in as_completed(future_to_ch):
            ch = future_to_ch[fut]
            got = fut.result()
            raw_by_channel[ch] = got
            done += 1
            if progress_cb is not None:
                progress_cb(done, ch, len(got))

    # ۲) dedup بین‌کانالی به ترتیب قطعیِ ورودی (CPU-only، سریع)
    run_seen = set()
    result = []
    for ch in channels:
        deduped = []
        for cfg in raw_by_channel.get(ch, []):
            h = config_hash(cfg)
            if h in run_seen:
                continue
            run_seen.add(h)
            deduped.append(cfg)
        result.append((ch, deduped))
    return result


# ----------------------------- خروجی سابسکریپشن --------------------------
def _write_pair(key, configs):
    """نوشتن یک دسته در دو قالب: متن خام (key.txt) و base64 (key_b64.txt)."""
    plain = "\n".join(configs) + ("\n" if configs else "")
    with open(os.path.join(SUB_DIR, f"{key}.txt"), "w", encoding="utf-8") as f:
        f.write(plain)
    b64 = base64.b64encode(plain.encode("utf-8")).decode("ascii")
    with open(os.path.join(SUB_DIR, f"{key}_b64.txt"), "w", encoding="utf-8") as f:
        f.write(b64)


def write_outputs(categories):
    """نوشتن همه‌ی دسته‌ها + فایل‌های قدیمی (برای سازگاری)."""
    os.makedirs(SUB_DIR, exist_ok=True)
    os.makedirs(DATA_DIR, exist_ok=True)

    for key, configs in categories.items():
        if key != "all" and not configs:
            continue  # دسته‌ی خالی فایل نمی‌سازد (به‌جز all)
        _write_pair(key, configs)

    # فایل‌های قدیمی = معادل دسته‌ی all (حفظ سازگاری با ساب‌های موجود کاربران)
    all_plain = "\n".join(categories["all"]) + ("\n" if categories["all"] else "")
    with open(SUB_PLAIN, "w", encoding="utf-8") as f:
        f.write(all_plain)
    with open(RAW_FILE, "w", encoding="utf-8") as f:
        f.write(all_plain)
    with open(SUB_B64, "w", encoding="utf-8") as f:
        f.write(base64.b64encode(all_plain.encode("utf-8")).decode("ascii"))


# ----------------------------- تولید README ------------------------------
def _sub_link(path):
    """لینک raw برای یک فایل اشتراک؛ اگر env ریپو نباشد، مسیر نسبی برمی‌گرداند."""
    return (RAW_BASE + path) if RAW_BASE else path


def _qr_url(data, size=240):
    """آدرس تصویر QR برای یک رشته (سرویس عمومی qrserver.com، بدون کلید/لاگین).

    داده‌ی کد، خودِ آدرسِ کوتاهِ اشتراک است (نه محتوای فایل) تا با ظرفیت QR بخواند.
    """
    encoded = urllib.parse.quote(data, safe="")
    return (
        "https://api.qrserver.com/v1/create-qr-code/"
        f"?size={size}x{size}&margin=10&qzone=1&data={encoded}"
    )


def generate_readme(total, channels_n, cat_counts, country_counts, channel_counts, updated):
    """ساخت محتوای README.md به‌صورت کاملاً داینامیک بر پایه‌ی نتایجِ همین اجرا."""
    out = []
    A = out.append

    all_b64 = _sub_link("sub/all_b64.txt")
    all_plain = _sub_link("sub/all.txt")
    proto_n = sum(1 for k, v in cat_counts.items() if v and k not in ("all", "reality"))

    # ----------------------------- سربرگ -----------------------------------
    A('<div align="center">')
    A("")
    A("# 🛰️ V2Ray Config Collector")
    A("")
    A("**جمع‌آوری خودکار کانفیگ‌های V2Ray از کانال‌های عمومی تلگرام**")
    A("")
    A("<sub>بدون نیاز به لاگین یا API • به‌روزرسانی خودکار هر ۵ ساعت با GitHub Actions</sub>")
    A("")
    A(
        f"![configs](https://img.shields.io/badge/کانفیگ‌ها-{total}-2ea44f?style=for-the-badge) "
        f"![channels](https://img.shields.io/badge/کانال‌ها-{channels_n}-1f6feb?style=for-the-badge&logo=telegram&logoColor=white) "
        f"![protocols](https://img.shields.io/badge/پروتکل‌ها-{proto_n}-8957e6?style=for-the-badge) "
        f"![countries](https://img.shields.io/badge/کشورها-{len(country_counts)}-orange?style=for-the-badge)"
    )
    A("")
    A(f"`⏱️ آخرین به‌روزرسانی: {updated}`")
    A("")
    A("</div>")
    A("")

    # ----------------------------- شروع سریع -------------------------------
    A("## 🚀 شروع سریع")
    A("")
    A("لینک اشتراکِ **همه‌ی** کانفیگ‌ها را کپی کرده و در کلاینت خود وارد کنید (پیشنهادی برای اکثر کاربران):")
    A("")
    A("```text")
    A(all_b64)
    A("```")
    A("")
    if RAW_BASE:  # تصویر QR فقط با آدرسِ مطلق معنا دارد
        A('<div align="center">')
        A("")
        A(f'<img src="{_qr_url(all_b64)}" alt="QR لینک اشتراک همه" width="200" />')
        A("")
        A("<sub>📷 برای افزودنِ سریع، این کد را در کلاینت اسکن کنید</sub>")
        A("")
        A("</div>")
        A("")

    # ----------------------- جدول لینک‌های اشتراک --------------------------
    A("## 📡 لینک‌های اشتراک به تفکیک دسته")
    A("")
    A("| دسته | تعداد | لینک اشتراک (Base64) | متن خام |")
    A("|:-----|:----:|:---------------------|:------:|")
    for key, (name, emoji) in CATEGORY_META.items():
        count = cat_counts.get(key, 0)
        if key != "all" and count == 0:
            continue
        b64 = _sub_link(f"sub/{key}_b64.txt")
        plain = _sub_link(f"sub/{key}.txt")
        A(f"| {emoji} **{name}** | `{count}` | `{b64}` | [⬇️ خام]({plain}) |")
    A("")
    A("> 💡 محتوای ستون **«لینک اشتراک (Base64)»** را کپی و در بخش *Subscription / اشتراک* کلاینت خود وارد کنید.")
    A("")

    # ----------------- نمودار توزیع پروتکل‌ها (mermaid pie) -----------------
    chart_items = [(k, cat_counts.get(k, 0)) for k in CHART_CATEGORIES if cat_counts.get(k, 0) > 0]
    if chart_items:
        A("## 📊 توزیع پروتکل‌ها")
        A("")
        A("```mermaid")
        A("pie showData")
        A('    title توزیع کانفیگ‌ها بر اساس پروتکل')
        for k, v in sorted(chart_items, key=lambda x: -x[1]):
            A(f'    "{CATEGORY_META[k][0]}" : {v}')
        A("```")
        A("")

    # ------------------------- جدول کشورها ---------------------------------
    if country_counts:
        A("## 🌍 توزیع کشورها")
        A("")
        top = sorted(country_counts.items(), key=lambda x: (-x[1], x[0]))[:12]
        max_c = top[0][1] or 1
        A("| کشور | تعداد | سهم |")
        A("|:-----|:----:|:----|")
        for cc, c in top:
            filled = max(1, round(20 * c / max_c))
            bar = "█" * filled + "░" * (20 - filled)
            A(f"| {country_flag(cc)} `{cc}` | `{c}` | `{bar}` |")
        if len(country_counts) > 12:
            A(f"| … | `+{len(country_counts) - 12}` | `سایر کشورها` |")
        A("")

    # ------------- جدول کانال‌ها (در بخشِ جمع‌شونده برای نظم) ---------------
    if channel_counts:
        ranked = sorted(channel_counts.items(), key=lambda x: (-x[1], x[0]))
        A("## 📥 منابع (کانال‌های تلگرام)")
        A("")
        A("<details>")
        A(f"<summary>📋 مشاهده‌ی فهرست کامل — {len(ranked)} کانال</summary>")
        A("")
        A("| # | کانال | تعداد کانفیگ |")
        A("|:-:|:------|:-----------:|")
        for i, (ch, c) in enumerate(ranked, 1):
            A(f"| {i} | [@{ch}](https://t.me/{ch}) | `{c}` |")
        A("")
        A("</details>")
        A("")

    # ------------------------- راهنمای استفاده -----------------------------
    A("## 📱 نحوه‌ی استفاده")
    A("")
    A("۱. لینکِ اشتراکِ دسته‌ی دلخواه (ستون Base64) را کپی کنید.")
    A("")
    A("۲. در کلاینت، بخشِ **Subscription / اشتراک** را باز کرده و لینک را اضافه کنید.")
    A("")
    A("۳. اشتراک را **Update** کنید تا کانفیگ‌ها بارگذاری شوند.")
    A("")
    A("کلاینت‌های پیشنهادی: **v2rayNG** · **NekoBox** · **Hiddify** · **Streisand** · **Shadowrocket**")
    A("")

    # ----------------------------- پاورقی ----------------------------------
    A("---")
    A('<div align="center">')
    A("")
    A("<sub>🤖 ساخته‌شده به‌صورت خودکار با GitHub Actions • هر ۵ ساعت به‌روزرسانی می‌شود</sub>")
    A("")
    A("<sub>⚠️ این کانفیگ‌ها از منابع عمومی جمع‌آوری شده‌اند و صرفاً برای آزمایش و دسترسی آزاد به اینترنت‌اند.</sub>")
    A("")
    A("</div>")
    A("")
    return "\n".join(out)


# ----------------------------- نوار پیشرفت زنده --------------------------
def render_progress(done, total, last_channel="", last_count=0,
                    total_configs=0, eta=None):
    """نمایش نوار پیشرفتِ زنده.

    - روی ترمینال واقعی (TTY): یک خط که با \\r روی خودش به‌روز می‌شود.
    - روی محیط CI مثل GitHub Actions (بدون TTY): هر مرحله یک خطِ جدا چاپ می‌شود
      تا لاگ به‌صورت زنده (stream) پیش برود؛ flush برای نمایش فوری ضروری است.
    """
    width = 24
    frac = (done / total) if total else 1.0
    filled = int(round(width * frac))
    bar = "█" * filled + "░" * (width - filled)
    pct = int(frac * 100)

    parts = [f"[{bar}] {pct:3d}%", f"{done}/{total} چنل"]
    if last_channel:
        parts.append(f"@{last_channel} +{last_count}")
    parts.append(f"مجموع {total_configs}")
    if eta is not None and done < total:
        parts.append(f"~{eta}s مانده")
    line = " | ".join(parts)

    if sys.stdout.isatty():
        sys.stdout.write("\r" + line.ljust(90))
        sys.stdout.flush()
        if done >= total:
            sys.stdout.write("\n")
            sys.stdout.flush()
    else:
        print(line, flush=True)


# ----------------------------- اجرای اصلی --------------------------------
def parse_args(argv=None):
    p = argparse.ArgumentParser(
        description="جمع‌آوری کانفیگ‌های v2ray از چنل‌های عمومی تلگرام."
    )
    p.add_argument(
        "-n", "--per-channel", type=int, default=None,
        help=f"تعداد کانفیگِ اخیر از هر چنل (پیش‌فرض: {PER_CHANNEL}).",
    )
    p.add_argument(
        "--max-pages", type=int, default=None,
        help=f"حداکثر صفحه برای هر چنل تا رسیدن به تعداد هدف (پیش‌فرض: {MAX_PAGES}).",
    )
    return p.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    # اولویت: آرگومان خط فرمان > متغیر محیطی/پیش‌فرض
    per_channel = args.per_channel if args.per_channel and args.per_channel > 0 else PER_CHANNEL
    max_pages = args.max_pages if args.max_pages and args.max_pages > 0 else MAX_PAGES

    channels = load_channels()
    if not channels:
        print("هیچ چنلی در channels.txt تعریف نشده است.", file=sys.stderr)
        # خروجی خالی نمی‌نویسیم تا داده‌ی قبلی حفظ شود
        return 1

    print(f"تعداد چنل‌ها: {len(channels)} | هدف از هر چنل: {per_channel} کانفیگِ اخیر "
          f"| سقف صفحات: {max_pages} | تردهای هم‌زمان: {WORKERS}")

    # هر اجرا کاملاً از نو: dedup فقط در محدوده‌ی همین اجرا انجام می‌شود.
    # واکشی به‌صورت موازی انجام می‌شود ولی ترتیب و dedup خروجی قطعی می‌ماند.
    total = len(channels)
    start = time.time()
    progress = {"grand": 0}     # شمارنده‌ی زنده‌ی کانفیگ‌های واکشی‌شده (پیش از dedup نهایی)

    def _on_channel_done(done, ch, count):
        # هر بار که واکشیِ یک چنل تمام می‌شود (به ترتیب اتمام، نه ورودی) صدا زده می‌شود.
        progress["grand"] += count
        elapsed = time.time() - start
        eta = int(elapsed / done * (total - done)) if done < total else 0
        render_progress(done, total, last_channel=ch, last_count=count,
                        total_configs=progress["grand"], eta=eta)

    render_progress(0, total, total_configs=0)
    collected_by_channel = collect_all(
        channels, per_channel, max_pages, WORKERS, progress_cb=_on_channel_done
    )

    # ساخت رکوردها با شماره‌ی per-channel (۱ برای اولین کانفیگِ هر کانال)
    records = []
    for ch, got in collected_by_channel:
        for idx, cfg in enumerate(got, 1):
            records.append({"channel": ch, "idx": idx, "cfg": cfg})

    # اگر این اجرا هیچ کانفیگی نگرفت (مثلاً قطعی شبکه)، خروجی قبلی را پاک نمی‌کنیم
    if not records:
        print("هیچ کانفیگی در این اجرا جمع نشد؛ خروجی قبلی حفظ شد.", file=sys.stderr)
        return 1

    # تشخیص کشورها
    print("در حال تشخیص کشورِ کانفیگ‌ها...", flush=True)
    annotate_countries(records)

    # ساخت remark جدید + دسته‌بندی + آمار
    categories = {key: [] for key in CATEGORY_META}
    country_counts = {}
    channel_counts = {}

    for r in records:
        cfg = r["cfg"]
        scheme = cfg.split("://", 1)[0].lower()
        primary = PROTOCOL_CATEGORY.get(scheme, "others")
        cc = r.get("cc", "")

        # نام جدید: «پرچم کد‌کشور | @کانال | شماره»
        parts = []
        if cc:
            parts.append((country_flag(cc) + " " + cc).strip())
        parts.append("@" + r["channel"])
        parts.append(str(r["idx"]))
        new_cfg = set_remark(cfg, " | ".join(parts))

        categories["all"].append(new_cfg)
        categories[primary].append(new_cfg)
        if scheme == "vless" and is_reality(cfg):
            categories["reality"].append(new_cfg)

        if cc:
            country_counts[cc] = country_counts.get(cc, 0) + 1
        channel_counts[r["channel"]] = channel_counts.get(r["channel"], 0) + 1

    write_outputs(categories)

    # تولید README داینامیک
    cat_counts = {key: len(v) for key, v in categories.items()}
    channels_with_data = sum(1 for _, g in collected_by_channel if g)
    updated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    readme = generate_readme(
        total=cat_counts["all"],
        channels_n=channels_with_data,
        cat_counts=cat_counts,
        country_counts=country_counts,
        channel_counts=channel_counts,
        updated=updated,
    )
    with open(README_FILE, "w", encoding="utf-8") as f:
        f.write(readme)

    print(f"\nمجموع کل کانفیگ‌ها: {cat_counts['all']} | کشورها: {len(country_counts)} "
          f"| دسته‌های دارای کانفیگ: {sum(1 for k, v in cat_counts.items() if v and k != 'all')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
