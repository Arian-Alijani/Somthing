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
"""

import argparse
import base64
import binascii
import html
import json
import os
import re
import sys
import time
import urllib.parse
import urllib.request
from collections import OrderedDict

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

ROOT = os.path.dirname(os.path.abspath(__file__))
CHANNELS_FILE = os.path.join(ROOT, "channels.txt")
DATA_DIR = os.path.join(ROOT, "data")
SUB_DIR = os.path.join(ROOT, "sub")
RAW_FILE = os.path.join(DATA_DIR, "all_configs.txt")   # اسنپ‌شات کانفیگ‌های همین اجرا
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


# ----------------------------- ابزار شبکه ---------------------------------
def fetch(url):
    """دریافت محتوای یک URL با چند بار تلاش مجدد."""
    last_err = None
    for attempt in range(1, RETRIES + 1):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
            with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
                data = resp.read()
            return data.decode("utf-8", errors="replace")
        except Exception as e:  # noqa: BLE001
            last_err = e
            time.sleep(2 * attempt)
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
    import hashlib
    canon = canonical_config(cfg)
    return hashlib.sha256(canon.encode("utf-8")).hexdigest()


# ----------------------------- جمع‌آوری از یک چنل -------------------------
def collect_from_channel(channel, run_seen, per_channel, max_pages):
    """تا per_channel کانفیگِ *اخیرِ* غیرتکراری از یک چنل برمی‌گرداند.

    در صفحه‌ی web تلگرام پیام‌ها از قدیمی (بالا) به جدید (پایین) مرتب‌اند، پس
    برای رسیدن به «جدیدترین‌ها» کانفیگ‌های هر صفحه معکوس می‌شوند (جدید اول).
    اگر صفحه‌ی نخست به per_channel نرسد، با پارامتر before صفحات قدیمی‌تر هم
    خوانده می‌شوند. تکراری‌ها با run_seen (مشترک بین همه‌ی چنل‌های همین اجرا)
    حذف می‌شوند تا یک کانفیگ دوبار در خروجی نیاید.
    """
    collected = []          # جدیدترین‌ها اول
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
            if h in run_seen:
                continue
            run_seen.add(h)
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


# ----------------------------- خروجی سابسکریپشن --------------------------
def write_outputs(all_configs):
    os.makedirs(SUB_DIR, exist_ok=True)
    os.makedirs(DATA_DIR, exist_ok=True)

    plain = "\n".join(all_configs) + ("\n" if all_configs else "")

    with open(SUB_PLAIN, "w", encoding="utf-8") as f:
        f.write(plain)
    with open(RAW_FILE, "w", encoding="utf-8") as f:
        f.write(plain)

    b64 = base64.b64encode(plain.encode("utf-8")).decode("ascii")
    with open(SUB_B64, "w", encoding="utf-8") as f:
        f.write(b64)


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
          f"| سقف صفحات: {max_pages}")

    # هر اجرا کاملاً از نو: dedup فقط در محدوده‌ی همین اجرا انجام می‌شود.
    run_seen = set()
    all_configs = []
    total = len(channels)
    start = time.time()

    render_progress(0, total, total_configs=0)
    for i, ch in enumerate(channels, 1):
        try:
            got = collect_from_channel(ch, run_seen, per_channel, max_pages)
            all_configs.extend(got)
            last_count = len(got)
        except Exception as e:  # noqa: BLE001
            # خطای یک چنل نباید بقیه را متوقف کند؛ \n تا نوارِ TTY خراب نشود.
            print(f"\n  [{ch}] خطا: {e}", file=sys.stderr, flush=True)
            last_count = 0
        elapsed = time.time() - start
        eta = int(elapsed / i * (total - i)) if i < total else 0
        render_progress(i, total, last_channel=ch, last_count=last_count,
                        total_configs=len(all_configs), eta=eta)

    # اگر این اجرا هیچ کانفیگی نگرفت (مثلاً قطعی شبکه)، خروجی قبلی را پاک نمی‌کنیم
    if not all_configs:
        print("هیچ کانفیگی در این اجرا جمع نشد؛ خروجی قبلی حفظ شد.", file=sys.stderr)
        return 1

    write_outputs(all_configs)

    print(f"\nمجموع کل کانفیگ‌ها در سابسکریپشن (این اجرا): {len(all_configs)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
