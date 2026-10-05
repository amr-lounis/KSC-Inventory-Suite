#!/usr/bin/env python3
"""Shared helpers for the Kaspersky inventory toolkit (stdlib only).

Single home for the utils duplicated across vuln_check / vuln_update /
json_to_excel / gui / kaspersky_inventory: app paths, text + version
helpers, OS classification, canonical software names, CISA KEV access,
JSON-over-HTTP and Excel styling.

Importing modules re-export the names their callers/tests use, so moving
code here changes no behavior.
"""
import json
import re
import sys
import time
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

USER_AGENT = {"User-Agent": "ksc-inventory/2.0"}
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


# ---------- paths ----------

def get_app_dir():
    if getattr(sys, "frozen", False):
        return Path(sys.executable).parent
    return Path(__file__).parent


def get_out_dir():
    d = get_app_dir() / "out"
    d.mkdir(parents=True, exist_ok=True)
    return d


def resource_path(name):
    """File next to the app/exe; falls back to bundled _MEIPASS."""
    p = get_app_dir() / name
    if p.exists():
        return p
    meipas = getattr(sys, "_MEIPASS", None)
    if meipas and (Path(meipas) / name).exists():
        return Path(meipas) / name
    return p


def cache_path(name):
    """Cache files (KEV/NVD/OSV/EPSS) live in out/."""
    return get_out_dir() / name


def load_json_file(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


# ---------- text ----------

WS_RE = re.compile(r"\s+")
TOK_RE = re.compile(r"[^a-z0-9]+")
NUM_RE = re.compile(r"\d+")
PAREN_RE = re.compile(r"\(.*?\)")


def strip_accents(s):
    return "".join(c for c in unicodedata.normalize("NFKD", s) if not unicodedata.combining(c))


def split_tokens(s, min_len=5, generic=()):
    return {t for t in TOK_RE.split(s) if len(t) >= min_len and t not in generic}


def split_tokens_list(s, min_len=3, generic=()):
    """Ordered variant (for top-N slicing)."""
    return [t for t in TOK_RE.split(s) if len(t) >= min_len and t not in generic]


def normalize_name(name, rules=None):
    s = strip_accents(str(name or "").lower())
    s = s.replace("\ufffd", "").replace("\x00", " ")
    s = WS_RE.sub(" ", s).strip()
    if rules:
        for k, v in (rules.get("aliases") or {}).items():
            if k in s:
                s = v
                break
    return s


def clean_label(label):
    s = strip_accents(str(label or "").lower())
    s = PAREN_RE.sub(" ", s)
    return WS_RE.sub(" ", s).strip()


# ---------- versions ----------

VER_CACHE = {}


def parse_version(s):
    parts = NUM_RE.findall(str(s or ""))
    if not parts:
        return ()
    return tuple(int(x) for x in parts[:6])


def parse_version_cached(s):
    key = str(s or "")
    v = VER_CACHE.get(key)
    if v is None:
        v = parse_version(key)
        if len(VER_CACHE) < 50000:
            VER_CACHE[key] = v
    return v


def cmp_versions(a, b):
    la, lb = tuple(a or ()), tuple(b or ())
    n = max(len(la), len(lb))
    la += (0,) * (n - len(la))
    lb += (0,) * (n - len(lb))
    return (la > lb) - (la < lb)


# ---------- OS ----------

LINUX_KEYWORDS = (
    "linux", "ubuntu", "debian", "centos", "rhel", "red hat", "fedora",
    "suse", "astra", "alt linux", "rosa", "mint", "arch", "gentoo",
    "oracle linux", "almalinux", "rocky", "kali",
)


def classify_os(os_name):
    """Windows / Linux / Other from a host OS string."""
    s = str(os_name or "").strip().lower()
    if not s:
        return "other"
    if "windows" in s or "microsoft" in s or "win32" in s:
        return "windows"
    if any(k in s for k in LINUX_KEYWORDS):
        return "linux"
    return "other"


# ---------- canonical software names ----------

ARCH_TOKENS = frozenset({
    "x64", "x86", "x32", "64-bit", "32-bit", "64bit", "32bit",
    "amd64", "i386", "i686", "x86_64", "win32", "win64", "64", "86", "32",
})
FILLER_TOKENS = frozenset({"bit", "bits", "edition"})
CHANNEL_TOKENS = frozenset({
    "esr", "lts", "stable", "beta", "preview", "nightly", "dev", "canary", "alpha",
})
LANG_NAMES = frozenset({
    "francais", "french", "english", "anglais", "german", "allemand",
    "spanish", "espagnol", "italian", "italien", "dutch", "neerlandais",
    "portuguese", "portugais", "russian", "russe", "arabic", "arabe",
    "chinese", "chinois", "japanese", "japonais", "korean", "coreen",
    "turkish", "turc", "polish", "polonais", "czech", "tcheque",
    "swedish", "suedois", "norwegian", "norvegien", "danish", "danois",
    "finnish", "finnois", "greek", "grec", "hebrew", "hebreu",
})
LOCALE_RE = re.compile(r"^[a-z]{2}([-_][a-z0-9]{2,3})?$")
PAREN_GROUP_RE = re.compile(r"[\(\[]([^\(\)\[\]]+)[\)\]]")
TRAIL_LOCALE_RE = re.compile(r"\s+-\s+[a-z]{2}([-_][a-z0-9]{2,3})?\s*$", re.IGNORECASE)
TRAIL_ARCH_RE = re.compile(
    r"\s+(x64|x86|x32|64-bit|32-bit|64bit|32bit|amd64|i[36]86|x86_64|win32|win64)\.?\s*$",
    re.IGNORECASE)
TRAIL_CHANNEL_RE = re.compile(
    r"\s+(esr|lts|stable|beta|preview|nightly|canary|alpha)\.?\s*$", re.IGNORECASE)
TRAIL_UPDATE_RE = re.compile(r"\s+update\s+\d+\s*$", re.IGNORECASE)
TRAIL_VER_RE = re.compile(r"(\d+(?:\.\d+)+(?:[-+._][0-9a-z]+)?)\s*$", re.IGNORECASE)
VER_TOKEN_RE = re.compile(r"^\d+(?:\.\d+)*$")
VER_IN_TEXT_RE = re.compile(r"\d+(?:\.\d+)*")


def _marker_token(tok):
    t = strip_accents(tok.lower())
    if t in ARCH_TOKENS or t in FILLER_TOKENS or t in CHANNEL_TOKENS or t in LANG_NAMES:
        return True
    return bool(LOCALE_RE.match(t))


def canonical_name(name, version=""):
    """Unified display name: strips arch (x64/x86), locale (fr/en-US),
    channel (ESR/Stable/Beta), 'Update NNN' and a version embedded in the
    name (only when it matches the record's version; branding years like
    'Office 2007' are kept).

    Used ONLY for grouping/display in Soft sheets; scoring still uses the
    exact (name, version) pair.
    """
    s = str(name or "").replace("\xa0", " ")
    s = WS_RE.sub(" ", s).strip(" -_,;")
    if not s:
        return ""
    ver = str(version or "").strip()
    if ver:
        m = TRAIL_VER_RE.search(s)
        if m:
            vtok, vver = parse_version_cached(m.group(1)), parse_version_cached(ver)
            if vtok and vver and (vver[:len(vtok)] == vtok or vtok[:len(vver)] == vver):
                s = WS_RE.sub(" ", s[:m.start(1)]).strip(" -_,;")

    def _sub(m):
        inner = m.group(1).strip()
        if ver and (inner == ver or ver.startswith(inner)):
            return ""
        toks = [t.strip(" \t-_.,") for t in inner.split()]
        if toks and all(_marker_token(t) for t in toks if t):
            return ""
        return m.group(0)

    prev = None
    while prev != s:
        prev = s
        s = PAREN_GROUP_RE.sub(_sub, s)
    prev = None
    while prev != s:
        prev = s
        s = TRAIL_LOCALE_RE.sub("", s)
        s = TRAIL_ARCH_RE.sub("", s)
        s = TRAIL_CHANNEL_RE.sub("", s)
        s = TRAIL_UPDATE_RE.sub("", s)
        # dotted version baked into the name (no dots = branding year, kept)
        m = TRAIL_VER_RE.search(s)
        if m and "." in m.group(1):
            s = s[:m.start(1)]
        s = WS_RE.sub(" ", s).strip(" -_,;")
    return s


# ---------- CISA KEV ----------

def load_kev_cache():
    for p in (cache_path("kev_cache.json"), get_app_dir() / "kev_cache.json"):
        try:
            d = json.loads(p.read_text(encoding="utf-8"))
            return d.get("vulnerabilities", d if isinstance(d, list) else [])
        except Exception:
            continue
    return []


def fetch_kev(timeout=30):
    try:
        d = http_json(KEV_URL, timeout=timeout)
        vulns = d.get("vulnerabilities", [])
        cache_path("kev_cache.json").write_text(json.dumps(
            {"fetched_at": datetime.now(timezone.utc).isoformat(), "count": len(vulns),
             "vulnerabilities": vulns}, ensure_ascii=False), encoding="utf-8")
        print(f"KEV cache updated: {len(vulns)} entries")
        return vulns
    except Exception as e:
        print(f"KEV download failed ({e}) - using cache")
        return load_kev_cache()


# ---------- JSON over HTTP ----------

def http_json(url, data=None, headers=None, timeout=60, retries=3):
    """GET/POST JSON with retry on rate-limit / transient errors."""
    hdrs = dict(USER_AGENT)
    if headers:
        hdrs.update(headers)
    body = None
    if data is not None:
        body = json.dumps(data).encode("utf-8")
        hdrs.setdefault("Content-Type", "application/json")
    last = None
    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, data=body, headers=hdrs)
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return json.loads(r.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            last = e
            # NVD answers 403 when rate-limited
            if e.code in (403, 429, 500, 502, 503, 504) and attempt < retries - 1:
                ra = e.headers.get("Retry-After") if e.headers else None
                wait = int(ra) if ra and str(ra).isdigit() else 10 * (attempt + 1)
                time.sleep(min(wait, 60))
                continue
            raise
        except (urllib.error.URLError, TimeoutError, ConnectionError) as e:
            last = e
            if attempt < retries - 1:
                time.sleep(3 * (attempt + 1))
                continue
            raise
    raise last


# ---------- Excel styling (openpyxl loaded lazily) ----------

def excel_styles(header_color="C00000", border_color="D9D9D9"):
    """Shared (hdr_font, hdr_fill, border, center, left) style tuple."""
    from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
    hdr_font = Font(bold=True, color="FFFFFF")
    hdr_fill = PatternFill(start_color=header_color, end_color=header_color,
                           fill_type="solid")
    thin = Side(style="thin", color=border_color)
    bd = Border(left=thin, right=thin, top=thin, bottom=thin)
    center = Alignment(horizontal="center", vertical="center", wrap_text=True)
    left = Alignment(horizontal="left", vertical="center", wrap_text=True)
    return hdr_font, hdr_fill, bd, center, left
