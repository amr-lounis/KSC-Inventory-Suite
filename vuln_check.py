#!/usr/bin/env python3
"""Offline-first vulnerability triage for Kaspersky inventory JSON.

Self-contained (stdlib only, no imports from other project scripts).
Usage:
    py vuln_check.py kaspersky_inventory_*.json [--online] [--top N] [-o out.json] [--excel]
Rules come from vuln_rules.json (built by vuln_update.py); paths from gui.py/CLI.
"""
import json
import math
import re
import sys
import time
import unicodedata
import urllib.error
import urllib.request
import urllib.parse
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from typing import Dict, List, Optional, Tuple

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_DELAY = 7  # seconds between NVD calls without API key

# Score thresholds (single source of truth for level_of + excel fills)
RISK_LEVELS = ("Critical", "High", "Medium", "Low", "Safe")
RISK_MIN_SCORE = {"Critical": 9, "High": 7, "Medium": 4, "Low": 0.1, "Safe": 0}
RISK_COLORS = {"Critical": "C00000", "High": "ED7D31", "Medium": "FFC000",
               "Low": "FFF2CC", "Safe": "E2EFDA"}
EVERGREEN_BROWSERS = ("google chrome", "microsoft edge", "mozilla firefox", "opera")


def get_app_dir():
    if getattr(sys, "frozen", False):
        return Path(sys.executable).parent
    return Path(__file__).parent


def get_out_dir():
    d = get_app_dir() / "out"
    d.mkdir(parents=True, exist_ok=True)
    return d


def resource_path(name):
    p = get_app_dir() / name
    if p.exists():
        return p
    meipas = getattr(sys, "_MEIPASS", None)
    if meipas and (Path(meipas) / name).exists():
        return Path(meipas) / name
    return p


def cache_path(name):
    return get_out_dir() / name


def load_rules(path=None):
    p = Path(path) if path else resource_path("vuln_rules.json")
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception as e:
        print(f"Warning: cannot load rules {p}: {e} - using empty rules")
        return {}


_WS_RE = re.compile(r"\s+")
_TOK_RE = re.compile(r"[^a-z0-9]+")
_NUM_RE = re.compile(r"\d+")

_VER_CACHE: Dict[str, tuple] = {}


def strip_accents(s):
    return "".join(c for c in unicodedata.normalize("NFKD", s) if not unicodedata.combining(c))


def split_tokens(s, min_len=5, generic=()):
    return {t for t in _TOK_RE.split(s) if len(t) >= min_len and t not in generic}


def split_tokens_list(s, min_len=3, generic=()):
    """Ordered variant (for top-N slicing)."""
    return [t for t in _TOK_RE.split(s) if len(t) >= min_len and t not in generic]


def normalize_name(name, rules=None):
    s = strip_accents(str(name or "").lower())
    s = s.replace("�", "").replace("\x00", " ")
    s = _WS_RE.sub(" ", s).strip()
    if rules:
        for k, v in (rules.get("aliases") or {}).items():
            if k in s:
                s = v
                break
    return s


def parse_version(s):
    parts = _NUM_RE.findall(str(s or ""))
    if not parts:
        return ()
    return tuple(int(x) for x in parts[:6])


def parse_version_cached(s):
    key = str(s or "")
    v = _VER_CACHE.get(key)
    if v is None:
        v = parse_version(key)
        if len(_VER_CACHE) < 50000:
            _VER_CACHE[key] = v
    return v


def cmp_versions(a, b):
    la, lb = tuple(a or ()), tuple(b or ())
    n = max(len(la), len(lb))
    la += (0,) * (n - len(la))
    lb += (0,) * (n - len(lb))
    return (la > lb) - (la < lb)


def entry_matches(norm, entry):
    """Supports {'match': 'substr'} and {'match_all': ['t1','t2',...]} (all tokens).

    Legacy substring semantics; EOL checks use the stricter
    _eol_entry_matches() below (word + version-component matching).
    """
    m = entry.get("match")
    if m and m in norm:
        return True
    ma = entry.get("match_all")
    if ma and all(t in norm for t in ma):
        return True
    return False


_VER_TOKEN_RE = re.compile(r"^\d+(?:\.\d+)*$")
_VER_IN_TEXT_RE = re.compile(r"\d+(?:\.\d+)*")
_WORD_RX_CACHE: Dict[str, "re.Pattern"] = {}
_VER_WORD_RX_CACHE: Dict[str, "re.Pattern"] = {}
_VER_PARTS_CACHE: Dict[str, Optional[tuple]] = {}
_PY_LIB_RE = re.compile(r"^python\d*[-_][a-z]")


def _word_rx(token):
    rx = _WORD_RX_CACHE.get(token)
    if rx is None:
        rx = re.compile(r"\b" + re.escape(token) + r"(?![a-z])")
        if len(_WORD_RX_CACHE) < 5000:
            _WORD_RX_CACHE[token] = rx
    return rx


def _ver_word_rx(token):
    """Standalone number in text: no digit/letter glued on either side."""
    rx = _VER_WORD_RX_CACHE.get(token)
    if rx is None:
        rx = re.compile(r"(?<![a-z0-9])" + re.escape(token) + r"(?![a-z0-9])")
        if len(_VER_WORD_RX_CACHE) < 5000:
            _VER_WORD_RX_CACHE[token] = rx
    return rx


def _ver_token_parts(token):
    """Numeric dotted token -> int tuple; None for non-version tokens."""
    if token in _VER_PARTS_CACHE:
        return _VER_PARTS_CACHE[token]
    m = _VER_TOKEN_RE.match(str(token or "").strip())
    v = tuple(int(x) for x in m.group(0).split(".")) if m else None
    if len(_VER_PARTS_CACHE) < 5000:
        _VER_PARTS_CACHE[token] = v
    return v


def _eol_entry_matches(norm, version, entry):
    """Strict EOL matching: name tokens as whole words; version tokens as
    leading version components OR standalone numbers in the product name
    (branding years like 'Office 2007' / 'SQL Server 2008').

    Fixes substring over-matching, e.g. token '7' matching version
    '17.0.20', '15' matching '152.0', or '6.0' matching '13.2.5026.0'.
    """
    m = entry.get("match")
    if m:
        combined = f"{norm} {str(version or '').strip().lower()}".strip()
        return m in norm or m in combined
    ma = entry.get("match_all")
    if not ma:
        return False
    ver = str(version or "").strip().lower()
    combined = f"{norm} {ver}".strip()
    ver_cands = []
    if ver:
        for grp in _VER_IN_TEXT_RE.findall(ver):
            try:
                ver_cands.append(tuple(int(x) for x in grp.split(".")))
            except ValueError:
                continue
    ver_cands = [c for c in ver_cands if c]
    for t in ma:
        vp = _ver_token_parts(t)
        if vp is not None:
            if any(c[:len(vp)] == vp for c in ver_cands):
                continue
            if _ver_word_rx(t).search(norm):
                continue
            return False
        elif not _word_rx(t).search(combined):
            return False
    return True


def _is_python_lib(norm):
    """Distro library packages (python3-apt, python3-botocore, ...) are not
    the Python interpreter: interpreter EOL/min-version rules don't apply."""
    return "python" in norm and bool(
        _PY_LIB_RE.search(norm) or norm.startswith("libpython"))


@lru_cache(maxsize=8)
def _compiled_family_patterns(patterns_key: tuple) -> tuple:
    """Compile family patterns with word-boundary guard (cached).

    Prevents e.g. 'java' matching 'javascript' while still matching
    'java 8', 'java(tm) 6', 'python3.12' (digit after is fine).
    """
    out = []
    for pat, fam in patterns_key:
        try:
            out.append((re.compile(r"\b" + re.escape(pat) + r"(?![a-z])"), fam, None))
        except re.error:
            out.append((None, fam, pat))
    return tuple(out)


def family_of(norm_name, rules):
    key = tuple(tuple(p) for p in (rules.get("family_patterns") or []))
    for compiled, fam, fallback in _compiled_family_patterns(key):
        if compiled is not None:
            if compiled.search(norm_name):
                return fam
        elif fallback and fallback in norm_name:
            return fam
    return None


def is_noise(norm_name, rules):
    return any(p in norm_name for p in (rules.get("noise_patterns") or []))


def level_of(score):
    for level in RISK_LEVELS:
        if score >= RISK_MIN_SCORE[level]:
            return level
    return "Safe"


def classify_os(os_name):
    """Windows / Linux / Other from host OS string (self-contained, mirrors json_to_excel)."""
    s = str(os_name or "").strip().lower()
    if not s:
        return "other"
    if "windows" in s or "microsoft" in s or "win32" in s:
        return "windows"
    linux_keywords = (
        "linux", "ubuntu", "debian", "centos", "rhel", "red hat", "fedora",
        "suse", "astra", "alt linux", "rosa", "mint", "arch", "gentoo",
        "oracle linux", "almalinux", "rocky", "kali",
    )
    if any(k in s for k in linux_keywords):
        return "linux"
    return "other"


def _check_eol(norm: str, version: str, rules: dict) -> Tuple[int, List[str], List[str]]:
    """Static + upstream EOL matches. Returns (score, reasons, actions).

    Matches against 'name + version' so entries like
    {'match_all': ['chrome', '100']} work even when DisplayName
    ('Google Chrome') does not contain the version number.
    """
    score, reasons, actions = 0, [], []
    ver_norm = strip_accents(str(version or "").lower())
    ver_norm = _WS_RE.sub(" ", ver_norm).strip()
    skip_python = _is_python_lib(norm)
    for item in (rules.get("eol_products") or []) + (rules.get("upstream_eol") or []):
        if item.get("kind", "app") != "app":
            continue
        if skip_python and item.get("product") == "python":
            continue
        if _eol_entry_matches(norm, ver_norm, item):
            score = max(score, int(item.get("score", 9)))
            reasons.append(item.get("label", item.get("match", "?")))
            if item.get("action"):
                actions.append(item["action"])
    return score, reasons, actions


def _browser_gap_score(gap: int, major_gap_only: bool) -> int:
    if major_gap_only:
        return 9 if gap >= 6 else (8 if gap >= 3 else 6)
    return 9 if gap >= 10 else 8


def _check_min_version(norm: str, fam: Optional[str], version: str, name: str,
                       rules: dict) -> Tuple[int, List[str], List[str]]:
    """Curated minimum-safe-version comparison."""
    score, reasons, actions = 0, [], []
    key = fam or norm
    if fam == "python" and _is_python_lib(norm):
        return score, reasons, actions
    entry = (rules.get("min_safe_versions") or {}).get(key)
    if not (entry and version and str(version).strip()):
        return score, reasons, actions
    cur = parse_version_cached(version)
    minimum = parse_version_cached(entry.get("min", ""))
    if not (cur and minimum and cmp_versions(cur, minimum) < 0):
        return score, reasons, actions
    gap = minimum[0] - cur[0] if len(minimum) > 0 and len(cur) > 0 else 0
    if fam in EVERGREEN_BROWSERS:
        s = _browser_gap_score(gap, major_gap_only=False)
        if gap < 10 and len(cur) > 1 and len(minimum) > 1 \
                and minimum[0] == cur[0] and minimum[1] - cur[1] >= 30:
            s = 9
        if cur and cur[0] <= 109:
            s = 9
    elif gap >= 2:
        s = 8
    elif gap == 1:
        s = 6
    else:
        s = 5
    score = max(score, s)
    reasons.append(f"Outdated: {version} < minimum safe {entry['min']} ({fam or name})")
    if entry.get("action"):
        actions.append(entry["action"])
    return score, reasons, actions


def _check_freshness(fam: Optional[str], version: str,
                     rules: dict) -> Tuple[int, List[str], List[str]]:
    """endoflife.date evergreen families vs latest known major.

    Edge/Opera share Chromium majors with Chrome, so they reuse the chrome entry.
    """
    score, reasons, actions = 0, [], []
    up_latest = rules.get("upstream_latest") or {}
    if not (version and str(version).strip()):
        return score, reasons, actions
    # Prefer direct entry, fall back to Chrome majors for Chromium-based browsers.
    candidates = []
    if fam:
        candidates.append(fam)
    if fam in ("microsoft edge", "opera") and "google chrome" not in candidates:
        candidates.append("google chrome")
    fam_key = next((c for c in candidates if c in up_latest), None)
    if not fam_key:
        return score, reasons, actions
    try:
        latest_major = int(up_latest[fam_key].get("major", 0))
    except (TypeError, ValueError):
        latest_major = 0
    cur = parse_version_cached(version)
    if not (cur and latest_major and cur[0] > 0 and cur[0] < latest_major):
        return score, reasons, actions
    gap = latest_major - cur[0]
    if fam in EVERGREEN_BROWSERS:
        s = _browser_gap_score(gap, major_gap_only=True)
    else:
        s = 8 if gap >= 2 else 6
    score = max(score, s)
    reasons.append(f"Outdated vs upstream: {version} (latest {fam} major {latest_major}, endoflife.date)")
    actions.append("Update to the latest release")
    return score, reasons, actions


def _check_kev(norm: str, publisher: str, score: int, rules: dict,
               kev_index: list) -> Tuple[int, List[str], List[str]]:
    """CISA KEV: bump only with existing evidence; informational otherwise."""
    reasons, actions = [], []
    generic = set(rules.get("generic_tokens") or ())
    first = match_kev_first(norm, normalize_name(publisher or ""),
                            split_tokens(norm, generic=generic), kev_index)
    if first is None:
        return score, reasons, actions
    note = (f"CISA KEV: {first['cveID']} - {first.get('product', '')} "
            f"({first.get('vulnerabilityName', '')[:80]})")
    if score >= 7:
        # outdated/EOL + product family actively exploited -> Critical-ish.
        # Name match only (no version proof): capped at 9; a version-confirmed
        # KEV CVE (NVD/OSV) is scored 10 by apply_risk_model().
        score = max(score, 9)
        reasons.append(note + " [product family actively exploited - verify version, patch]")
        actions.append("Patch immediately (product family actively exploited)")
    elif score > 0:
        reasons.append(note + " [verify installed version is patched]")
    else:
        # current version, but product family has exploited CVEs -> informational
        score = max(score, 3)
        reasons.append(note + " [product family in KEV - keep updated]")
        actions.append("Keep updated (product family in CISA KEV)")
    return score, reasons, actions


def assess(name: str, version: str, publisher: str = "",
           rules: Optional[dict] = None, kev=None) -> dict:
    """Score one (name, version). Pure offline unless kev index given.

    Each check is independent - add new sources as _check_* helpers.
    """
    rules = rules or {}
    norm = normalize_name(name, rules)
    if not norm or is_noise(norm, rules):
        return {"score": 0, "level": "Safe", "reasons": ["Noise/OS update entry - excluded"], "action": "-",
                "components": {"eol": 0, "outdated": 0, "floor": 0, "kev_name": False}}
    fam = family_of(norm, rules)
    ver = str(version or "").strip()

    checks = [
        _check_eol(norm, ver, rules),
        _check_min_version(norm, fam, ver, name, rules),
        _check_freshness(fam, ver, rules),
    ]
    comp = {"eol": checks[0][0], "outdated": max(checks[1][0], checks[2][0]),
            "floor": 0, "kev_name": False}
    score = 0
    reasons: List[str] = []
    actions: List[str] = []
    for s, rs, acts in checks:
        score = max(score, s)
        reasons.extend(rs)
        actions.extend(acts)

    if kev:
        kev_index = kev if (kev and isinstance(kev[0], tuple)) else build_kev_index(kev, rules)
        score, rs, acts = _check_kev(norm, publisher, score, rules, kev_index)
        comp["kev_name"] = bool(rs)
        reasons.extend(rs)
        actions.extend(acts)

    if not reasons:
        if not ver:
            # Missing version must not be reported as Safe (false negative).
            comp["floor"] = 4
            return {"score": 4, "level": "Medium",
                    "reasons": ["Version missing - manual review required"],
                    "action": "Verify installed version manually", "components": comp}
        return {"score": 0, "level": "Safe", "reasons": [], "action": "-", "components": comp}
    if not actions:
        actions.append("Update to a supported version")
    return {"score": score, "level": level_of(score),
            "reasons": reasons, "action": "; ".join(dict.fromkeys(actions)),
            "components": comp}


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
        req = urllib.request.Request(KEV_URL, headers={"User-Agent": "ksc-inventory/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            d = json.loads(r.read().decode("utf-8"))
        vulns = d.get("vulnerabilities", [])
        cache_path("kev_cache.json").write_text(json.dumps(
            {"fetched_at": datetime.now(timezone.utc).isoformat(), "count": len(vulns),
             "vulnerabilities": vulns}, ensure_ascii=False), encoding="utf-8")
        print(f"KEV cache updated: {len(vulns)} entries")
        return vulns
    except Exception as e:
        print(f"KEV download failed ({e}) - using cache")
        return load_kev_cache()


def build_kev_index(kev_list, rules=None):
    """Precompute normalized KEV data once (was re-normalized per software item).

    Skips vendor-only labels (e.g. product == "Microsoft") that would otherwise
    match every product of that vendor with an unrelated CVE.
    """
    generic = set((rules or {}).get("generic_tokens") or ())
    index = []
    for entry in kev_list or []:
        prod = normalize_name(entry.get("product", ""))
        if not prod:
            continue
        if _is_vendor_only_label(prod, generic):
            continue
        vend = normalize_name(entry.get("vendorProject", ""))
        overlap = split_tokens(prod, generic=generic)
        index.append((entry, prod, vend, overlap))
    return index


def _is_vendor_only_label(prod: str, generic: set) -> bool:
    """True for labels like 'Microsoft' that would match every vendor product."""
    parts = [t for t in prod.split() if t]
    return bool(parts) and all(t in generic or len(t) < 3 for t in parts) \
        and not any(c.isdigit() for c in prod)


def match_kev_first(norm_name, pub_norm, tokens, kev_index):
    """Return first matching KEV entry (assess only uses the first hit)."""
    for entry, prod, vend, overlap in kev_index:
        if prod in norm_name:
            return entry
        if len(prod) >= 6 and any(prod in t or t in prod for t in tokens):
            if not vend or vend in norm_name or vend in pub_norm:
                return entry
        if vend and (vend in norm_name or vend in pub_norm) and overlap & tokens:
            return entry
    return None


# ======================================================================
# Online sources (v2)
#   * NVD CVE 2.0   - CPE version-range matching (paginated, apiKey header)
#   * OSV.dev       - Linux distro packages (batch ids -> full records)
#   * EPSS (FIRST)  - probability of exploitation per CVE
#   * CISA KEV      - exact CVE match (not product-name guessing)
# Every source is cached with a TTL and is readable offline from cache.
# Enrichers only ADD evidence (item["cves"]); the final score is computed
# in one place: apply_risk_model().
# ======================================================================
EPSS_URL = "https://api.first.org/data/v1/epss"
OSV_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/"
NVD_PAGE_SIZE = 2000
NVD_DELAY_KEY = 0.8          # 50 requests / 30 s with an API key
EPSS_BATCH = 50
OSV_BATCH = 500
UA_HEADERS = {"User-Agent": "ksc-inventory/2.0"}

TTL_NVD = 3 * 86400
TTL_OSV = 3 * 86400
TTL_OSV_VULN = 14 * 86400
TTL_EPSS = 1 * 86400
TTL_CVE = 14 * 86400

_MISSING = object()
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}")


class TTLCache:
    """Tiny JSON cache: {"_v": 2, "entries": {key: {"ts": epoch, "data": ...}}}."""

    def __init__(self, path, ttl):
        self.path = Path(path)
        self.ttl = ttl
        self.entries = {}
        self.dirty = False
        try:
            d = json.loads(self.path.read_text(encoding="utf-8"))
            if isinstance(d, dict) and d.get("_v") == 2 and isinstance(d.get("entries"), dict):
                self.entries = d["entries"]
        except Exception:
            pass

    def get(self, key, stale_ok=False):
        e = self.entries.get(key)
        if not isinstance(e, dict):
            return _MISSING
        if stale_ok or (time.time() - float(e.get("ts", 0))) <= self.ttl:
            return e.get("data")
        return _MISSING

    def put(self, key, data):
        self.entries[key] = {"ts": int(time.time()), "data": data}
        self.dirty = True

    def save(self):
        if not self.dirty:
            return
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text(json.dumps({"_v": 2, "entries": self.entries},
                                            ensure_ascii=False), encoding="utf-8")
            self.dirty = False
        except Exception as e:
            print(f"Cannot save cache {self.path.name}: {e}")


def _http_json(url, data=None, headers=None, timeout=60, retries=3):
    """GET/POST JSON with retry on rate-limit / transient errors."""
    hdrs = dict(UA_HEADERS)
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


def resolve_nvd_key(cli_value=None):
    """NVD API key: --nvd-key > NVD_API_KEY env > settings.json NVD_API_KEY."""
    import os
    key = (cli_value or os.environ.get("NVD_API_KEY") or "").strip()
    if key:
        return key
    try:
        d = json.loads((get_app_dir() / "settings.json").read_text(encoding="utf-8-sig"))
        return str(d.get("NVD_API_KEY") or "").strip()
    except Exception:
        return ""


def _nvd_headers(api_key):
    # NVD requires the key as an HTTP header (a URL parameter is ignored).
    return {"apiKey": api_key} if api_key else {}


def nvd_search(query, api_key=None, results=10, timeout=30):
    params = {"keywordSearch": query, "resultsPerPage": results}
    return _http_json(NVD_URL + "?" + urllib.parse.urlencode(params),
                      headers=_nvd_headers(api_key), timeout=timeout)


def nvd_fetch_cpe(cpe, api_key=None, timeout=60, max_pages=30):
    """ALL CVEs whose applicability matches the (partial) CPE, paginated.

    virtualMatchString accepts a partial CPE such as 'cpe:2.3:a:google:chrome'
    (cpeName needs a full 13-field name). Returns the raw 'vulnerabilities' list.
    """
    out, start, pages = [], 0, 0
    delay = NVD_DELAY_KEY if api_key else NVD_DELAY
    while pages < max_pages:
        params = {"virtualMatchString": cpe, "resultsPerPage": NVD_PAGE_SIZE,
                  "startIndex": start}
        raw = _http_json(NVD_URL + "?" + urllib.parse.urlencode(params),
                         headers=_nvd_headers(api_key), timeout=timeout)
        vulns = raw.get("vulnerabilities") or []
        out.extend(vulns)
        pages += 1
        total = int(raw.get("totalResults") or 0)
        start += len(vulns)
        if not vulns or start >= total:
            break
        time.sleep(delay)
    return out


def nvd_fetch_cve(cve_id, api_key=None, timeout=30):
    raw = _http_json(NVD_URL + "?" + urllib.parse.urlencode({"cveId": cve_id}),
                     headers=_nvd_headers(api_key), timeout=timeout)
    v = raw.get("vulnerabilities") or []
    return v[0].get("cve", {}) if v else {}


def cvss_of(cve):
    """Best base score from an NVD CVE object: v3.1 > v3.0 > v4.0 > v2,
    NVD 'Primary' analysis preferred over CNA 'Secondary'."""
    metrics = (cve.get("metrics") or {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40"):
        entries = sorted(metrics.get(key) or [],
                         key=lambda m: 0 if str(m.get("type", "")).lower() == "primary" else 1)
        for m in entries:
            d = m.get("cvssData") or {}
            if d.get("baseScore") is not None:
                return float(d["baseScore"]), d.get("baseSeverity", "")
    for m in metrics.get("cvssMetricV2") or []:
        d = m.get("cvssData") or {}
        if d.get("baseScore") is not None:
            return float(d["baseScore"]), "via v2"
    return 0.0, ""


def _cvss_roundup(v):
    """FIRST CVSS v3.1 Roundup: smallest 1-decimal number >= input."""
    scaled = v * 100000.0
    if float(int(scaled)) == scaled:
        return round(v, 1)
    return (math.floor(scaled / 10000.0) + 1) / 10.0


def cvss_v3_base_score(vector):
    """Numeric base score (0.0-10.0) from a CVSS v3.x vector string.

    Implements FIRST CVSS v3.1 equations. Returns None for missing,
    malformed, or non-v3 vectors (e.g. CVSS v4, which OSV may also emit).
    """
    try:
        parts = str(vector or "").strip().split("/")
        if len(parts) < 2 or not parts[0].startswith("CVSS:3."):
            return None
        m = {}
        for p in parts[1:]:
            if ":" in p:
                k, v = p.split(":", 1)
                m[k.strip()] = v.strip()
        changed = m.get("S") == "C"
        av = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}[m["AV"]]
        ac = {"L": 0.77, "H": 0.44}[m["AC"]]
        if changed:
            pr = {"N": 0.85, "L": 0.68, "H": 0.5}[m["PR"]]
        else:
            pr = {"N": 0.85, "L": 0.62, "H": 0.27}[m["PR"]]
        ui = {"N": 0.85, "R": 0.62}[m["UI"]]
        c = {"H": 0.56, "L": 0.22, "N": 0.0}[m["C"]]
        i = {"H": 0.56, "L": 0.22, "N": 0.0}[m["I"]]
        a = {"H": 0.56, "L": 0.22, "N": 0.0}[m["A"]]
    except (KeyError, ValueError, AttributeError):
        return None
    iss = 1.0 - (1.0 - c) * (1.0 - i) * (1.0 - a)
    if not changed:
        impact = 6.42 * iss
    elif iss <= 0:
        return 0.0
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.029) ** 15)
    exploit = 8.22 * av * ac * pr * ui
    if impact <= 0:
        return 0.0
    raw = min(impact + exploit, 10.0) if not changed \
        else min(1.08 * (impact + exploit), 10.0)
    return _cvss_roundup(raw)


# ---- NVD CPE version-range matching (Windows/desktop apps) ----
NVD_CPE = {
    "google chrome": ["cpe:2.3:a:google:chrome"],
    "microsoft edge": ["cpe:2.3:a:microsoft:edge_chromium", "cpe:2.3:a:microsoft:edge"],
    "mozilla firefox": ["cpe:2.3:a:mozilla:firefox"],
    "mozilla thunderbird": ["cpe:2.3:a:mozilla:thunderbird"],
    "opera": ["cpe:2.3:a:opera:opera_browser"],
    "adobe acrobat": ["cpe:2.3:a:adobe:acrobat", "cpe:2.3:a:adobe:acrobat_reader"],
    "adobe reader": ["cpe:2.3:a:adobe:acrobat_reader", "cpe:2.3:a:adobe:acrobat"],
    "java": ["cpe:2.3:a:oracle:jdk", "cpe:2.3:a:oracle:jre"],
    "python": ["cpe:2.3:a:python:python"],
    "vlc media player": ["cpe:2.3:a:videolan:vlc_media_player"],
    "7-zip": ["cpe:2.3:a:7-zip:7-zip"],
    "winrar": ["cpe:2.3:a:rarlab:winrar"],
    "notepad++": ["cpe:2.3:a:notepad-plus-plus:notepad\\+\\+"],
    "teamviewer": ["cpe:2.3:a:teamviewer:teamviewer"],
    "anydesk": ["cpe:2.3:a:anydesk:anydesk"],
    "putty": ["cpe:2.3:a:putty:putty"],
    "winscp": ["cpe:2.3:a:winscp:winscp"],
    "wireshark": ["cpe:2.3:a:wireshark:wireshark"],
    "git": ["cpe:2.3:a:git-scm:git"],
    "libreoffice": ["cpe:2.3:a:libreoffice:libreoffice"],
    "vmware workstation": ["cpe:2.3:a:vmware:workstation"],
}


def get_cpe_map(rules=None):
    """Built-in map + optional vuln_rules.json 'cpe_map': {"family or name": [cpe, ...]}."""
    m = {k: list(v) for k, v in NVD_CPE.items()}
    extra = (rules or {}).get("cpe_map") or {}
    for k, v in extra.items():
        if isinstance(v, str):
            v = [v]
        if isinstance(v, list) and v:
            m[str(k).strip().lower()] = [str(x) for x in v]
    return m


def cpe_key_for(it, cpe_map):
    """Which cpe_map entry applies to an item (family, exact name, or 'name <ver>')."""
    norm = normalize_name(it.get("name"))
    if _is_python_lib(norm):
        return None
    fam = it.get("family")
    if fam in cpe_map:
        return fam
    if norm in cpe_map:
        return norm
    for key in cpe_map:
        if " " in key and norm.startswith(key + " "):
            return key
    return None


def _nvd_usable(cve):
    if str(cve.get("vulnStatus", "")).lower() == "rejected":
        return False
    for d in cve.get("descriptions") or []:
        if d.get("lang") == "en" and str(d.get("value", "")).startswith("** REJECT"):
            return False
    return True


def _brief_nvd_cve(cve, cpe_prefix=None):
    sc, _sev = cvss_of(cve)
    matches = []
    for conf in cve.get("configurations") or []:
        for node in conf.get("nodes") or []:
            if node.get("negate"):
                continue
            for m in node.get("cpeMatch") or []:
                if m.get("negate") or not m.get("vulnerable", True):
                    continue
                crit = m.get("criteria", "")
                if cpe_prefix and not str(crit).startswith(cpe_prefix + ":"):
                    continue
                matches.append({"criteria": crit,
                                "versionStartIncluding": m.get("versionStartIncluding"),
                                "versionStartExcluding": m.get("versionStartExcluding"),
                                "versionEndIncluding": m.get("versionEndIncluding"),
                                "versionEndExcluding": m.get("versionEndExcluding")})
    return {"id": cve.get("id", "?"), "cvss": sc or None,
            "published": (cve.get("published") or "")[:10],
            "kev": bool(cve.get("cisaExploitAdd")), "match": matches}


def _nvd_range_hit(criteria, m, installed):
    """True if installed version is inside the CPE match range, False if
    outside, None when the entry states no usable version info."""
    parts = str(criteria or "").split(":")
    embedded = parts[5] if len(parts) > 5 else "*"
    update = parts[6] if len(parts) > 6 else "*"
    si, sx, ei, ex = (m.get("versionStartIncluding"), m.get("versionStartExcluding"),
                      m.get("versionEndIncluding"), m.get("versionEndExcluding"))
    if not any([si, sx, ei, ex]):
        if embedded in ("*", "-", ""):
            return None
        if update not in ("*", "-", ""):   # beta/rc/update builds: not comparable
            return None
        try:
            return cmp_versions(parse_version_cached(installed),
                                parse_version_cached(embedded)) == 0
        except Exception:
            return None
    try:
        vp = parse_version_cached(installed)
        if si and cmp_versions(vp, parse_version_cached(si)) < 0:
            return False
        if sx and cmp_versions(vp, parse_version_cached(sx)) <= 0:
            return False
        if ei and cmp_versions(vp, parse_version_cached(ei)) > 0:
            return False
        if ex and cmp_versions(vp, parse_version_cached(ex)) >= 0:
            return False
    except Exception:
        return None
    return True


def _add_cve(it, entry):
    cves = it.setdefault("cves", [])
    for c in cves:
        if isinstance(c, dict) and c.get("id") == entry["id"]:
            if entry.get("cvss") and not c.get("cvss"):
                c["cvss"] = entry["cvss"]
            return
    cves.append(entry)


def enrich_nvd_cpe(items, rules=None, api_key=None, cache_file=None, online=True, fetcher=None):
    """Confirmed CVEs from NVD CPE ranges. A CVE counts only when its stated
    version range contains the installed version. Offline -> reads the cache."""
    cache = TTLCache(cache_file or cache_path("nvd_cache_v2.json"), TTL_NVD)
    cpe_map = get_cpe_map(rules)
    keyed = [(it, k) for it in (items or []) for k in [cpe_key_for(it, cpe_map)] if k]
    fetch = fetcher or (lambda cpe: nvd_fetch_cpe(cpe, api_key))
    pause = 0 if fetcher else (NVD_DELAY_KEY if api_key else NVD_DELAY)

    cpe_data = {}
    for cpe in sorted({c for _, k in keyed for c in cpe_map[k]}):
        key = f"cpe::{cpe}"
        cur = cache.get(key, stale_ok=not online)
        if cur is _MISSING and online:
            try:
                raw = fetch(cpe)
                cur = [_brief_nvd_cve(v.get("cve", v), cpe) for v in raw
                       if _nvd_usable(v.get("cve", v))]
                cache.put(key, cur)
                print(f"  NVD {cpe}: {len(cur)} CVE(s)")
            except Exception as e:
                print(f"  NVD {cpe} failed ({e}) - using stale cache if any")
                cur = cache.get(key, stale_ok=True)
            if pause:
                time.sleep(pause)
        cpe_data[cpe] = None if cur is _MISSING else cur
    cache.save()

    for it, k in keyed:
        ver = str(it.get("version") or "").strip()
        if not ver:
            continue
        hits, have_data = {}, False
        for cpe in cpe_map[k]:
            lst = cpe_data.get(cpe)
            if not lst:
                continue
            have_data = True
            for cve in lst:
                cid = cve.get("id")
                if not cid or cid in hits:
                    continue
                for m in cve.get("match", []):
                    if not str(m.get("criteria", "")).startswith(cpe + ":"):
                        continue
                    if _nvd_range_hit(m["criteria"], m, ver) is True:
                        hits[cid] = cve
                        break
        it["nvd_checked"] = have_data
        for cid, cve in sorted(hits.items(), key=lambda kv: -(kv[1].get("cvss") or 0))[:25]:
            _add_cve(it, {"id": cid, "cvss": cve.get("cvss"), "published": cve.get("published", ""),
                          "kev": bool(cve.get("kev")), "src": "nvd"})
        it["cve_total"] = max(it.get("cve_total", 0), len(hits))
    return items


# ---- OSV.dev (Linux distro packages): version-aware ----
_OSV_TEXT_SEV = {"critical": 9.0, "high": 7.5, "medium": 5.0, "moderate": 5.0,
                 "low": 2.5, "negligible": 0.5}

_SRC_RULES = (
    (re.compile(r"^linux-(?:image|headers|modules|tools|buildinfo|libc-dev)"), "linux"),
    (re.compile(r"^(?:libssl\d|libssl-dev|openssl)"), "openssl"),
    (re.compile(r"^(?:libc6|libc-bin|libc-dev-bin|locales)"), "glibc"),
    (re.compile(r"^libcurl\d"), "curl"),
    (re.compile(r"^openssh-"), "openssh"),
    (re.compile(r"^libgnutls\d+"), "gnutls28"),
    (re.compile(r"^libsqlite3"), "sqlite3"),
    (re.compile(r"^apache2-"), "apache2"),
    (re.compile(r"^(?:libkrb5-|libgssapi-krb5|krb5-)"), "krb5"),
    (re.compile(r"^(?:lib)?(python3\.\d+)"), r"\1"),
)

_UBU_RE = re.compile(r"ubuntu\D{0,25}?(\d{2}\.\d{2})")
_DEB_RE = re.compile(r"debian\D{0,30}?(\d{1,2})\b")


def osv_ecosystem_for_os(os_name):
    """OSV ecosystem from the host OS string ('Ubuntu 22.04.3 LTS' -> 'Ubuntu:22.04:LTS')."""
    s = str(os_name or "").lower()
    m = _UBU_RE.search(s)
    if m:
        rel = m.group(1)
        lts = rel.endswith(".04") and int(rel[:2]) % 2 == 0
        return f"Ubuntu:{rel}:LTS" if lts else f"Ubuntu:{rel}"
    m = _DEB_RE.search(s)
    if m:
        return f"Debian:{m.group(1)}"
    return None


def _osv_name_variants(name, rules=None):
    """OSV Debian/Ubuntu records use SOURCE package names; inventory gives binary names."""
    ln = str(name or "").strip().lower()
    out = [ln] if ln else []
    m = re.match(r"^python3?[-_](.+)$", ln)
    if m and m.group(1) not in out:
        out.append(m.group(1))
    custom = ((rules or {}).get("linux_source_map") or {}).get(ln)
    if custom and custom not in out:
        out.append(str(custom))
    for rx, tmpl in _SRC_RULES:
        mm = rx.match(ln)
        if mm:
            src = mm.expand(tmpl)
            if src not in out:
                out.append(src)
            break
    return out[:3]


def _osv_ecosystems(version, hints=None):
    """Ecosystems to query. Prefer the real distro of the hosts (hints)."""
    if hints:
        return list(hints)[:3]
    v = str(version or "").lower()
    if not v:
        return []
    if ".el" in v or "rhel" in v or "rocky" in v or "alma" in v or "suse" in v:
        return []
    if "ubuntu" in v:
        return ["Ubuntu:24.04:LTS", "Ubuntu:22.04:LTS", "Ubuntu:20.04:LTS"]
    return ["Debian:12", "Debian:11", "Ubuntu:22.04:LTS", "Ubuntu:24.04:LTS"]


def _osv_post(batch, timeout=60):
    return _http_json(OSV_URL, data={"queries": batch}, timeout=timeout)


def _osv_get(vuln_id, timeout=30):
    return _http_json(OSV_VULN_URL + urllib.parse.quote(str(vuln_id), safe=""), timeout=timeout)


def _osv_cvss(vuln):
    """(score|None, approx_flag) from an OSV record's top-level severity."""
    best, text = None, None
    for sev in vuln.get("severity", []) or []:
        typ = str(sev.get("type", "")).upper()
        if typ.startswith("CVSS_V3"):
            s = cvss_v3_base_score(sev.get("score", ""))
            if s is not None and (best is None or s > best):
                best = s
        else:
            t = str(sev.get("score", "")).strip().lower()
            if t in _OSV_TEXT_SEV:
                text = max(text or 0.0, _OSV_TEXT_SEV[t])
    if best is not None:
        return best, False
    t = str(((vuln.get("database_specific") or {}).get("severity", ""))).strip().lower()
    if t in _OSV_TEXT_SEV:
        text = max(text or 0.0, _OSV_TEXT_SEV[t])
    if text is not None:
        return text, True
    return None, False


def _brief_osv_full(v):
    ids = set()
    for s in [v.get("id", "")] + list(v.get("aliases") or []) + \
            list(v.get("upstream") or []) + list(v.get("related") or []):
        ids.update(_CVE_RE.findall(str(s)))
    sc, approx = _osv_cvss(v)
    per_cve = {}
    # Ubuntu USN records carry per-CVE severity in affected[].database_specific.cves_map
    for aff in v.get("affected") or []:
        cm = (aff.get("database_specific") or {}).get("cves_map")
        for block in ([cm] if isinstance(cm, dict) else (cm or [])):
            for c in (block or {}).get("cves", []) or []:
                s, _a = _osv_cvss({"severity": c.get("severity")})
                if s is not None and c.get("id"):
                    per_cve[c["id"]] = max(per_cve.get(c["id"], 0.0), s)
                    ids.add(c["id"])
    return {"id": v.get("id", "?"), "cves": sorted(ids)[:30], "cvss": sc, "approx": approx,
            "per_cve": per_cve, "published": (v.get("published") or "")[:10]}


def enrich_osv(data, items, online=True, cache_file=None, fetcher=None, detail_fetcher=None,
               rules=None):
    """OSV enrichment for Linux-seen software (adds confirmed CVEs, never changes the score).

    1) querybatch -> advisory IDs (only id/modified come back)
    2) GET /v1/vulns/{id} for each unique ID -> severity + CVE aliases
    Offline -> reads both caches.
    """
    cf = Path(cache_file) if cache_file else cache_path("osv_cache_v2.json")
    qcache = TTLCache(cf, TTL_OSV)
    dcache = TTLCache(cf.with_name(cf.stem + "_vulns.json"), TTL_OSV_VULN)
    fetch = fetcher or _osv_post
    get_one = detail_fetcher or _osv_get

    item_keys, missing, seen = {}, [], set()
    for idx, it in enumerate(items or []):
        if "linux" not in (it.get("os") or []):
            continue
        ver = str(it.get("version") or "").strip()
        if not ver:
            continue
        keys = []
        for variant in _osv_name_variants(it.get("name"), rules):
            for eco in _osv_ecosystems(ver, it.get("eco_hints")):
                key = f"{eco}|{variant}|{ver}"
                keys.append(key)
                if qcache.get(key, stale_ok=not online) is _MISSING and key not in seen:
                    seen.add(key)
                    missing.append((key, {"package": {"name": variant, "ecosystem": eco},
                                          "version": ver}))
        if keys:
            item_keys[idx] = keys

    if online and missing:
        print(f"OSV: {len(missing)} package queries for {len(item_keys)} linux items")
        for off in range(0, len(missing), OSV_BATCH):
            chunk = missing[off:off + OSV_BATCH]
            try:
                results = fetch([q for _, q in chunk]).get("results", [])
            except Exception as e:
                print(f"  OSV batch failed ({e}) - keeping what we have")
                break
            for (key, q), r in zip(chunk, results):
                ids = [v.get("id") for v in (r.get("vulns") or []) if v.get("id")]
                tok, pages = r.get("next_page_token"), 0
                while tok and pages < 5:        # a few queries may be paginated
                    try:
                        r2 = fetch([dict(q, page_token=tok)]).get("results", [{}])[0]
                    except Exception:
                        break
                    ids += [v.get("id") for v in (r2.get("vulns") or []) if v.get("id")]
                    tok, pages = r2.get("next_page_token"), pages + 1
                qcache.put(key, list(dict.fromkeys(ids)))
        qcache.save()

    all_ids = set()
    for keys in item_keys.values():
        for key in keys:
            v = qcache.get(key, stale_ok=True)
            if v is not _MISSING:
                all_ids.update(v or [])
    need = [i for i in sorted(all_ids) if dcache.get(i, stale_ok=not online) is _MISSING]
    if online and need:
        print(f"OSV: fetching {len(need)} advisory records")

        def _one(vid):
            try:
                return vid, _brief_osv_full(get_one(vid))
            except Exception:
                return vid, None
        with ThreadPoolExecutor(max_workers=8) as ex:
            for vid, brief in ex.map(_one, need):
                if brief is not None:
                    dcache.put(vid, brief)
        dcache.save()

    for idx, keys in item_keys.items():
        it = items[idx]
        found = {}
        for key in keys:
            ids = qcache.get(key, stale_ok=True)
            if ids is _MISSING:
                continue
            it["osv_checked"] = True
            for vid in ids or []:
                b = dcache.get(vid, stale_ok=True)
                if b is _MISSING or not b:
                    b = {"id": vid, "cves": _CVE_RE.findall(vid), "cvss": None,
                         "approx": False, "per_cve": {}, "published": ""}
                for t in (b.get("cves") or [vid]):
                    cv = (b.get("per_cve") or {}).get(t) or b.get("cvss")
                    prev = found.get(t)
                    if prev is None or (cv or 0) > (prev.get("cvss") or 0):
                        found[t] = {"id": t, "cvss": cv, "published": b.get("published", ""),
                                    "advisory": vid, "src": "osv",
                                    "approx": bool(b.get("approx"))}
        for e in sorted(found.values(), key=lambda e: -(e.get("cvss") or 0))[:25]:
            _add_cve(it, e)
        it["cve_total"] = max(it.get("cve_total", 0), len(found))
    return items


# ---- EPSS (FIRST.org): probability a CVE is exploited in the next 30 days ----
def fetch_epss(cve_ids, online=True, cache_file=None, fetcher=None):
    """-> {cve: {"epss": float|None, "pct": float|None}}. Offline reads the cache."""
    cache = TTLCache(cache_file or cache_path("epss_cache_v2.json"), TTL_EPSS)
    out, need = {}, []
    for c in cve_ids:
        v = cache.get(c, stale_ok=not online)
        if v is _MISSING:
            need.append(c)
        else:
            out[c] = v
    if online and need:
        print(f"EPSS: {len(need)} CVE(s)")
        for off in range(0, len(need), EPSS_BATCH):
            chunk = need[off:off + EPSS_BATCH]
            try:
                if fetcher:
                    raw = fetcher(chunk)
                else:
                    raw = _http_json(EPSS_URL + "?" + urllib.parse.urlencode(
                        {"cve": ",".join(chunk)}, safe=","))
                got = {d["cve"]: {"epss": float(d["epss"]), "pct": float(d.get("percentile") or 0)}
                       for d in raw.get("data", []) if d.get("cve")}
            except Exception as e:
                print(f"  EPSS batch failed ({e})")
                continue
            for c in chunk:
                v = got.get(c) or {"epss": None, "pct": None}
                cache.put(c, v)
                out[c] = v
        cache.save()
    return out


def build_kev_map(kev_list):
    return {e.get("cveID"): e for e in (kev_list or []) if e.get("cveID")}


def resolve_missing_cvss(items, api_key=None, online=True, limit=None, epss_map=None,
                         kev_map=None, cache_file=None, fetcher=None):
    """Fill CVSS for CVEs that came without one (typical for Debian/Ubuntu OSV records)
    using NVD ?cveId=. Bounded per run (NVD is rate limited); KEV/high-EPSS first."""
    cache = TTLCache(cache_file or cache_path("nvd_cve_cache_v2.json"), TTL_CVE)
    need = {}
    for it in items or []:
        for c in it.get("cves") or []:
            if isinstance(c, dict) and not c.get("cvss") and str(c.get("id", "")).startswith("CVE-"):
                need.setdefault(c["id"], []).append(c)
    if not need:
        return
    todo = [cid for cid in need if cache.get(cid, stale_ok=not online) is _MISSING]
    if online and todo:
        epss_map, kev_map = epss_map or {}, kev_map or {}
        todo.sort(key=lambda c: (c not in kev_map, -((epss_map.get(c) or {}).get("epss") or 0.0)))
        cap = limit if limit is not None else (300 if api_key else 25)
        fetch = fetcher or (lambda cid: nvd_fetch_cve(cid, api_key))
        pause = 0 if fetcher else (NVD_DELAY_KEY if api_key else NVD_DELAY)
        done = 0
        for cid in todo[:cap]:
            try:
                cve = fetch(cid)
                sc, _ = cvss_of(cve)
                cache.put(cid, {"cvss": sc or None})
            except Exception as e:
                print(f"  NVD {cid} failed ({e})")
            done += 1
            if pause:
                time.sleep(pause)
        print(f"NVD CVSS lookup: {done} resolved, {max(0, len(todo) - done)} left "
              f"(provisional score used; raise --cvss-lookups or add an API key)")
        cache.save()
    for cid, lst in need.items():
        v = cache.get(cid, stale_ok=True)
        if v is not _MISSING and v and v.get("cvss"):
            for c in lst:
                c["cvss"] = v["cvss"]


# ---- Composite risk model ----
def cve_risk(cvss, kev=False, epss=None):
    """Risk 0-10 for ONE confirmed CVE.

    base      = CVSS (provisional when unknown: 3.5 / 5.0 / 6.5 by EPSS)
    KEV       = actively exploited -> at least 9.5
    EPSS      >= 0.5: +1.0 | >= 0.1: +0.5 | < 0.01 with CVSS >= 7: -0.5
    """
    if cvss:
        base = float(cvss)
    elif epss is None:
        base = 5.0
    else:
        base = 6.5 if epss >= 0.1 else (3.5 if epss < 0.01 else 5.0)
    s = base
    if kev:
        s = max(base + 1.0, 9.5)
    if cvss and epss is not None:
        if epss >= 0.5:
            s += 1.0
        elif epss >= 0.1:
            s += 0.5
        elif epss < 0.01 and base >= 7.0 and not kev:
            s -= 0.5
    return round(max(0.0, min(10.0, s)), 1)


_EVIDENCE_RANK = {"confirmed": 3, "name-match": 2, "rule": 1, "none": 0}


def apply_risk_model(items, kev_map=None, epss_map=None):
    """Single place where the final score is computed.

    score = max(rule score, worst confirmed CVE risk, floor)
      * rule score  : EOL (kept) / outdated-version rules. When NVD has data for the
                      product and NO CVE affects this version, 'outdated' is capped at 6.
      * CVE risk    : cve_risk() per CVE (CVSS + KEV + EPSS) + up to +0.5 for several High CVEs.
      * name-only KEV (no version proof) lifts at most to 9, never to 10.
    Also sets max_cvss, max_epss, kev, evidence and an exposure-weighted priority.
    """
    kev_map, epss_map = kev_map or {}, epss_map or {}
    for it in items or []:
        comp = it.get("components") or {}
        eol = float(comp.get("eol", 0))
        outdated = float(comp.get("outdated", 0))
        floor = float(comp.get("floor", 0))
        base_reasons = it.setdefault("base_reasons", list(it.get("reasons") or []))
        base_action = it.setdefault("base_action", it.get("action", "-"))
        reasons = list(base_reasons)
        actions = [] if base_action in ("-", "", None) else [base_action]

        conf = [c for c in (it.get("cves") or [])
                if isinstance(c, dict) and c.get("src") in ("nvd", "osv")]
        for c in conf:
            cid = c.get("id")
            c["kev"] = bool(kev_map.get(cid)) or bool(c.get("kev"))
            e = epss_map.get(cid) or {}
            c["epss"] = e.get("epss")
            c["risk"] = cve_risk(c.get("cvss"), c["kev"], c["epss"])
        conf.sort(key=lambda c: (-c["risk"], not c["kev"], -(c.get("cvss") or 0)))

        cve_s = 0.0
        if conf:
            top = conf[0]
            cve_s = top["risk"]
            n_high = sum(1 for c in conf if c["risk"] >= 7.0)
            if n_high >= 2:
                cve_s = min(10.0, cve_s + min(0.5, 0.1 * (n_high - 1)))
            tags = []
            tags.append(f"CVSS {top['cvss']}" if top.get("cvss") else "CVSS n/a (provisional)")
            if top["kev"]:
                tags.append("CISA KEV - actively exploited")
            if top.get("epss") is not None:
                tags.append(f"EPSS {top['epss'] * 100:.1f}%")
            more = f" +{len(conf) - 1} more ({n_high} High/Critical)" if len(conf) > 1 else ""
            reasons.append(f"{str(top.get('src', '')).upper()}: {top['id']} ({', '.join(tags)}) "
                           f"affects {it.get('name')} {it.get('version')}{more}")
            if top["kev"]:
                actions.append("Patch immediately (actively exploited in the wild)")
            else:
                actions.append(f"Upgrade to a release that fixes {top['id']}"
                               + (f" and {len(conf) - 1} other CVE(s)" if len(conf) > 1 else ""))

        if not conf and it.get("nvd_checked") and outdated > 6:
            outdated = 6.0
            reasons.append("NVD: no known CVE affects this exact version - "
                           "'outdated version' score capped at 6")

        rule_s = max(eol, outdated)
        kev_name = bool(comp.get("kev_name"))
        lifted = False
        if kev_name:
            if rule_s >= 7 and rule_s < 9.0:
                rule_s, lifted = 9.0, True
            elif rule_s == 0:
                rule_s, lifted = 3.0, True

        score = round(max(rule_s, cve_s, floor), 1)
        if conf:
            evidence = "confirmed"
        elif lifted:
            evidence = "name-match"
        elif score > 0:
            evidence = "rule"
        else:
            evidence = "none"

        hosts = max(1, len(it.get("hosts") or []))
        exposure = min(1.0, 0.5 * math.log10(hosts)) if score >= 4 else 0.0
        it["score"] = score
        it["level"] = level_of(score)
        it["reasons"] = reasons
        it["action"] = "; ".join(dict.fromkeys(actions)) if actions else \
            ("Update to a supported version" if score > 0 else "-")
        it["max_cvss"] = max([c["cvss"] for c in conf if c.get("cvss")] or [0.0]) or None
        it["max_epss"] = max([c["epss"] for c in conf if c.get("epss") is not None] or [None]) \
            if any(c.get("epss") is not None for c in conf) else None
        it["kev"] = any(c["kev"] for c in conf)
        it["evidence"] = evidence
        it["priority"] = round(min(10.0, score + exposure), 1)
    return items


def enrich_all(items, rules, online=True, api_key=None, kev=None, cvss_lookups=None,
               fetchers=None):
    """Run every source (cache-only when offline), then compute final scores."""
    fx = fetchers or {}
    enrich_nvd_cpe(items, rules, api_key=api_key, online=online, fetcher=fx.get("nvd"))
    enrich_osv(None, items, online=online, fetcher=fx.get("osv"),
               detail_fetcher=fx.get("osv_vuln"), rules=rules)
    cve_ids = sorted({c["id"] for it in items for c in (it.get("cves") or [])
                      if isinstance(c, dict) and str(c.get("id", "")).startswith("CVE-")})
    epss_map = fetch_epss(cve_ids, online=online, fetcher=fx.get("epss"))
    kev_map = build_kev_map(kev)
    resolve_missing_cvss(items, api_key=api_key, online=online, limit=cvss_lookups,
                         epss_map=epss_map, kev_map=kev_map, fetcher=fx.get("cve"))
    apply_risk_model(items, kev_map, epss_map)
    items.sort(key=lambda x: (-x["score"], -x["count"], x["name"]))
    return items


def find_eol_hosts(data, rules):
    """Hosts whose OS matches EOL list (or empty OS). Returns list of dicts."""
    eol_entries = [e for e in (rules.get("eol_os") or [])] + \
                  [e for e in (rules.get("upstream_eol") or []) if e.get("kind", "os") == "os"]
    out = []
    for h in data.get("hosts", []):
        info = h.get("host", {}) if isinstance(h.get("host"), dict) else {}
        os_name = str(info.get("os") or "")
        low = normalize_name(os_name)
        hit = next((e for e in eol_entries if _eol_entry_matches(low, "", e)), None)
        if hit or not low:
            out.append({"ip": str(info.get("ip") or "").strip() or (info.get("display_name") or "?"),
                        "name": info.get("display_name") or info.get("dn") or "?",
                        "os": os_name or "(unknown)",
                        "label": hit["label"] if hit else "OS unknown",
                        "score": int(hit["score"]) if hit else 5})
    return out


def analyze(data, rules, kev=None):
    """Aggregate software across hosts and assess each (name, version).

    Each item also carries OS split info:
    - os: sorted list of OS categories where it was seen (windows/linux/other)
    - os_counts: {cat: install count}
    - hosts_by_os: {cat: [sample IPs/names]}
    """
    kev_index = build_kev_index(kev, rules) if kev else []
    norm_cache = {}
    agg = OrderedDict()
    for h in data.get("hosts", []):
        info = h.get("host", {}) if isinstance(h.get("host"), dict) else {}
        hid = str(info.get("ip") or "").strip().split(",")[0] or (info.get("display_name") or "?")
        os_cat = classify_os(info.get("os", ""))
        for sw in h.get("software", []):
            if not isinstance(sw, dict):
                continue
            name = str(sw.get("name") or "").strip()
            if not name:
                continue
            ver = str(sw.get("version") or "").strip()
            key = (name.lower(), ver)
            e = agg.get(key)
            if e is None:
                e = agg[key] = {"name": name, "version": ver,
                                "publisher": str(sw.get("publisher") or "").strip(),
                                "count": 0, "hosts": [],
                                "os_counts": {"windows": 0, "linux": 0, "other": 0},
                                "hosts_by_os": {"windows": [], "linux": [], "other": []},
                                "eco_set": set()}
            e["count"] += 1
            if hid not in e["hosts"]:
                e["hosts"].append(hid)
            e["os_counts"][os_cat] += 1
            if os_cat == "linux":
                eco = osv_ecosystem_for_os(info.get("os", ""))
                if eco:
                    e["eco_set"].add(eco)
            if hid not in e["hosts_by_os"][os_cat]:
                e["hosts_by_os"][os_cat].append(hid)
    items = []
    for (nl, ver), e in agg.items():
        r = assess(e["name"], ver, e["publisher"], rules, kev_index)
        nn = norm_cache.get(nl)
        if nn is None:
            nn = norm_cache[nl] = normalize_name(e["name"], rules)
        os_list = sorted([c for c, n in e["os_counts"].items() if n > 0])
        eco_hints = sorted(e.pop("eco_set"))
        items.append({**e, "family": family_of(nn, rules),
                      "os": os_list, "eco_hints": eco_hints,
                      "score": r["score"], "level": r["level"],
                      "reasons": r["reasons"], "action": r["action"], "cves": [],
                      "components": r.get("components", {})})
    items.sort(key=lambda x: (-x["score"], -x["count"], x["name"]))
    return items


def summarize(items, eol_hosts, total_hosts):
    by_level = {}
    for it in items:
        by_level[it["level"]] = by_level.get(it["level"], 0) + 1
    hosts_at_risk = len({ip for it in items if it["score"] >= 7 for ip in it["hosts"]} | {h["ip"] for h in eol_hosts})
    return {"total_hosts": total_hosts, "unique_software": len(items),
            "by_level": by_level,
            "critical_high_items": sum(1 for it in items if it["score"] >= 7),
            "confirmed_cve_items": sum(1 for it in items if it.get("evidence") == "confirmed"),
            "kev_items": sum(1 for it in items if it.get("kev")),
            "eol_hosts": len(eol_hosts), "hosts_at_risk": hosts_at_risk}


def _merge_by_software(items, cat):
    """Group items of one OS by software name (case-insensitive).

    One row per Software; Version cell holds all distinct versions sorted.
    Score = worst (max) across versions; hosts/reasons/actions = union.
    """
    groups = OrderedDict()
    for it in items:
        cats = it.get("os")
        if cats is not None and cat not in cats:
            continue
        key = str(it.get("name") or "").strip().lower()
        if not key:
            continue
        by_os_hosts = (it.get("hosts_by_os") or {}).get(cat)
        if by_os_hosts is None:  # backward compat: items without OS info
            hosts = list(it.get("hosts") or [])
        else:
            hosts = list(by_os_hosts)
            if not hosts:
                continue
        g = groups.get(key)
        if g is None:
            g = groups[key] = {
                "name": str(it.get("name") or "").strip(),
                "versions": [], "versions_set": set(),
                "publishers": [], "pub_set": set(),
                "score": 0, "hosts": [], "hosts_set": set(),
                "reasons": [], "reasons_set": set(),
                "actions": [], "actions_set": set(),
                "cves": [], "cves_set": set(),
                "max_cvss": None, "max_epss": None, "kev": False, "evidence": "none",
            }
        ver = str(it.get("version") or "").strip()
        if ver and ver not in g["versions_set"]:
            g["versions_set"].add(ver)
            g["versions"].append(ver)
        pub = str(it.get("publisher") or "").strip()
        if pub and pub not in g["pub_set"]:
            g["pub_set"].add(pub)
            g["publishers"].append(pub)
        try:
            sc = float(it.get("score", 0))
        except (TypeError, ValueError):
            sc = 0.0
        if sc > g["score"]:
            g["score"] = sc
        mc = it.get("max_cvss")
        if mc and (g["max_cvss"] is None or mc > g["max_cvss"]):
            g["max_cvss"] = mc
        me = it.get("max_epss")
        if me is not None and (g["max_epss"] is None or me > g["max_epss"]):
            g["max_epss"] = me
        g["kev"] = g["kev"] or bool(it.get("kev"))
        ev = it.get("evidence") or "none"
        if _EVIDENCE_RANK.get(ev, 0) > _EVIDENCE_RANK.get(g["evidence"], 0):
            g["evidence"] = ev
        for h in hosts:
            if h not in g["hosts_set"]:
                g["hosts_set"].add(h)
                g["hosts"].append(h)
        for r in (it.get("reasons") or []):
            if r not in g["reasons_set"]:
                g["reasons_set"].add(r)
                g["reasons"].append(r)
        act = it.get("action", "-")
        acts = [act] if isinstance(act, str) else list(act or [])
        for a in acts:
            a = (a or "").strip()
            if a and a != "-" and a not in g["actions_set"]:
                g["actions_set"].add(a)
                g["actions"].append(a)
        for c in (it.get("cves") or []):
            cid = c.get("id") if isinstance(c, dict) else c
            if cid and cid not in g["cves_set"]:
                g["cves_set"].add(cid)
                g["cves"].append(cid)

    def _vkey(v):
        t = parse_version_cached(v)
        if t:
            return (0, t, "")
        return (1, (), str(v).lower())

    merged = []
    for g in groups.values():
        g["versions"].sort(key=_vkey)
        merged.append(g)
    merged.sort(key=lambda g: (-g["score"], -len(g["hosts"]), g["name"].lower()))
    return merged


def _hosts_critical_by_os(data, items):
    """One row per host with only Critical/High software, grouped by OS."""
    lookup = {}
    for it in items or []:
        if it.get("level") not in ("Critical", "High"):
            continue
        key = (str(it.get("name") or "").strip().lower(),
               str(it.get("version") or "").strip())
        # keep worst score on collision
        prev = lookup.get(key)
        if prev is None or float(it.get("score", 0)) > float(prev.get("score", 0)):
            lookup[key] = it

    by_os = {"windows": [], "linux": [], "other": []}
    for h in (data or {}).get("hosts", []):
        info = h.get("host", {}) if isinstance(h.get("host"), dict) else {}
        ip = str(info.get("ip") or "").strip().split(",")[0] \
            or str(info.get("display_name") or info.get("dn") or "?")
        hostname = str(info.get("display_name") or info.get("dn") or "?")
        cat = classify_os(info.get("os", ""))
        risky = []
        for sw in h.get("software", []):
            if not isinstance(sw, dict):
                continue
            nm = str(sw.get("name") or "").strip()
            vr = str(sw.get("version") or "").strip()
            if not nm:
                continue
            it = lookup.get((nm.lower(), vr))
            if it is not None:
                risky.append((nm, vr, it))
        if not risky:
            continue
        risky.sort(key=lambda t: (-float(t[2].get("score", 0)), t[0].lower()))
        sw_list = "\n".join(f"{n} {v} [{r.get('level')}]" for n, v, r in risky)
        notes = "\n".join(
            f"{n} {v}: {' | '.join(list(r.get('reasons') or []) + [c.get('id') if isinstance(c, dict) else str(c) for c in (r.get('cves') or [])[:3]])}".strip()
            for n, v, r in risky)
        recs = "\n".join(f"{n} {v}: {r.get('action') or '-'}" for n, v, r in risky)
        by_os.get(cat, by_os["other"]).append([ip, hostname, sw_list, notes, recs])
    return by_os


METHOD_ROWS = [
    ("Score (0-10)", "max( rule score , worst confirmed-CVE risk , floor ). Levels: Critical >= 9, High >= 7, Medium >= 4, Low > 0."),
    ("Confirmed CVE", "A CVE whose NVD CPE version range contains the installed version (Windows/desktop apps) or an OSV advisory for the exact package version (Linux)."),
    ("CVE risk", "CVSS base score (v3.1 > v3.0 > v4.0 > v2). CISA KEV (exact CVE) -> at least 9.5. EPSS >= 50%: +1.0, >= 10%: +0.5, < 1% with CVSS >= 7: -0.5. Unknown CVSS -> provisional 3.5 / 5.0 / 6.5 by EPSS."),
    ("Several High CVEs", "+0.1 per extra High/Critical CVE, max +0.5."),
    ("Rule score", "EOL products/OS (kept as is) and outdated-version rules. If NVD has data for the product and no CVE affects this exact version, the outdated-version score is capped at 6."),
    ("Name-match KEV", "Product family appears in CISA KEV but no version proof: raised to at most 9, never 10."),
    ("Evidence", "confirmed = CVE proven for this version | rule = EOL / version rule only | name-match = KEV product family only."),
    ("Not covered", "Products without a CPE mapping (add them under 'cpe_map' in vuln_rules.json) and Linux packages whose binary name differs from the source package name. Absence of a CVE is not proof of safety."),
]


def _method_sheet(wb, hdr_font, hdr_fill, bd, center, left):
    ws = wb.create_sheet("Scoring Method")
    ws.append(["Topic", "How it is calculated"])
    for c in (1, 2):
        x = ws.cell(row=1, column=c)
        x.font, x.fill, x.alignment, x.border = hdr_font, hdr_fill, center, bd
    for r, (k, v) in enumerate(METHOD_ROWS, start=2):
        ws.cell(row=r, column=1, value=k).alignment = left
        ws.cell(row=r, column=2, value=v).alignment = left
        ws.cell(row=r, column=1).border = bd
        ws.cell(row=r, column=2).border = bd
        ws.row_dimensions[r].height = 48
    ws.column_dimensions["A"].width = 22
    ws.column_dimensions["B"].width = 110


def write_risk_excel(items, eol_hosts, summary, out, data=None):
    from openpyxl import Workbook
    from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
    wb = Workbook()
    hdr_font = Font(bold=True, color="FFFFFF")
    hdr_fill = PatternFill(start_color="C00000", end_color="C00000", fill_type="solid")
    thin = Side(style="thin", color="D9D9D9")
    bd = Border(left=thin, right=thin, top=thin, bottom=thin)
    center = Alignment(horizontal="center", vertical="center", wrap_text=True)
    left = Alignment(horizontal="left", vertical="center", wrap_text=True)
    fills = {lv: PatternFill(start_color=RISK_COLORS[lv], end_color=RISK_COLORS[lv], fill_type="solid")
             for lv in RISK_LEVELS}

    ws = wb.active
    ws.title = "Summary"
    ws.append(["Metric", "Value"])
    for c in range(1, 3):
        x = ws.cell(row=1, column=c)
        x.font = hdr_font
        x.fill = hdr_fill
        x.alignment = center
        x.border = bd
    # Items without OS info (legacy) are shown in every sheet so no data is lost.
    merged_by_os = {c: _merge_by_software(items, c)
                    for c in ("windows", "linux", "other")}
    by_os = {c: len(merged_by_os[c]) for c in merged_by_os}
    # Unique software names across all OS (same software on several OS counts once)
    _all_names = set()
    for c in merged_by_os:
        for g in merged_by_os[c]:
            _all_names.add(g["name"].strip().lower())
    merged_total = len(_all_names)
    rows = [("Generated", datetime.now(timezone.utc).isoformat(timespec="seconds")),
            ("Total hosts", summary["total_hosts"]),
            ("Unique software (name+version)", summary["unique_software"]),
            ("Unique software names", merged_total),
            ("Windows software", by_os["windows"]),
            ("Linux software", by_os["linux"]),
            ("Other software", by_os["other"]),
            ("Hosts at risk", summary["hosts_at_risk"]),
            ("EOL hosts", summary["eol_hosts"]),
            ("Items with confirmed CVE", summary.get("confirmed_cve_items", 0)),
            ("Items in CISA KEV (confirmed)", summary.get("kev_items", 0))] + \
        [(f"Items: {lv}", summary["by_level"].get(lv, 0)) for lv in RISK_LEVELS]
    for r, (k, v) in enumerate(rows, start=2):
        ws.cell(row=r, column=1, value=k).alignment = left
        ws.cell(row=r, column=2, value=v).alignment = center
        ws.cell(row=r, column=1).border = bd
        ws.cell(row=r, column=2).border = bd
    ws.column_dimensions["A"].width = 30
    ws.column_dimensions["B"].width = 42
    ws.row_dimensions[1].height = 22
    ws.freeze_panes = "A2"
    ws.sheet_properties.pageSetUpPr.fitToPage = True

    def _est_lines(text, width):
        """Estimate wrapped line count for a cell given column width."""
        s = "" if text is None else str(text)
        if not s:
            return 1
        per_line = max(10, int(width * 1.0))
        total = 0
        for seg in s.split("\n"):
            total += max(1, -(-len(seg) // per_line))
        return max(1, total)

    def _autofit_widths(headers, rows, base, caps, sample=2000):
        """Widen columns to fit content, within caps."""
        out_w = list(base)
        for c in range(len(headers)):
            mx = len(str(headers[c]))
            for row in rows[:sample]:
                v = row[c]
                if v is None:
                    continue
                for seg in str(v).split("\n"):
                    if len(seg) > mx:
                        mx = len(seg)
                    if mx >= caps[c]:
                        break
                if mx >= caps[c]:
                    break
            out_w[c] = min(caps[c], max(base[c], mx + 2))
        return out_w

    def dump(title, headers, rows, widths):
        caps = [50, 35, 30, 12, 8, 10, 80, 45, 10, 10, 8, 14]
        widths = _autofit_widths(headers, rows, widths, caps)
        w = wb.create_sheet(title)
        w.append(headers)
        for c in range(1, len(headers) + 1):
            x = w.cell(row=1, column=c)
            x.font = hdr_font
            x.fill = hdr_fill
            x.alignment = center
            x.border = bd
        w.row_dimensions[1].height = 22
        for r, row in enumerate(rows, start=2):
            top = 1
            for c, v in enumerate(row, start=1):
                cell = w.cell(row=r, column=c, value=v)
                cell.alignment = center if c in (2, 4, 5, 9, 10, 11, 12) else left
                cell.border = bd
                if headers[c - 1] == "Risk" and v in fills:
                    cell.fill = fills[v]
                if headers[c - 1] == "EPSS" and isinstance(v, (int, float)):
                    cell.number_format = "0.0%"
                top = max(top, _est_lines(v, widths[c - 1]))
            w.row_dimensions[r].height = min(180, max(15, 15 * top))
        for col, wd in zip("ABCDEFGHIJKL", widths):
            w.column_dimensions[col].width = wd
        w.freeze_panes = "A2"
        w.sheet_properties.pageSetUpPr.fitToPage = True
        if rows:
            w.auto_filter.ref = f"A1:{w.cell(row=1, column=len(headers)).column_letter}{len(rows) + 1}"

    def _os_rows(cat):
        """One row per Software; Version cell holds all distinct versions."""
        out_rows = []
        for g in merged_by_os[cat]:
            level = level_of(g["score"])
            out_rows.append([
                g["name"], ", ".join(g["versions"]), " / ".join(g["publishers"]),
                level, g["score"], len(g["hosts"]),
                " | ".join(g["reasons"] + g["cves"][:5]),
                "; ".join(g["actions"]) or "-",
                g["max_cvss"] if g["max_cvss"] else "", g["max_epss"] if g["max_epss"] is not None else "",
                "YES" if g["kev"] else "", g["evidence"],
            ])
        return out_rows

    headers = ["Software", "Version", "Publisher", "Risk", "Score",
               "Hosts", "Reasons", "Fix Action", "Max CVSS", "EPSS", "KEV", "Evidence"]
    widths = [45, 30, 24, 10, 7, 8, 60, 35, 10, 9, 7, 14]
    dump("Windows Soft", headers, _os_rows("windows"), widths)
    dump("Linux Soft", headers, _os_rows("linux"), widths)

    if data is not None:
        by_os = _hosts_critical_by_os(data, items)
        h_headers = ["IP Host", "Host Name", "Critical/High Software", "Note", "Recommendation"]
        h_widths = [18, 25, 50, 60, 45]

        def dump_hosts(title, rows):
            rows = sorted(rows, key=lambda r: (-r[2].count("\n"), r[1].lower()))
            widths = _autofit_widths(h_headers, rows, h_widths, [22, 30, 55, 80, 50])
            w = wb.create_sheet(title)
            w.append(h_headers)
            for c in range(1, len(h_headers) + 1):
                x = w.cell(row=1, column=c)
                x.font = hdr_font
                x.fill = hdr_fill
                x.alignment = center
                x.border = bd
            w.row_dimensions[1].height = 22
            for r, row in enumerate(rows, start=2):
                top = 1
                for c, v in enumerate(row, start=1):
                    cell = w.cell(row=r, column=c, value=v)
                    cell.alignment = center if c in (1, 2) else left
                    cell.border = bd
                    top = max(top, _est_lines(v, widths[c - 1]))
                w.row_dimensions[r].height = min(240, max(15, 15 * top))
            for col, wd in zip("ABCDE", widths):
                w.column_dimensions[col].width = wd
            w.freeze_panes = "A2"
            w.sheet_properties.pageSetUpPr.fitToPage = True
            if rows:
                w.auto_filter.ref = f"A1:E{len(rows) + 1}"

        dump_hosts("Windows Hosts", by_os["windows"])
        dump_hosts("Linux Hosts", by_os["linux"])
        if by_os["other"]:
            dump_hosts("Other Hosts", by_os["other"])
    _method_sheet(wb, hdr_font, hdr_fill, bd, center, left)
    wb.save(out)


def write_hosts_critical_excel(data, items, out):
    """Legacy standalone hosts file (kept for compat). Main report now embeds these sheets."""
    from openpyxl import Workbook
    from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
    wb = Workbook()
    hdr_font = Font(bold=True, color="FFFFFF")
    hdr_fill = PatternFill(start_color="C00000", end_color="C00000", fill_type="solid")
    thin = Side(style="thin", color="D9D9D9")
    bd = Border(left=thin, right=thin, top=thin, bottom=thin)
    center = Alignment(horizontal="center", vertical="center", wrap_text=True)
    left = Alignment(horizontal="left", vertical="center", wrap_text=True)
    headers = ["IP Host", "Host Name", "Critical/High Software", "Note", "Recommendation"]
    widths = [18, 25, 50, 60, 45]

    def fill_sheet(ws, rows):
        ws.append(headers)
        for c in range(1, len(headers) + 1):
            x = ws.cell(row=1, column=c)
            x.font = hdr_font
            x.fill = hdr_fill
            x.alignment = center
            x.border = bd
        ws.row_dimensions[1].height = 22
        rows.sort(key=lambda r: (-r[2].count("\n"), r[1].lower()))
        for r, row in enumerate(rows, start=2):
            top = 1
            for c, v in enumerate(row, start=1):
                cell = ws.cell(row=r, column=c, value=v)
                cell.alignment = center if c in (1, 2) else left
                cell.border = bd
                s = "" if v is None else str(v)
                per = max(10, int(widths[c - 1] * 1.0))
                lines = 0
                for seg in s.split("\n"):
                    lines += max(1, -(-len(seg) // per))
                top = max(top, max(1, lines))
            ws.row_dimensions[r].height = min(240, max(15, 15 * top))
        for col, wd in zip("ABCDE", widths):
            ws.column_dimensions[col].width = wd
        ws.freeze_panes = "A2"
        ws.sheet_properties.pageSetUpPr.fitToPage = True
        if rows:
            ws.auto_filter.ref = f"A1:E{len(rows) + 1}"

    by_os = _hosts_critical_by_os(data, items)

    # reuse default sheet for first title to avoid empty "Sheet"
    sheets = [("Windows Hosts", "windows"), ("Linux Hosts", "linux")]
    if by_os["other"]:
        sheets.append(("Other Hosts", "other"))
    for i, (title, key) in enumerate(sheets):
        ws = wb.active if i == 0 else wb.create_sheet(title)
        if ws.title != title:
            ws.title = title
        fill_sheet(ws, by_os[key])
    wb.save(out)


USAGE = """Usage: py vuln_check.py <input.json> [-o report.json] [--excel] [--online]

Analyze one Kaspersky inventory JSON for vulnerable/EOL software.

Examples:
  py vuln_check.py out\\kaspersky_inventory_20260916_141859.json --excel
  py vuln_check.py out\\kaspersky_inventory_20260916_141859.json -o out\\my_report.json --online

Rules come from vuln_rules.json (built by vuln_update.py).
Paths can also be driven from gui.py (Vulnerability Report button)."""

def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser(description="Vulnerability triage for KSC inventory JSON")
    ap.add_argument("input", nargs="?", help="kaspersky_inventory_*.json")
    ap.add_argument("-o", "--output", help="risk report JSON path")
    ap.add_argument("--excel", action="store_true", help="also write risk_report_*.xlsx")
    ap.add_argument("--online", action="store_true", help="fetch KEV + NVD (CPE) + OSV enrichment (needs internet)")
    ap.add_argument("--top", type=int, default=None, help=argparse.SUPPRESS)  # deprecated
    ap.add_argument("--cvss-lookups", type=int, default=None,
                    help="max NVD ?cveId lookups for CVEs without CVSS (default 25, 300 with a key)")
    ap.add_argument("--nvd-key", help="NVD API key (or env NVD_API_KEY / settings.json NVD_API_KEY)")
    ap.add_argument("--rules", help="path to vuln_rules.json")
    a = ap.parse_args(argv)

    if not a.input:
        print(USAGE)
        return 1

    rules = load_rules(a.rules)
    data = json.loads(Path(a.input).read_text(encoding="utf-8"))

    kev = fetch_kev() if a.online else load_kev_cache()
    if a.online and not kev:
        print("No KEV data available (offline?) - continuing without KEV")
        kev = []
    items = analyze(data, rules, kev or None)
    api_key = resolve_nvd_key(a.nvd_key)
    if a.online:
        print(f"Online enrichment: NVD (CPE ranges, key={'yes' if api_key else 'no - slow'}), "
              f"OSV, EPSS, CISA KEV")
    else:
        print("Offline: using cached NVD / OSV / EPSS / KEV data (run with --online to refresh)")
    enrich_all(items, rules, online=a.online, api_key=api_key, kev=kev,
               cvss_lookups=a.cvss_lookups)

    eol_hosts = find_eol_hosts(data, rules)
    summary = summarize(items, eol_hosts, len(data.get("hosts", [])))
    report = {"generated_at": datetime.now(timezone.utc).isoformat(), "input": str(a.input),
              "summary": summary, "eol_hosts": eol_hosts, "items": items}
    inp = Path(a.input)
    if a.output:
        out = Path(a.output)
    else:
        # Default: inside out/ folder
        out = get_out_dir() / f"risk_report_{inp.stem}.json"
    out.write_text(json.dumps(report, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"Hosts {summary['total_hosts']} SW {summary['unique_software']} "
          f"Critical/High {summary['critical_high_items']} EOL-hosts {summary['eol_hosts']} "
          f"at-risk {summary['hosts_at_risk']}")
    print(f"Levels: {summary['by_level']}")
    print(f"Confirmed-CVE items {summary['confirmed_cve_items']} (KEV {summary['kev_items']})")
    print(f"Saved {out}")
    if a.excel:
        xout = out.with_suffix(".xlsx")
        write_risk_excel(items, eol_hosts, summary, str(xout), data)
        print(f"Saved {xout}")
        # cleanup legacy split file if it exists
        legacy = out.with_name(out.stem + "_hosts.xlsx")
        try:
            if legacy.exists():
                legacy.unlink()
                print(f"Removed legacy {legacy.name}")
        except Exception:
            pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
