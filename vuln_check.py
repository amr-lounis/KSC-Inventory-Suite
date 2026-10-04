#!/usr/bin/env python3
"""Offline-first vulnerability triage for Kaspersky inventory JSON.

Self-contained (stdlib only, no imports from other project scripts).
Usage:
    py vuln_check.py kaspersky_inventory_*.json [--online] [--top N] [-o out.json] [--excel]
Rules come from vuln_rules.json (built by vuln_update.py); paths from gui.py/CLI.
"""
import json
import re
import sys
import time
import unicodedata
import urllib.request
import urllib.parse
from collections import OrderedDict
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from typing import Dict, List, Optional, Tuple

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_DELAY = 7  # seconds between NVD calls without API key

# Score thresholds (single source of truth for level_of + excel fills)
RISK_LEVELS = ("Critical", "High", "Medium", "Low", "Safe")
RISK_MIN_SCORE = {"Critical": 9, "High": 7, "Medium": 4, "Low": 1, "Safe": 0}
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
        # outdated/EOL + actively exploited -> Critical
        score = 10
        reasons.append(note + " [actively exploited - patch now]")
        actions.append("Patch immediately (actively exploited in the wild)")
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
        return {"score": 0, "level": "Safe", "reasons": ["Noise/OS update entry - excluded"], "action": "-"}
    fam = family_of(norm, rules)
    ver = str(version or "").strip()

    checks = [
        _check_eol(norm, ver, rules),
        _check_min_version(norm, fam, ver, name, rules),
        _check_freshness(fam, ver, rules),
    ]
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
        reasons.extend(rs)
        actions.extend(acts)

    if not reasons:
        if not ver:
            # Missing version must not be reported as Safe (false negative).
            return {"score": 4, "level": "Medium",
                    "reasons": ["Version missing - manual review required"],
                    "action": "Verify installed version manually"}
        return {"score": 0, "level": "Safe", "reasons": [], "action": "-"}
    if not actions:
        actions.append("Update to a supported version")
    return {"score": score, "level": level_of(score),
            "reasons": reasons, "action": "; ".join(dict.fromkeys(actions))}


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


def nvd_search(query, api_key=None, results=10, timeout=30):
    params = {"keywordSearch": query, "resultsPerPage": results}
    if api_key:
        params["apiKey"] = api_key
    url = NVD_URL + "?" + urllib.parse.urlencode(params)
    req = urllib.request.Request(url, headers={"User-Agent": "ksc-inventory/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8"))


def cvss_of(cve):
    metrics = (cve.get("metrics") or {})
    for m in (metrics.get("cvssMetricV31") or []) + (metrics.get("cvssMetricV30") or []):
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
    import math
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


# ---- OSV.dev (Linux distro packages): version-aware, batch, no key needed ----
OSV_URL = "https://api.osv.dev/v1/querybatch"
OSV_BATCH = 500
_OSV_TEXT_SEV = {"critical": 9.0, "high": 7.5, "medium": 5.0,
                 "low": 2.5, "negligible": 0.5}


def _osv_name_variants(name):
    ln = str(name or "").strip().lower()
    out = [ln] if ln else []
    m = re.match(r"^python3?[-_](.+)$", ln)
    if m and m.group(1) and m.group(1) not in out:
        out.append(m.group(1))
    return out[:2]


def _osv_ecosystems(version):
    """Candidate OSV ecosystems from a distro version string.

    Inventory OS data is often just 'Linux', so the distro major is unknown:
    query supported majors and merge by CVE ID (server filters each one).
    RHEL-style versions have no reliable mapping -> skipped (heuristic only).
    """
    v = str(version or "").lower()
    if not v:
        return []
    if ".el" in v or "rhel" in v or "rocky" in v or "alma" in v or "suse" in v:
        return []
    if "ubuntu" in v:
        return ["Ubuntu:24.04", "Ubuntu:22.04", "Ubuntu:20.04"]
    return ["Debian:12", "Debian:11", "Ubuntu:22.04", "Ubuntu:24.04"]


def _osv_post(batch, timeout=60):
    data = json.dumps({"queries": batch}).encode("utf-8")
    req = urllib.request.Request(OSV_URL, data=data,
                                 headers={"Content-Type": "application/json",
                                          "User-Agent": "ksc-inventory/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8"))


def _osv_cvss(vuln):
    """(score|None, approx_flag) from an OSV vuln entry."""
    best = None
    for sev in vuln.get("severity", []) or []:
        if str(sev.get("type", "")).upper().startswith("CVSS_V3"):
            s = cvss_v3_base_score(sev.get("score", ""))
            if s is not None and (best is None or s > best):
                best = s
    if best is not None:
        return best, False
    txt = str(((vuln.get("database_specific") or {}).get("severity", ""))).strip().lower()
    if txt in _OSV_TEXT_SEV:
        return _OSV_TEXT_SEV[txt], True
    return None, False


def _brief_osv_vuln(v):
    sc, approx = _osv_cvss(v)
    return {"id": v.get("id", "?"), "cvss": sc, "approx": approx,
            "published": (v.get("published") or "")[:10],
            "summary": (v.get("summary") or "")[:120]}


def enrich_osv(data, items, online=True, cache_file=None, fetcher=None):
    """Version-aware OSV.dev enrichment for Linux-seen software.

    Score becomes max(heuristic, best confirmed CVSS). Only raises, never
    lowers: absence from OSV means 'no known CVE for this build', not safe.
    Cached in osv_cache.json; failures non-fatal (heuristic scores kept).
    """
    cache_file = Path(cache_file) if cache_file else cache_path("osv_cache.json")
    try:
        cache = json.loads(cache_file.read_text(encoding="utf-8"))
        if not isinstance(cache, dict):
            cache = {}
    except Exception:
        cache = {}
    fetch = fetcher or _osv_post

    item_keys = {}
    missing, seen_keys = [], set()
    for idx, it in enumerate(items or []):
        if "linux" not in (it.get("os") or []):
            continue
        ver = str(it.get("version") or "").strip()
        if not ver:
            continue
        keys = []
        for variant in _osv_name_variants(it.get("name")):
            for eco in _osv_ecosystems(ver):
                key = f"{eco}|{variant}|{ver}"
                keys.append(key)
                if key not in cache and key not in seen_keys:
                    seen_keys.add(key)
                    missing.append((key, {"package": {"name": variant, "ecosystem": eco},
                                          "version": ver}))
        if keys:
            item_keys[idx] = keys

    if online and missing:
        print(f"OSV enrichment: {len(missing)} queries for "
              f"{len(item_keys)} linux items (cache has {len(cache)})")
        for off in range(0, len(missing), OSV_BATCH):
            chunk = missing[off:off + OSV_BATCH]
            try:
                res = fetch([q for _, q in chunk])
                results = res.get("results", [])
            except Exception as e:
                print(f"  OSV batch failed ({e}) - keeping heuristic scores")
                break
            for (key, _), r in zip(chunk, results):
                vulns = [ _brief_osv_vuln(v) for v in (r.get("vulns") or [])]
                vulns.sort(key=lambda v: -((v.get("cvss") or 0.0)))
                cache[key] = {"vulns": vulns[:10]}
        try:
            cache_file.write_text(json.dumps(cache, ensure_ascii=False, indent=1), encoding="utf-8")
        except Exception as e:
            print(f"Cannot save OSV cache: {e}")

    for idx, keys in item_keys.items():
        it = items[idx]
        merged = {}
        for key in keys:
            for v in (cache.get(key, {}) or {}).get("vulns", []):
                prev = merged.get(v.get("id"))
                if prev is None or (v.get("cvss") or 0.0) > (prev.get("cvss") or 0.0):
                    merged[v["id"]] = v
        if not merged:
            continue
        have = {c.get("id") if isinstance(c, dict) else c for c in (it.get("cves") or [])}
        for v in sorted(merged.values(), key=lambda v: -((v.get("cvss") or 0.0)))[:5]:
            if v["id"] not in have:
                it.setdefault("cves", []).append(
                    {"id": v["id"], "cvss": v.get("cvss") or 0.0,
                     "published": v.get("published", "")})
                have.add(v["id"])
        scored = [(v["cvss"], v["id"], v.get("approx", False))
                  for v in merged.values() if v.get("cvss")]
        if scored:
            best, bid, approx = max(scored)
            if best > (it.get("score") or 0):
                tag = " (~ecosystem severity)" if approx else ""
                it["score"] = round(float(best), 1)
                it["level"] = level_of(it["score"])
                extra = f" +{len(scored) - 1} more" if len(scored) > 1 else ""
                it["reasons"].append(
                    f"OSV: {bid} CVSS {best}{tag} "
                    f"({it.get('name')} {it.get('version')}{extra})")
    return items


# ---- NVD CPE version-range matching (Windows/desktop apps) ----
NVD_CPE = {
    "google chrome": ["cpe:2.3:a:google:chrome"],
    "microsoft edge": ["cpe:2.3:a:microsoft:edge"],
    "mozilla firefox": ["cpe:2.3:a:mozilla:firefox"],
    "opera": ["cpe:2.3:a:opera:opera_browser"],
    "adobe acrobat": ["cpe:2.3:a:adobe:acrobat", "cpe:2.3:a:adobe:acrobat_reader"],
    "adobe reader": ["cpe:2.3:a:adobe:acrobat_reader", "cpe:2.3:a:adobe:acrobat"],
    "java": ["cpe:2.3:a:oracle:jdk", "cpe:2.3:a:oracle:jre"],
    "python": ["cpe:2.3:a:python:python"],
    "vlc media player": ["cpe:2.3:a:videolan:vlc_media_player"],
    "7-zip": ["cpe:2.3:a:7-zip:7-zip"],
    "winrar": ["cpe:2.3:a:rarlab:winrar"],
    "notepad++": ["cpe:2.3:a:notepad-plus-plus:notepad++"],
    "teamviewer": ["cpe:2.3:a:teamviewer:teamviewer"],
    "anydesk": ["cpe:2.3:a:anydesk:anydesk"],
}


def nvd_fetch_cpe(cpe, api_key=None, timeout=60):
    params = {"cpeName": cpe, "resultsPerPage": 2000}
    if api_key:
        params["apiKey"] = api_key
    url = NVD_URL + "?" + urllib.parse.urlencode(params)
    req = urllib.request.Request(url, headers={"User-Agent": "ksc-inventory/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8"))


def _brief_nvd_cve(cve):
    sc, _sev = cvss_of(cve)
    matches = []
    for conf in cve.get("configurations") or []:
        for node in conf.get("nodes") or []:
            if node.get("negate"):
                continue
            for m in node.get("cpeMatch") or []:
                if m.get("negate") or not m.get("vulnerable", True):
                    continue
                matches.append({"criteria": m.get("criteria", ""),
                                "versionStartIncluding": m.get("versionStartIncluding"),
                                "versionStartExcluding": m.get("versionStartExcluding"),
                                "versionEndIncluding": m.get("versionEndIncluding"),
                                "versionEndExcluding": m.get("versionEndExcluding")})
    return {"id": cve.get("id", "?"), "cvss": sc,
            "published": (cve.get("published") or "")[:10], "match": matches}


def _nvd_range_hit(criteria, m, installed):
    """True if installed version is inside the CPE match range, False if
    outside, None when the entry states no usable version info."""
    parts = str(criteria or "").split(":")
    embedded = parts[5] if len(parts) > 5 else "*"
    si, sx, ei, ex = (m.get("versionStartIncluding"), m.get("versionStartExcluding"),
                      m.get("versionEndIncluding"), m.get("versionEndExcluding"))
    if not any([si, sx, ei, ex]):
        if embedded in ("*", "-", ""):
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


def enrich_nvd_cpe(items, api_key=None, cache_file=None, online=True, fetcher=None):
    """CPE version-range NVD enrichment for mapped families.

    Only CVEs whose stated range contains the installed version raise the
    score (to the CVE's CVSS). Unranged product mentions are ignored for
    scoring. Cached per-CPE in nvd_cache.json under 'cpe::<cpe>' keys.
    """
    cache_file = Path(cache_file) if cache_file else cache_path("nvd_cache.json")
    try:
        cache = json.loads(cache_file.read_text(encoding="utf-8"))
        if not isinstance(cache, dict):
            cache = {}
    except Exception:
        try:
            cache = json.loads((get_app_dir() / "nvd_cache.json").read_text(encoding="utf-8"))
            if not isinstance(cache, dict):
                cache = {}
        except Exception:
            cache = {}
    fetch = fetcher or (lambda cpe: nvd_fetch_cpe(cpe, api_key))

    fams = sorted({it.get("family") for it in items or [] if it.get("family") in NVD_CPE})
    cpe_data = {}
    if online:
        for fam in fams:
            for cpe in NVD_CPE[fam]:
                key = f"cpe::{cpe}"
                if key not in cache:
                    try:
                        raw = fetch(cpe)
                        cache[key] = [_brief_nvd_cve(v.get("cve", {}))
                                      for v in (raw.get("vulnerabilities") or [])]
                        print(f"  NVD CPE {cpe}: {len(cache[key])} CVE(s)")
                    except Exception as e:
                        print(f"  NVD CPE {cpe} failed ({e})")
                        cache[key] = cache.get(key, [])
                    time.sleep(1 if api_key else NVD_DELAY)
                cpe_data[cpe] = cache.get(key, [])
        try:
            cache_file.write_text(json.dumps(cache, ensure_ascii=False, indent=1), encoding="utf-8")
        except Exception as e:
            print(f"Cannot save NVD cache: {e}")
    else:
        for fam in fams:
            for cpe in NVD_CPE[fam]:
                cpe_data[cpe] = cache.get(f"cpe::{cpe}", [])

    for it in items or []:
        fam = it.get("family")
        if fam not in NVD_CPE:
            continue
        ver = str(it.get("version") or "").strip()
        if not ver:
            continue
        hits, seen = [], set()
        for cpe in NVD_CPE[fam]:
            for cve in cpe_data.get(cpe, []):
                cid = cve.get("id")
                if not cid or cid in seen:
                    continue
                for m in cve.get("match", []):
                    if not str(m.get("criteria", "")).startswith(cpe + ":"):
                        continue
                    if _nvd_range_hit(m["criteria"], m, ver) is True:
                        hits.append((cve.get("cvss") or 0.0, cid))
                        seen.add(cid)
                        break
        if not hits:
            continue
        have = {c.get("id") if isinstance(c, dict) else c for c in (it.get("cves") or [])}
        for sc, cid in sorted(hits, reverse=True)[:5]:
            if cid not in have:
                it.setdefault("cves", []).append({"id": cid, "cvss": sc})
                have.add(cid)
        scored = [(s, i) for s, i in hits if s and s > 0]
        if scored:
            best, bid = max(scored)
            if best > (it.get("score") or 0):
                it["score"] = round(float(best), 1)
                it["level"] = level_of(it["score"])
                extra = f" +{len(scored) - 1} more" if len(scored) > 1 else ""
                it["reasons"].append(
                    f"NVD: {bid} CVSS {best} (affects {it.get('name')} {ver}{extra})")
    return items


def enrich_nvd(items, rules, top=30, cache_file=None, api_key=None):
    """Online NVD enrichment: CPE version-range matching for mapped families,
    keyword fallback for the rest. Cached, failures non-fatal."""
    enrich_nvd_cpe(items, api_key=api_key, cache_file=cache_file)
    cache_file = Path(cache_file) if cache_file else cache_path("nvd_cache.json")
    try:
        cache = json.loads(cache_file.read_text(encoding="utf-8"))
    except Exception:
        # fallback: legacy location next to exe
        try:
            cache = json.loads((get_app_dir() / "nvd_cache.json").read_text(encoding="utf-8"))
        except Exception:
            cache = {}
    generic = set((rules.get("generic_tokens") or []))
    cands = [it for it in items
             if it["score"] >= 4 and it.get("family") not in NVD_CPE][:top]
    print(f"NVD enrichment: {len(cands)} items (cache has {len(cache)})")
    for i, it in enumerate(cands, 1):
        q = it.get("family") or it["name"]
        if q in cache:
            it["cves"] = cache[q]
            continue
        try:
            data = nvd_search(q, api_key=api_key)
            toks = split_tokens_list(normalize_name(q), generic=generic)
            found = []
            for v in (data.get("vulnerabilities") or [])[:20]:
                cve = v.get("cve", {})
                desc = " ".join(d.get("value", "") for d in cve.get("descriptions", []) if d.get("lang") == "en").lower()
                if toks and not all(t in desc for t in toks[:3]):
                    continue
                sc, sev = cvss_of(cve)
                found.append({"id": cve.get("id"), "cvss": sc, "severity": sev,
                              "published": (cve.get("published") or "")[:10]})
            found.sort(key=lambda x: -x["cvss"])
            cache[q] = found[:5]
            it["cves"] = found[:5]
            if found:
                best = found[0]["cvss"]
                if best >= 9 and it["score"] < 9:
                    it["score"] = 9
                    it["level"] = "Critical"
                    it["reasons"].append(f"NVD: {found[0]['id']} CVSS {best} (keyword match - review)")
            print(f"  [{i}/{len(cands)}] {q[:50]}: {len(found)} CVE(s)")
        except Exception as e:
            print(f"  [{i}/{len(cands)}] {q[:50]}: NVD failed ({e})")
            it["cves"] = cache.get(q, [])
        time.sleep(1 if api_key else NVD_DELAY)
    try:
        cache_file.write_text(json.dumps(cache, ensure_ascii=False, indent=1), encoding="utf-8")
    except Exception as e:
        print(f"Cannot save NVD cache: {e}")
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
                                "hosts_by_os": {"windows": [], "linux": [], "other": []}}
            e["count"] += 1
            if hid not in e["hosts"]:
                e["hosts"].append(hid)
            e["os_counts"][os_cat] += 1
            if hid not in e["hosts_by_os"][os_cat]:
                e["hosts_by_os"][os_cat].append(hid)
    items = []
    for (nl, ver), e in agg.items():
        r = assess(e["name"], ver, e["publisher"], rules, kev_index)
        nn = norm_cache.get(nl)
        if nn is None:
            nn = norm_cache[nl] = normalize_name(e["name"], rules)
        os_list = sorted([c for c, n in e["os_counts"].items() if n > 0])
        items.append({**e, "family": family_of(nn, rules),
                      "os": os_list,
                      "score": r["score"], "level": r["level"],
                      "reasons": r["reasons"], "action": r["action"], "cves": []})
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
            ("EOL hosts", summary["eol_hosts"])] + \
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
        caps = [50, 35, 30, 12, 8, 10, 80, 45]
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
                cell.alignment = center if c in (2, 4, 5) else left
                cell.border = bd
                if headers[c - 1] == "Risk" and v in fills:
                    cell.fill = fills[v]
                top = max(top, _est_lines(v, widths[c - 1]))
            w.row_dimensions[r].height = min(180, max(15, 15 * top))
        for col, wd in zip("ABCDEFGH", widths):
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
            ])
        return out_rows

    headers = ["Software", "Version", "Publisher", "Risk", "Score",
               "Hosts", "Reasons", "Fix Action"]
    widths = [45, 30, 24, 10, 7, 8, 60, 35]
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
    ap.add_argument("--top", type=int, default=30, help="NVD-enriched items (default 30)")
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
    if a.online:
        import os
        enrich_osv(data, items, online=True)
        enrich_nvd(items, rules, top=a.top, api_key=os.environ.get("NVD_API_KEY"))

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
