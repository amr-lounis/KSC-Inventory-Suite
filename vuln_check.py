#!/usr/bin/env python3
"""Offline-first vulnerability triage for Kaspersky inventory JSON.

Stdlib only. Usage:
    py vuln_check.py kaspersky_inventory_*.json [--online] [--top N] [-o out.json] [--excel]
    py vuln_check.py --update-rules   # refresh upstream sections of vuln_rules.json
                                      # from endoflife.date API + CISA KEV (needs internet)
Reads vuln_rules.json next to the script/exe.
"""
import json
import re
import sys
import time
import unicodedata
import urllib.request
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_DELAY = 7  # seconds between NVD calls without API key


def get_app_dir():
    if getattr(sys, "frozen", False):
        return Path(sys.executable).parent
    return Path(__file__).parent


def get_out_dir():
    # كل الملفات الناتجة (تقارير + cache) داخل مجلد out
    d = get_app_dir() / "out"
    d.mkdir(parents=True, exist_ok=True)
    return d


def resource_path(name):
    """Rules live next to exe; fall back to bundled _MEIPASS."""
    p = get_app_dir() / name
    if p.exists():
        return p
    meipas = getattr(sys, "_MEIPASS", None)
    if meipas and (Path(meipas) / name).exists():
        return Path(meipas) / name
    return p


def cache_path(name):
    """Cache files (KEV/NVD) live in out/."""
    return get_out_dir() / name


def load_rules(path=None):
    p = Path(path) if path else resource_path("vuln_rules.json")
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception as e:
        print(f"Warning: cannot load rules {p}: {e} - using empty rules")
        return {}


def strip_accents(s):
    return "".join(c for c in unicodedata.normalize("NFKD", s) if not unicodedata.combining(c))


_WS_RE = re.compile(r"\s+")
_TOK_RE = re.compile(r"[^a-z0-9]+")
_NUM_RE = re.compile(r"\d+")


def split_tokens(s, min_len=5, generic=()):
    return {t for t in _TOK_RE.split(s) if len(t) >= min_len and t not in generic}


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


def family_of(norm_name, rules):
    for pat, fam in (rules.get("family_patterns") or []):
        if pat in norm_name:
            return fam
    return None


def is_noise(norm_name, rules):
    return any(p in norm_name for p in (rules.get("noise_patterns") or []))


def parse_version(s):
    parts = _NUM_RE.findall(str(s or ""))
    if not parts:
        return ()
    return tuple(int(x) for x in parts[:6])


_VER_CACHE = {}

def parse_version_cached(s):
    key = str(s or "")
    v = _VER_CACHE.get(key)
    if v is None:
        v = parse_version(key)
        if len(_VER_CACHE) < 50000:
            _VER_CACHE[key] = v
    return v


def cmp_versions(a, b):
    n = max(len(a), len(b))
    a += (0,) * (n - len(a))
    b += (0,) * (n - len(b))
    return (a > b) - (a < b)


def level_of(score):
    if score >= 9:
        return "Critical"
    if score >= 7:
        return "High"
    if score >= 4:
        return "Medium"
    if score >= 1:
        return "Low"
    return "Safe"


def entry_matches(norm, entry):
    """Supports {'match': 'substr'} and {'match_all': ['t1','t2',...]} (all tokens)."""
    m = entry.get("match")
    if m and m in norm:
        return True
    ma = entry.get("match_all")
    if ma and all(t in norm for t in ma):
        return True
    return False


def assess(name, version, publisher="", rules=None, kev=None, host_count=0):
    """Return dict(score, level, reasons[], action). Pure offline unless kev given."""
    rules = rules or {}
    norm = normalize_name(name, rules)
    reasons, actions = [], []
    score = 0

    if not norm or is_noise(norm, rules):
        return {"score": 0, "level": "Safe", "reasons": ["Noise/OS update entry - excluded"], "action": "-"}

    for item in (rules.get("eol_products") or []) + (rules.get("upstream_eol") or []):
        if item.get("kind", "app") != "app":
            continue
        if entry_matches(norm, item):
            score = max(score, int(item.get("score", 9)))
            reasons.append(item.get("label", item.get("match", "?")))
            if item.get("action"):
                actions.append(item["action"])

    fam = family_of(norm, rules)
    min_versions = rules.get("min_safe_versions") or {}
    key = fam or norm
    if key in min_versions and version and str(version).strip():
        entry = min_versions[key]
        cur, minimum = parse_version_cached(version), parse_version_cached(entry.get("min", ""))
        if cur and minimum and cmp_versions(cur, minimum) < 0:
            gap = minimum[0] - cur[0] if len(minimum) > 0 and len(cur) > 0 else 0
            if fam in ("google chrome", "microsoft edge", "mozilla firefox", "opera"):
                s = 9 if gap >= 10 or (len(cur) > 1 and len(minimum) > 1 and minimum[0] == cur[0] and minimum[1] - cur[1] >= 30) else 8
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

    # Upstream freshness (endoflife.date): evergreen families vs latest known major
    up_latest = rules.get("upstream_latest") or {}
    if fam in up_latest and version and str(version).strip():
        try:
            latest_major = int(up_latest[fam].get("major", 0))
        except (TypeError, ValueError):
            latest_major = 0
        cur = parse_version_cached(version)
        if cur and latest_major and cur[0] > 0 and cur[0] < latest_major:
            gap = latest_major - cur[0]
            if fam in ("google chrome", "microsoft edge", "mozilla firefox", "opera"):
                s = 9 if gap >= 6 else (8 if gap >= 3 else 6)
            else:
                s = 8 if gap >= 2 else 6
            score = max(score, s)
            reasons.append(f"Outdated vs upstream: {version} (latest {fam} major {latest_major}, endoflife.date)")
            actions.append("Update to the latest release")

    if kev:
        if kev and isinstance(kev[0], tuple):
            kev_index = kev  # prebuilt by analyze()
        else:
            kev_index = build_kev_index(kev, rules)
        generic = set(rules.get("generic_tokens") or ())
        first = match_kev_first(norm, normalize_name(publisher or ""),
                                split_tokens(norm, generic=generic), kev_index)
        if first is not None:
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

    if not reasons:
        return {"score": 0, "level": "Safe", "reasons": [], "action": "-"}
    if not actions:
        actions.append("Update to a supported version")
    return {"score": score, "level": level_of(score), "reasons": reasons, "action": "; ".join(dict.fromkeys(actions))}


def build_kev_index(kev_list, rules=None):
    """Precompute normalized KEV data once (was re-normalized per software item)."""
    generic = set((rules or {}).get("generic_tokens") or ())
    index = []
    for entry in kev_list or []:
        prod = normalize_name(entry.get("product", ""))
        if not prod:
            continue
        vend = normalize_name(entry.get("vendorProject", ""))
        overlap = {t for t in _TOK_RE.split(prod) if len(t) >= 5 and t not in generic}
        index.append((entry, prod, vend, overlap))
    return index


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


def enrich_nvd(items, rules, top=30, cache_file=None, api_key=None):
    """Online NVD keyword enrichment for top-N risky items. Cached, failures non-fatal."""
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
    cands = [it for it in items if it["score"] >= 4][:top]
    print(f"NVD enrichment: {len(cands)} items (cache has {len(cache)})")
    for i, it in enumerate(cands, 1):
        q = it.get("family") or it["name"]
        if q in cache:
            it["cves"] = cache[q]
            continue
        try:
            data = nvd_search(q, api_key=api_key)
            toks = [t for t in re.split(r"[^a-z0-9]+", normalize_name(q)) if len(t) >= 3 and t not in generic]
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
        if q not in cache or True:
            pass
        time.sleep(1 if api_key else NVD_DELAY)
    try:
        cache_file.write_text(json.dumps(cache, ensure_ascii=False, indent=1), encoding="utf-8")
    except Exception as e:
        print(f"Cannot save NVD cache: {e}")
    return items


# ---------------------------------------------------------------------------
# Upstream rules update (endoflife.date API + CISA KEV) - agreed standard schemas
# ---------------------------------------------------------------------------
EOL_API_BASE = "https://endoflife.date/api"
# endoflife.date product -> (kind, keyword for match_all, use_cycle_token)
EOL_UPSTREAM_PRODUCTS = {
    "windows": ("os", "windows", False),
    "windows-server": ("os", None, False),
    "ubuntu": ("os", "ubuntu", False),
    "debian": ("os", "debian", False),
    "rhel": ("os", "rhel", False),
    "rocky-linux": ("os", "rocky", False),
    "centos": ("os", "centos", False),
    "oracle-linux": ("os", "oracle linux", False),
    "almalinux": ("os", "alma", False),
    "office": ("app", "office", False),
    "mssqlserver": ("app", "sql server", False),
    "msexchange": ("app", "exchange", False),
    "python": ("app", "python", True),
    "oracle-jdk": ("app", "java", False),
}
# endoflife.date product -> our family key (true evergreen, single version line)
EVERGREEN_UPSTREAM = {"chrome": "google chrome", "firefox": "mozilla firefox"}


def fetch_eol_product(product, timeout=30):
    req = urllib.request.Request(f"{EOL_API_BASE}/{product}.json",
                                 headers={"User-Agent": "ksc-inventory/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        data = json.loads(r.read().decode("utf-8"))
    return data if isinstance(data, list) else []


def clean_label(label):
    s = strip_accents(str(label or "").lower())
    s = re.sub(r"\(.*?\)", " ", s)
    return re.sub(r"\s+", " ", s).strip()


def is_past(eol_str, today):
    try:
        return datetime.strptime(str(eol_str)[:10], "%Y-%m-%d").date() < today
    except (ValueError, TypeError):
        return False


def build_upstream_entries(today=None):
    """Fetch endoflife.date and build (upstream_eol, upstream_latest, products_ok)."""
    from concurrent.futures import ThreadPoolExecutor
    from datetime import date
    today = today or date.today()
    upstream_eol, upstream_latest, products_ok = [], {}, []
    all_products = list(EOL_UPSTREAM_PRODUCTS) + list(EVERGREEN_UPSTREAM)

    def _fetch(product):
        try:
            return product, fetch_eol_product(product), None
        except Exception as e:
            return product, [], str(e)

    # parallel downloads (I/O bound), results merged in fixed product order
    fetched = {}
    with ThreadPoolExecutor(max_workers=8) as ex:
        for product, releases, err in ex.map(_fetch, all_products):
            fetched[product] = (releases, err)
    for product in all_products:
        releases, err = fetched[product]
        if err is not None:
            print(f"  [skip] {product}: {err}")
            continue
        if not releases:
            print(f"  [skip] {product}: empty response")
            continue
        products_ok.append(product)
        kind, keyword, use_cycle = EOL_UPSTREAM_PRODUCTS.get(product, ("app", None, False))

        eol_rels = [x for x in releases if x.get("eol") and is_past(x.get("eol"), today)]
        if product == "windows":
            # bare-major matches only when the whole major line is EOL (7/8/8.1/XP/Vista),
            # never for 10/11 (supported editions exist and KSC strings lack build numbers)
            by_major = {}
            for x in releases:
                tok = (clean_label(x.get("releaseLabel") or x.get("cycle")).split() or ["?"])[0]
                by_major.setdefault(tok, {"eol": 0, "total": 0})
                by_major[tok]["total"] += 1
                if x.get("eol") and is_past(x.get("eol"), today):
                    by_major[tok]["eol"] += 1
            for tok, st in sorted(by_major.items()):
                if st["eol"] == st["total"]:
                    eol_date = max(x["eol"] for x in releases
                                   if (clean_label(x.get("releaseLabel") or x.get("cycle")).split() or ["?"])[0] == tok)
                    upstream_eol.append({
                        "match_all": ["windows", tok], "kind": "os", "score": 10,
                        "label": f"Windows {tok.upper()} (EOL {eol_date}, endoflife.date)",
                        "eol": eol_date, "product": "windows",
                        "action": "Upgrade/Migrate to a supported Windows"})
        else:
            for x in eol_rels:
                raw = x.get("releaseLabel") or x.get("cycle") or ""
                norm = clean_label(raw)
                token = (clean_label(x.get("cycle")).split() or [norm.split()[0] if norm.split() else ""])[0] \
                    if use_cycle else (norm.split()[0] if norm.split() else "")
                if keyword:
                    entry = {"match_all": [keyword, token] if token else [keyword]}
                elif len(norm) >= 6 and not norm.replace(".", "").replace("-", "").isdigit():
                    entry = {"match": norm}
                elif token:
                    entry = {"match_all": [product.replace("-", " "), token]}
                else:
                    continue
                entry.update({
                    "kind": kind, "score": 10 if kind == "os" else 9,
                    "label": f"{raw} (EOL {x['eol']}, endoflife.date)",
                    "eol": x["eol"], "product": product,
                    "action": "Upgrade/Migrate to a supported OS" if kind == "os"
                              else "Upgrade to a supported version"})
                upstream_eol.append(entry)

        if product in EVERGREEN_UPSTREAM:
            majors = []
            for x in releases:
                if x.get("eol") and is_past(x.get("eol"), today):
                    continue
                lab = clean_label(x.get("releaseLabel") or x.get("cycle"))
                m = re.match(r"(\d+)", lab)
                if m:
                    majors.append(int(m.group(1)))
            if majors:
                upstream_latest[EVERGREEN_UPSTREAM[product]] = {
                    "major": max(majors), "checked": today.isoformat(),
                    "source": f"endoflife.date/{product}"}
    upstream_eol.sort(key=lambda e: (e.get("kind", ""), e.get("label", "")))
    return upstream_eol, upstream_latest, products_ok


REQUIRED_RULE_SECTIONS = ("eol_os", "eol_products", "min_safe_versions", "family_patterns",
                            "aliases", "noise_patterns", "generic_tokens")

# Built-in seed: used to CREATE vuln_rules.json when missing (then enriched from internet).
# Same content as the shipped vuln_rules.json static sections.
DEFAULT_STATIC_RULES = {
  "_comment": "Vulnerability rules for vuln_check.py - editable without touching code. All matching is case-insensitive substring on the normalized software/OS name.",
  "eol_os": [
    {"match": "windows xp", "label": "Windows XP (EOL 2014)", "score": 10},
    {"match": "windows vista", "label": "Windows Vista (EOL 2017)", "score": 10},
    {"match": "windows 7", "label": "Windows 7 (EOL 2020)", "score": 10},
    {"match": "windows 8", "label": "Windows 8/8.1 (EOL 2016/2023)", "score": 10},
    {"match": "windows 8.1", "label": "Windows 8.1 (EOL 2023)", "score": 10},
    {"match": "server 2003", "label": "Windows Server 2003 (EOL 2015)", "score": 10},
    {"match": "server 2008", "label": "Windows Server 2008/R2 (EOL 2020)", "score": 10},
    {"match": "server 2012", "label": "Windows Server 2012/R2 (EOL 2023)", "score": 9}
  ],
  "eol_products": [
    {"match": "office professional plus 2007", "label": "Office 2007 (EOL 2017)", "score": 9, "action": "Uninstall / Upgrade to a supported Office"},
    {"match": "office standard 2007", "label": "Office 2007 (EOL 2017)", "score": 9, "action": "Uninstall / Upgrade to a supported Office"},
    {"match": "office professional plus 2010", "label": "Office 2010 (EOL 2020)", "score": 9, "action": "Uninstall / Upgrade to a supported Office"},
    {"match": "office standard 2010", "label": "Office 2010 (EOL 2020)", "score": 9, "action": "Uninstall / Upgrade to a supported Office"},
    {"match": "office professional plus 2013", "label": "Office 2013 (EOL 2023)", "score": 8, "action": "Upgrade to a supported Office"},
    {"match": "java 6", "label": "Java 6 (EOL 2013)", "score": 9, "action": "Uninstall / Upgrade Java"},
    {"match": "java 7", "label": "Java 7 (EOL 2015)", "score": 9, "action": "Uninstall / Upgrade Java"},
    {"match": "java(tm) 6", "label": "Java 6 (EOL 2013)", "score": 9, "action": "Uninstall / Upgrade Java"},
    {"match": "visual c++ 2008", "label": "VC++ 2008 (EOL, DLL-hijack history)", "score": 7, "action": "Uninstall if unused"},
    {"match": "visual c++ 2010", "label": "VC++ 2010 (EOL 2020)", "score": 7, "action": "Uninstall if unused"},
    {"match": "visual c++ 2012", "label": "VC++ 2012 (support ended 2023)", "score": 5, "action": "Uninstall if unused"},
    {"match": "visual c++ 2013", "label": "VC++ 2013 (support ended 2024)", "score": 5, "action": "Uninstall if unused"},
    {"match": "adobe flash", "label": "Flash Player (EOL 2020)", "score": 10, "action": "Uninstall immediately"},
    {"match": "shockwave", "label": "Shockwave (EOL 2019)", "score": 9, "action": "Uninstall immediately"},
    {"match": "quicktime", "label": "QuickTime for Windows (EOL 2016)", "score": 9, "action": "Uninstall immediately"}
  ],
  "min_safe_versions": {
    "google chrome": {"min": "152.0.0.0", "action": "Update browser"},
    "microsoft edge": {"min": "152.0.0.0", "action": "Update browser"},
    "mozilla firefox": {"min": "154.0.0.0", "action": "Update browser"},
    "opera": {"min": "117.0.0.0", "action": "Update browser"},
    "adobe acrobat": {"min": "25.001.0.0", "action": "Update via Adobe updater"},
    "adobe reader": {"min": "25.001.0.0", "action": "Update via Adobe updater"},
    "java": {"min": "8.0.441.0", "action": "Update Java / remove if unused"},
    "vlc media player": {"min": "3.0.21.0", "action": "Update VLC"},
    "7-zip": {"min": "24.9.0.0", "action": "Update 7-Zip (known MotW CVEs in old builds)"},
    "winrar": {"min": "7.1.0.0", "action": "Update WinRAR (CVE-2023-38831 in older builds)"},
    "python": {"min": "3.12.0.0", "action": "Upgrade Python (3.8 and older are EOL)"},
    "kaspersky endpoint security": {"min": "12.7.0.0", "action": "Update KES via KSC task"},
    "kaspersky security center": {"min": "14.0.0.0", "action": "Update KSC agent via KSC task"},
    "ocs inventory": {"min": "2.9.0.0", "action": "Update OCS agent"},
    "vmware tools": {"min": "12.3.0.0", "action": "Update VMware Tools"},
    "notepad++": {"min": "8.6.0.0", "action": "Update Notepad++"},
    "teamviewer": {"min": "15.50.0.0", "action": "Update TeamViewer / restrict access"},
    "anydesk": {"min": "8.1.0.0", "action": "Update AnyDesk / restrict access"}
  },
  "family_patterns": [
    ["google chrome", "google chrome"],
    ["microsoft edge", "microsoft edge"],
    ["firefox", "mozilla firefox"],
    ["opera", "opera"],
    ["adobe acrobat", "adobe acrobat"],
    ["adobe reader", "adobe reader"],
    ["acrobat reader", "adobe reader"],
    ["java", "java"],
    ["vlc", "vlc media player"],
    ["7-zip", "7-zip"],
    ["winrar", "winrar"],
    ["python", "python"],
    ["kaspersky endpoint security", "kaspersky endpoint security"],
    ["administration de kaspersky", "kaspersky security center"],
    ["kaspersky security center", "kaspersky security center"],
    ["network agent", "kaspersky security center"],
    ["ocs inventory", "ocs inventory"],
    ["vmware tools", "vmware tools"],
    ["notepad++", "notepad++"],
    ["teamviewer", "teamviewer"],
    ["anydesk", "anydesk"]
  ],
  "aliases": {
    "agent d'administration de kaspersky security center": "kaspersky security center network agent",
    "plug-in du serveur des appareils mobiles exchange": "kaspersky security center plugin",
    "serveur d'administration de kaspersky security center": "kaspersky security center server",
    "extension pour ios mobile device management": "kaspersky security center plugin",
    "controle d'integrite du pc windows": "windows pc health check",
    "googlechrome": "google chrome",
    "microsoft office professionnel plus": "microsoft office professional plus",
    "logiciel pour dispositif a chipset intel": "intel chipset device software"
  },
  "noise_patterns": [
    "windows qfe",
    "compatibility fix database",
    "update for x64-based windows",
    "update for microsoft windows",
    "security update for microsoft windows",
    "windows driver package",
    "mise a jour pour windows",
    "correctif pour windows",
    "language pack",
    "module linguistique",
    "proofing tools"
  ],
  "generic_tokens": ["microsoft", "corporation", "windows", "for", "update", "agent", "software", "package", "driver", "version", "plus", "pro", "the", "and", "administration", "server", "client", "redistributable"]
}


def update_rules_from_upstream(rules_path=None):
    """Create (if missing) or refresh vuln_rules.json from standard internet feeds."""
    rules_path = Path(rules_path) if rules_path else resource_path("vuln_rules.json")
    existed = rules_path.exists()
    if existed:
        try:
            rules = json.loads(rules_path.read_text(encoding="utf-8"))
        except Exception as e:
            print(f"ERROR: cannot read {rules_path} ({e}) - rules unchanged")
            return 1
        # self-heal incomplete files from built-in defaults instead of refusing
        missing = [k for k in REQUIRED_RULE_SECTIONS if not rules.get(k)]
        if missing:
            print(f"Warning: {rules_path} missing sections {missing} - restoring defaults")
            defaults = json.loads(json.dumps(DEFAULT_STATIC_RULES))
            for k in missing:
                rules[k] = defaults[k]
    else:
        print(f"Creating {rules_path} from built-in defaults + internet feeds ...")
        rules = json.loads(json.dumps(DEFAULT_STATIC_RULES))
    print("Fetching endoflife.date ...")
    upstream_eol, upstream_latest, products_ok = build_upstream_entries()
    if not products_ok and not upstream_eol:
        print("ERROR: no upstream data fetched - rules unchanged")
        return 1
    rules["upstream_eol"] = upstream_eol
    rules["upstream_latest"] = upstream_latest
    from datetime import date
    src = rules.get("sources") or {}
    src["endoflife_date"] = {"url": EOL_API_BASE, "fetched_at": date.today().isoformat(),
                             "products": sorted(products_ok),
                             "entries": len(upstream_eol)}
    print("Refreshing CISA KEV cache ...")
    kev = fetch_kev()
    src["cisa_kev"] = {"url": KEV_URL, "fetched_at": date.today().isoformat(),
                       "entries": len(kev)}
    rules["sources"] = src
    # backup (only when file existed) + atomic write (never leave a half-written file)
    if existed:
        try:
            backup = rules_path.with_name(rules_path.stem + ".bak.json")
            backup.write_text(rules_path.read_text(encoding="utf-8"), encoding="utf-8")
        except Exception as e:
            print(f"Warning: backup failed ({e})")
    tmp = rules_path.with_suffix(".tmp")
    tmp.write_text(json.dumps(rules, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(rules_path)
    n_os = sum(1 for e in upstream_eol if e.get("kind") == "os")
    print(f"Saved {rules_path}: upstream_eol={len(upstream_eol)} (os={n_os}, app={len(upstream_eol)-n_os}) "
          f"upstream_latest={upstream_latest}")
    return 0


def find_eol_hosts(data, rules):
    """Hosts whose OS matches EOL list (or empty OS). Returns list of dicts."""
    eol_entries = [e for e in (rules.get("eol_os") or [])] + \
                  [e for e in (rules.get("upstream_eol") or []) if e.get("kind", "os") == "os"]
    out = []
    for h in data.get("hosts", []):
        info = h.get("host", {}) if isinstance(h.get("host"), dict) else {}
        os_name = str(info.get("os") or "")
        low = normalize_name(os_name)
        hit = next((e for e in eol_entries if entry_matches(low, e)), None)
        if hit or not low:
            out.append({"ip": str(info.get("ip") or "").strip() or (info.get("display_name") or "?"),
                        "name": info.get("display_name") or info.get("dn") or "?",
                        "os": os_name or "(unknown)",
                        "label": hit["label"] if hit else "OS unknown",
                        "score": int(hit["score"]) if hit else 5})
    return out


def analyze(data, rules, kev=None):
    """Aggregate software across hosts and assess each (name, version)."""
    from collections import OrderedDict
    kev_index = build_kev_index(kev, rules) if kev else []
    norm_cache = {}
    agg = OrderedDict()
    for h in data.get("hosts", []):
        info = h.get("host", {}) if isinstance(h.get("host"), dict) else {}
        hid = str(info.get("ip") or "").strip().split(",")[0] or (info.get("display_name") or "?")
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
                                "count": 0, "hosts": []}
            e["count"] += 1
            if hid not in e["hosts"]:
                e["hosts"].append(hid)
    items = []
    for (nl, ver), e in agg.items():
        r = assess(e["name"], ver, e["publisher"], rules, kev_index, e["count"])
        nn = norm_cache.get(nl)
        if nn is None:
            nn = norm_cache[nl] = normalize_name(e["name"], rules)
        items.append({**e, "family": family_of(nn, rules),
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


def write_risk_excel(items, eol_hosts, summary, out):
    from openpyxl import Workbook
    from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
    wb = Workbook()
    hdr_font = Font(bold=True, color="FFFFFF")
    hdr_fill = PatternFill(start_color="C00000", end_color="C00000", fill_type="solid")
    thin = Side(style="thin", color="D9D9D9")
    bd = Border(left=thin, right=thin, top=thin, bottom=thin)
    center = Alignment(horizontal="center", vertical="center", wrap_text=True)
    left = Alignment(horizontal="left", vertical="center", wrap_text=True)
    fills = {"Critical": PatternFill(start_color="C00000", end_color="C00000", fill_type="solid"),
             "High": PatternFill(start_color="ED7D31", end_color="ED7D31", fill_type="solid"),
             "Medium": PatternFill(start_color="FFC000", end_color="FFC000", fill_type="solid"),
             "Low": PatternFill(start_color="FFF2CC", end_color="FFF2CC", fill_type="solid"),
             "Safe": PatternFill(start_color="E2EFDA", end_color="E2EFDA", fill_type="solid")}

    ws = wb.active
    ws.title = "Summary"
    ws.append(["Metric", "Value"])
    for c in range(1, 3):
        x = ws.cell(row=1, column=c)
        x.font = hdr_font
        x.fill = hdr_fill
        x.alignment = center
        x.border = bd
    rows = [("Generated", datetime.now(timezone.utc).isoformat(timespec="seconds")),
            ("Total hosts", summary["total_hosts"]),
            ("Unique software", summary["unique_software"]),
            ("Hosts at risk", summary["hosts_at_risk"]),
            ("EOL hosts", summary["eol_hosts"])] + \
        [(f"Items: {lv}", summary["by_level"].get(lv, 0)) for lv in ("Critical", "High", "Medium", "Low", "Safe")]
    for r, (k, v) in enumerate(rows, start=2):
        ws.cell(row=r, column=1, value=k).alignment = left
        ws.cell(row=r, column=2, value=v).alignment = center
        ws.cell(row=r, column=1).border = bd
        ws.cell(row=r, column=2).border = bd
    ws.column_dimensions["A"].width = 22
    ws.column_dimensions["B"].width = 30

    def dump(title, headers, rows, widths):
        w = wb.create_sheet(title)
        w.append(headers)
        for c in range(1, len(headers) + 1):
            x = w.cell(row=1, column=c)
            x.font = hdr_font
            x.fill = hdr_fill
            x.alignment = center
            x.border = bd
        for r, row in enumerate(rows, start=2):
            for c, v in enumerate(row, start=1):
                cell = w.cell(row=r, column=c, value=v)
                cell.alignment = center if c in (2, 4, 5) else left
                cell.border = bd
                if headers[c - 1] == "Risk" and v in fills:
                    cell.fill = fills[v]
        for col, wd in zip("ABCDEFGH", widths):
            w.column_dimensions[col].width = wd
        w.freeze_panes = "A2"
        if rows:
            w.auto_filter.ref = f"A1:{w.cell(row=1, column=len(headers)).column_letter}{len(rows) + 1}"

    risky = [it for it in items if it["score"] >= 4]
    dump("Critical Actions",
         ["Software", "Version", "Risk", "Hosts", "Sample IPs", "Fix Action"],
         [[it["name"], it["version"], it["level"], it["count"], ", ".join(it["hosts"][:5]), it["action"]]
          for it in risky if it["score"] >= 7],
         [50, 18, 10, 8, 30, 40])
    dump("All Findings",
         ["Software", "Version", "Publisher", "Risk", "Score", "Hosts", "Reasons", "Fix Action"],
         [[it["name"], it["version"], it["publisher"], it["level"], it["score"], it["count"],
           " | ".join(it["reasons"] + [c["id"] for c in it["cves"]][:3]), it["action"]] for it in risky],
         [45, 16, 24, 10, 7, 8, 60, 35])
    dump("EOL Hosts", ["IP", "Hostname", "OS", "Issue"],
         [[h["ip"], h["name"], h["os"], h["label"]] for h in eol_hosts],
         [18, 25, 35, 35])
    wb.save(out)


def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser(description="Vulnerability triage for KSC inventory JSON")
    ap.add_argument("input", nargs="?", help="kaspersky_inventory_*.json")
    ap.add_argument("-o", "--output", help="risk report JSON path")
    ap.add_argument("--excel", action="store_true", help="also write risk_report_*.xlsx")
    ap.add_argument("--online", action="store_true", help="fetch KEV + NVD enrichment (needs internet)")
    ap.add_argument("--top", type=int, default=30, help="NVD-enriched items (default 30)")
    ap.add_argument("--rules", help="path to vuln_rules.json")
    ap.add_argument("--update-rules", action="store_true",
                    help="download endoflife.date + CISA KEV and refresh upstream sections of vuln_rules.json")
    a = ap.parse_args(argv)

    if a.update_rules:
        return update_rules_from_upstream(a.rules)
    if not a.input:
        ap.error("input is required (or use --update-rules)")

    rules = load_rules(a.rules)
    data = json.loads(Path(a.input).read_text(encoding="utf-8"))

    kev = fetch_kev() if a.online else load_kev_cache()
    if a.online and not kev:
        print("No KEV data available (offline?) - continuing without KEV")
        kev = []
    items = analyze(data, rules, kev or None)
    if a.online:
        import os
        enrich_nvd(items, rules, top=a.top, api_key=os.environ.get("NVD_API_KEY"))

    eol_hosts = find_eol_hosts(data, rules)
    summary = summarize(items, eol_hosts, len(data.get("hosts", [])))
    report = {"generated_at": datetime.now(timezone.utc).isoformat(), "input": str(a.input),
              "summary": summary, "eol_hosts": eol_hosts, "items": items}
    inp = Path(a.input)
    if a.output:
        out = Path(a.output)
    else:
        # الافتراضي: داخل مجلد out
        out = get_out_dir() / f"risk_report_{inp.stem}.json"
    out.write_text(json.dumps(report, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"Hosts {summary['total_hosts']} SW {summary['unique_software']} "
          f"Critical/High {summary['critical_high_items']} EOL-hosts {summary['eol_hosts']} "
          f"at-risk {summary['hosts_at_risk']}")
    print(f"Levels: {summary['by_level']}")
    print(f"Saved {out}")
    if a.excel:
        xout = out.with_suffix(".xlsx")
        write_risk_excel(items, eol_hosts, summary, str(xout))
        print(f"Saved {xout}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
