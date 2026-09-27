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
    n = max(len(a), len(b))
    a += (0,) * (n - len(a))
    b += (0,) * (n - len(b))
    return (a > b) - (a < b)


def entry_matches(norm, entry):
    """Supports {'match': 'substr'} and {'match_all': ['t1','t2',...]} (all tokens)."""
    m = entry.get("match")
    if m and m in norm:
        return True
    ma = entry.get("match_all")
    if ma and all(t in norm for t in ma):
        return True
    return False


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


def _check_eol(norm: str, rules: dict) -> Tuple[int, List[str], List[str]]:
    """Static + upstream EOL matches. Returns (score, reasons, actions)."""
    score, reasons, actions = 0, [], []
    for item in (rules.get("eol_products") or []) + (rules.get("upstream_eol") or []):
        if item.get("kind", "app") != "app":
            continue
        if entry_matches(norm, item):
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

    Edge shares Chromium majors with Chrome, so it reuses the chrome entry.
    """
    score, reasons, actions = 0, [], []
    up_latest = rules.get("upstream_latest") or {}
    fam_key = "google chrome" if fam == "microsoft edge" else fam
    if not (fam_key in up_latest and version and str(version).strip()):
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
        _check_eol(norm, rules),
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
        r = assess(e["name"], ver, e["publisher"], rules, kev_index)
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
    rows = [("Generated", datetime.now(timezone.utc).isoformat(timespec="seconds")),
            ("Total hosts", summary["total_hosts"]),
            ("Unique software", summary["unique_software"]),
            ("Hosts at risk", summary["hosts_at_risk"]),
            ("EOL hosts", summary["eol_hosts"])] + \
        [(f"Items: {lv}", summary["by_level"].get(lv, 0)) for lv in RISK_LEVELS]
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
    ap.add_argument("--online", action="store_true", help="fetch KEV + NVD enrichment (needs internet)")
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
