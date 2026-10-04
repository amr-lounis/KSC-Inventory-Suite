#!/usr/bin/env python3
"""Build/refresh vuln_rules.json from the internet only (standalone).

Sources (agreed schemas, no API key needed):
  - endoflife.date API  (EOL dates + supported branches per product)
  - CISA KEV catalog    (actively exploited vulnerabilities)
  - vendor version APIs  (Edge, Mozilla, Chrome, VideoLAN, GitHub, Adoptium-style
                          via endoflife) for latest safe versions per family

Usage:
    py vuln_update.py [--rules path/to/vuln_rules.json]

Creates the file from built-in defaults when missing, otherwise refreshes
only the upstream sections (upstream_eol / upstream_latest / sources)
and keeps user customizations untouched. Stdlib only.
"""
import json
import os
import re
import sys
import unicodedata
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

UA = {"User-Agent": "ksc-inventory/1.0"}
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EOL_API_BASE = "https://endoflife.date/api"
UPDATE_WORKERS = 8  # parallel endoflife.date downloads (I/O bound)

_PAREN_RE = re.compile(r"\(.*?\)")
_WS_RE = re.compile(r"\s+")
_MAJOR_RE = re.compile(r"(\d+)")


def get_app_dir():
    if getattr(sys, "frozen", False):
        return Path(sys.executable).parent
    return Path(__file__).parent


def get_out_dir():
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


def strip_accents(s):
    return "".join(c for c in unicodedata.normalize("NFKD", s) if not unicodedata.combining(c))


def clean_label(label):
    s = strip_accents(str(label or "").lower())
    s = _PAREN_RE.sub(" ", s)
    return _WS_RE.sub(" ", s).strip()


def first_token(release) -> str:
    return (clean_label(release.get("releaseLabel") or release.get("cycle")).split() or ["?"])[0]


def major_of(label) -> Optional[int]:
    m = _MAJOR_RE.match(clean_label(label))
    return int(m.group(1)) if m else None


def is_past_date(eol_str, today) -> bool:
    try:
        return datetime.strptime(str(eol_str)[:10], "%Y-%m-%d").date() < today
    except (ValueError, TypeError):
        return False


def fetch_json(url, timeout=30):
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8"))

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
# edge is Chromium-based: fetched directly when available, otherwise
# vuln_check falls back to chrome majors for microsoft edge / opera.
EVERGREEN_UPSTREAM = {"chrome": "google chrome", "edge": "microsoft edge", "firefox": "mozilla firefox"}

_VERSION_RE = re.compile(r"(\d+(?:\.\d+)*)")


def _clean_version(raw) -> Optional[str]:
    """Normalize a fetched version ('v8.9.8' -> '8.9.8'); None if not version-like."""
    s = str(raw or "").strip()
    s = s[1:] if s[:1] in ("v", "V") and len(s) > 1 and s[1].isdigit() else s
    m = _VERSION_RE.fullmatch(s)
    return m.group(1) if m else None


def _github_headers():
    """GitHub API headers; uses GITHUB_TOKEN env when set to avoid 60 req/hour limit."""
    h = dict(UA)
    h["Accept"] = "application/vnd.github+json"
    tok = (os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN") or "").strip()
    if tok:
        h["Authorization"] = f"Bearer {tok}"
    return h


def _provider_github(repo: str, timeout=20):
    req = urllib.request.Request(
        f"https://api.github.com/repos/{repo}/releases/latest", headers=_github_headers())
    with urllib.request.urlopen(req, timeout=timeout) as r:
        # Respect rate-limit headers: fail fast with a clear message.
        remaining = r.headers.get("X-RateLimit-Remaining")
        if remaining is not None and str(remaining).strip() == "0":
            raise ValueError("GitHub rate limit exceeded (set GITHUB_TOKEN)")
        d = json.loads(r.read().decode("utf-8"))
    if d.get("prerelease"):
        raise ValueError("latest is a prerelease")
    v = _clean_version(d.get("tag_name") or d.get("name"))
    if not v:
        raise ValueError(f"bad tag {d.get('tag_name')!r}")
    return v


def _provider_videolan(timeout=25):
    req = urllib.request.Request("https://download.videolan.org/pub/videolan/vlc/last-win64.txt",
                                 headers=UA)
    # NOTE: don't use fetch_json (plain text, not JSON)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        v = _clean_version(r.read().decode("utf-8", "replace").strip())
    if not v:
        raise ValueError("bad videolan response")
    return v


def _endoflife_releases(product: str, timeout=30):
    return fetch_eol_product(product, timeout=timeout)


def _ver_key(s) -> tuple:
    """Numeric version tuple for branch comparison (local, no deps)."""
    parts = re.findall(r"\d+", str(s or ""))
    return tuple(int(x) for x in parts[:4]) if parts else (0,)


def _oldest_supported(releases: list, today, lts_only=False):
    """Oldest non-EOL branch (optionally LTS-only) -> its latest version."""
    cands = []
    for x in releases:
        if x.get("eol") and is_past_date(x.get("eol"), today):
            continue
        if lts_only and not x.get("lts"):
            continue
        latest = (x.get("latest") or "").strip()
        if not latest or not _clean_version(latest):
            continue
        cyc = clean_label(x.get("cycle")).split()
        key = _ver_key(cyc[0]) if cyc else (0,)
        cands.append((key, latest))
    if not cands:
        return None
    cands.sort(key=lambda t: t[0])
    return cands[0][1]


def _provider_endoflife_min(product: str, lts_only=False, timeout=30):
    from datetime import date
    v = _oldest_supported(_endoflife_releases(product, timeout), date.today(), lts_only)
    if not v:
        raise ValueError("no supported branch")
    return v


# our family -> (fetch callable, fix action). All live; failures skip the family.
# NOTE: browsers (chrome/firefox/edge/opera) are intentionally NOT here: they
# use evergreen freshness vs latest major (edge/opera fall back to Chromium majors).
# A min==latest check would score even a days-old browser as High (floor 8).
VERSION_PROVIDERS = {
    "vlc media player": (lambda: _provider_videolan(), "Update VLC"),
    "notepad++": (lambda: _provider_github("notepad-plus-plus/notepad-plus-plus"), "Update Notepad++"),
    "ocs inventory": (lambda: _provider_github("OCSInventory-NG/WindowsAgent"), "Update OCS agent"),
    "python": (lambda: _provider_endoflife_min("python"), "Upgrade Python"),
    "java": (lambda: _provider_endoflife_min("oracle-jdk", lts_only=True), "Update Java / remove if unused"),
}


def build_min_safe_versions() -> Tuple[dict, List[str]]:
    """Fetch latest safe versions per family. Returns (min_safe, report_lines)."""
    from concurrent.futures import ThreadPoolExecutor

    def _run(item):
        fam, (fn, _action) = item
        try:
            return fam, fn(), None
        except Exception as e:
            return fam, None, str(e)

    results = {}
    with ThreadPoolExecutor(max_workers=6) as ex:
        for fam, ver, err in ex.map(_run, VERSION_PROVIDERS.items()):
            results[fam] = (ver, err)
    min_safe, report = {}, []
    for fam in VERSION_PROVIDERS:
        ver, err = results[fam]
        _fn, action = VERSION_PROVIDERS[fam]
        if ver:
            min_safe[fam] = {"min": ver, "action": action, "source": "internet (vuln_update)"}
            report.append(f"  [ok] {fam}: min {ver}")
        else:
            report.append(f"  [skip] {fam}: {err}")
    return min_safe, report

REQUIRED_RULE_SECTIONS = ("aliases", "family_patterns", "noise_patterns", "generic_tokens")

# Local normalization dictionaries (NOT vulnerability rules): describe OUR data quirks
# (French names, mojibake, noise). These cannot come from the internet; everything
# else in vuln_rules.json (scores, EOL dates, versions) is generated from online feeds.
DEFAULT_STATIC_RULES = {
  "_comment": "vuln_rules.json is GENERATED from the internet (endoflife.date + CISA KEV + vendor version APIs) by vuln_update.py. Only the *-dictionaries below (aliases/family/noise/generic) are local normalization knowledge; all scores, EOL dates and versions come from online feeds.",
  "family_patterns": [
    ["google chrome", "google chrome"],
    ["microsoft edge", "microsoft edge"],
    ["firefox", "mozilla firefox"],
    ["opera", "opera"],
    ["adobe acrobat", "adobe acrobat"],
    ["adobe reader", "adobe reader"],
    ["acrobat reader", "adobe reader"],
    ["java", "java"],
    ["openjdk", "java"],
    ["jre", "java"],
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


def fetch_eol_product(product, timeout=30):
    data = fetch_json(f"{EOL_API_BASE}/{product}.json", timeout=timeout)
    return data if isinstance(data, list) else []


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
        d = fetch_json(KEV_URL, timeout=timeout)
        vulns = d.get("vulnerabilities", [])
        cache_path("kev_cache.json").write_text(json.dumps(
            {"fetched_at": datetime.now(timezone.utc).isoformat(), "count": len(vulns),
             "vulnerabilities": vulns}, ensure_ascii=False), encoding="utf-8")
        print(f"KEV cache updated: {len(vulns)} entries")
        return vulns
    except Exception as e:
        print(f"KEV download failed ({e}) - using cache")
        return load_kev_cache()


def _download_all(all_products: List[str]) -> Dict[str, tuple]:
    """Parallel downloads; returns {product: (releases, error)} in fixed order."""

    def _fetch(product):
        try:
            return product, fetch_eol_product(product), None
        except Exception as e:
            return product, [], str(e)

    fetched = {}
    with ThreadPoolExecutor(max_workers=UPDATE_WORKERS) as ex:
        for product, releases, err in ex.map(_fetch, all_products):
            fetched[product] = (releases, err)
    return fetched


def _windows_major_entries(releases: list, today) -> List[dict]:
    """Bare-major matches only when the whole major line is EOL (7/8/8.1/XP/Vista),
    never for 10/11 (supported editions exist and KSC strings lack build numbers)."""
    by_major: Dict[str, dict] = {}
    for x in releases:
        tok = first_token(x)
        st = by_major.setdefault(tok, {"eol": 0, "total": 0})
        st["total"] += 1
        if x.get("eol") and is_past_date(x.get("eol"), today):
            st["eol"] += 1
    entries = []
    for tok, st in sorted(by_major.items()):
        if st["eol"] == st["total"]:
            eol_date = max(x["eol"] for x in releases if first_token(x) == tok)
            entries.append({
                "match_all": ["windows", tok], "kind": "os", "score": 10,
                "label": f"Windows {tok.upper()} (EOL {eol_date}, endoflife.date)",
                "eol": eol_date, "product": "windows",
                "action": "Upgrade/Migrate to a supported Windows"})
    return entries


def _labeled_entries(product: str, kind: str, keyword: Optional[str], use_cycle: bool,
                     eol_rels: list, supported_tokens: set) -> List[dict]:
    entries = []
    for x in eol_rels:
        raw = x.get("releaseLabel") or x.get("cycle") or ""
        norm = clean_label(raw)
        if use_cycle:
            cyc = clean_label(x.get("cycle")).split()
            token = cyc[0] if cyc else (norm.split()[0] if norm.split() else "")
        else:
            token = norm.split()[0] if norm.split() else ""
        if keyword:
            if not token:
                entry = {"match_all": [keyword]}
            elif any(s != token and s.startswith(token) for s in supported_tokens):
                # token is a mere prefix of a SUPPORTED release (e.g. 3.1 vs 3.10) -> skip
                continue
            else:
                entry = {"match_all": [keyword, token]}
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
        entries.append(entry)
    return entries


def _evergreen_latest(product: str, releases: list, today) -> Optional[dict]:
    majors = []
    for x in releases:
        if x.get("eol") and is_past_date(x.get("eol"), today):
            continue
        m = major_of(x.get("releaseLabel") or x.get("cycle"))
        if m:
            majors.append(m)
    if not majors:
        return None
    return {"major": max(majors), "checked": today.isoformat(),
            "source": f"endoflife.date/{product}"}


def build_upstream_entries(today=None):
    """Fetch endoflife.date and build (upstream_eol, upstream_latest, products_ok)."""
    today = today or date.today()
    upstream_eol, upstream_latest, products_ok = [], {}, []
    all_products = list(EOL_UPSTREAM_PRODUCTS) + list(EVERGREEN_UPSTREAM)
    fetched = _download_all(all_products)
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
        eol_rels = [x for x in releases if x.get("eol") and is_past_date(x.get("eol"), today)]
        supported_tokens = set()
        for x in releases:
            if x.get("eol") and is_past_date(x.get("eol"), today):
                continue
            cyc = clean_label(x.get("cycle")).split()
            if cyc:
                supported_tokens.add(cyc[0])
            lab = clean_label(x.get("releaseLabel") or "").split()
            if lab:
                supported_tokens.add(lab[0])
        if product == "windows":
            upstream_eol.extend(_windows_major_entries(releases, today))
        else:
            upstream_eol.extend(_labeled_entries(product, kind, keyword, use_cycle,
                                                 eol_rels, supported_tokens))
        if product in EVERGREEN_UPSTREAM:
            latest = _evergreen_latest(product, releases, today)
            if latest:
                upstream_latest[EVERGREEN_UPSTREAM[product]] = latest
    upstream_eol.sort(key=lambda e: (e.get("kind", ""), e.get("label", "")))
    return upstream_eol, upstream_latest, products_ok


def _load_or_seed(rules_path: Path) -> Tuple[Optional[dict], bool]:
    """Returns (rules, existed). Seeds from built-in defaults when missing/incomplete."""
    if not rules_path.exists():
        print(f"Creating {rules_path} from built-in defaults + internet feeds ...")
        return json.loads(json.dumps(DEFAULT_STATIC_RULES)), False
    try:
        rules = json.loads(rules_path.read_text(encoding="utf-8"))
    except Exception as e:
        print(f"ERROR: cannot read {rules_path} ({e}) - rules unchanged")
        return None, True
    missing = [k for k in REQUIRED_RULE_SECTIONS if not rules.get(k)]
    if missing:
        print(f"Warning: {rules_path} missing sections {missing} - restoring defaults")
        defaults = json.loads(json.dumps(DEFAULT_STATIC_RULES))
        for k in missing:
            rules[k] = defaults[k]
    return rules, True


def _save_rules(rules_path: Path, rules: dict, existed: bool) -> None:
    """Backup (if existed) + atomic write."""
    if existed:
        try:
            backup = rules_path.with_name(rules_path.stem + ".bak.json")
            backup.write_text(rules_path.read_text(encoding="utf-8"), encoding="utf-8")
        except Exception as e:
            print(f"Warning: backup failed ({e})")
    tmp = rules_path.with_suffix(".tmp")
    tmp.write_text(json.dumps(rules, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(rules_path)


def update_rules_from_upstream(rules_path=None):
    """Create (if missing) or refresh vuln_rules.json from standard internet feeds."""
    rules_path = Path(rules_path) if rules_path else resource_path("vuln_rules.json")
    rules, existed = _load_or_seed(rules_path)
    if rules is None:
        return 1
    print("Fetching endoflife.date ...")
    upstream_eol, upstream_latest, products_ok = build_upstream_entries()
    if not products_ok and not upstream_eol:
        print("ERROR: no upstream data fetched - rules unchanged")
        return 1
    rules["upstream_eol"] = upstream_eol
    rules["upstream_latest"] = upstream_latest
    print("Fetching latest safe versions ...")
    min_safe, version_report = build_min_safe_versions()
    print("\n".join(version_report))
    rules["min_safe_versions"] = min_safe
    # eol lists are fully upstream-generated; drop stale hand-written sections
    # (upstream covers Windows/Server/Office/Java/Python EOL; KEV still signals the rest)
    rules["eol_os"] = []
    rules["eol_products"] = []
    src = rules.get("sources") or {}
    src["endoflife_date"] = {"url": EOL_API_BASE, "fetched_at": date.today().isoformat(),
                             "products": sorted(products_ok),
                             "entries": len(upstream_eol)}
    print("Refreshing CISA KEV cache ...")
    kev = fetch_kev()
    src["cisa_kev"] = {"url": KEV_URL, "fetched_at": date.today().isoformat(),
                       "entries": len(kev)}
    rules["sources"] = src
    _save_rules(rules_path, rules, existed)
    n_os = sum(1 for e in upstream_eol if e.get("kind") == "os")
    print(f"Saved {rules_path}: upstream_eol={len(upstream_eol)} (os={n_os}, app={len(upstream_eol)-n_os}) "
          f"min_safe={len(min_safe)} upstream_latest={upstream_latest}")
    print("Note: families without a version API (e.g. Acrobat, WinRAR, TeamViewer, "
          "AnyDesk, Opera, Kaspersky, VMware, Flash, VC++) rely on EOL + CISA KEV signals only.")
    return 0


def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser(description="Build/refresh vuln_rules.json from endoflife.date + CISA KEV")
    ap.add_argument("--rules", help="path to vuln_rules.json (default: next to script/exe)")
    a = ap.parse_args(argv)
    return update_rules_from_upstream(a.rules)


if __name__ == "__main__":
    raise SystemExit(main())
