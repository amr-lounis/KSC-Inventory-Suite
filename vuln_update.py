#!/usr/bin/env python3
"""Build/refresh vuln_rules.json from standard internet feeds (standalone).

Sources (agreed schemas, no API key needed):
  - endoflife.date API  (EOL dates + latest releases per product)
  - CISA KEV catalog    (actively exploited vulnerabilities)

Usage:
    py vuln_update.py [--rules path/to/vuln_rules.json]

Creates the file from built-in defaults when missing, otherwise refreshes
only the upstream sections (upstream_eol / upstream_latest / sources)
and keeps user customizations untouched. Stdlib only.
"""
import json
import re
import sys
import unicodedata
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import date, datetime, timezone
from pathlib import Path

UA = {"User-Agent": "ksc-inventory/1.0"}
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
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
    s = re.sub(r"\(.*?\)", " ", s)
    return re.sub(r"\s+", " ", s).strip()


def is_past(eol_str, today):
    try:
        return datetime.strptime(str(eol_str)[:10], "%Y-%m-%d").date() < today
    except (ValueError, TypeError):
        return False


def fetch_json(url, timeout=30):
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8"))


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


def build_upstream_entries(today=None):
    """Fetch endoflife.date and build (upstream_eol, upstream_latest, products_ok)."""
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


def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser(description="Build/refresh vuln_rules.json from endoflife.date + CISA KEV")
    ap.add_argument("--rules", help="path to vuln_rules.json (default: next to script/exe)")
    a = ap.parse_args(argv)
    return update_rules_from_upstream(a.rules)


if __name__ == "__main__":
    raise SystemExit(main())
