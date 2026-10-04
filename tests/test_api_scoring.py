"""API-based scoring: CVSS calc, strict EOL matching, NVD CPE ranges, OSV merge."""
import vuln_check as vc


def _rules():
    return {
        "aliases": {}, "family_patterns": [["google chrome", "google chrome"],
                                           ["java", "java"],
                                           ["python", "python"]],
        "noise_patterns": [], "generic_tokens": [],
        "eol_products": [], "eol_os": [],
        "upstream_eol": [
            {"match_all": ["chrome", "100"], "kind": "app", "score": 9,
             "label": "100 (EOL)", "action": "Upgrade"},
            {"match_all": ["java", "7"], "kind": "app", "score": 9,
             "label": "7 (EOL)", "action": "Upgrade"},
            {"match_all": ["office", "2007"], "kind": "app", "score": 9,
             "label": "2007 SP3 (EOL)", "action": "Upgrade"},
        ],
        "min_safe_versions": {}, "upstream_latest": {},
    }


# ---------- CVSS v3.1 calculator ----------

def test_cvss_known_vectors():
    assert vc.cvss_v3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H") == 10.0
    assert vc.cvss_v3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == 9.8
    assert vc.cvss_v3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N") == 6.1
    assert vc.cvss_v3_base_score("CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N") == 0.0


def test_cvss_bad_input():
    assert vc.cvss_v3_base_score("") is None
    assert vc.cvss_v3_base_score("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H") is None
    assert vc.cvss_v3_base_score("garbage") is None


# ---------- strict EOL matching ----------

def test_eol_no_substring_bleed():
    assert vc._eol_entry_matches("java", "17.0.20", {"match_all": ["java", "7"]}) is False
    assert vc._eol_entry_matches("google chrome", "152.0", {"match_all": ["chrome", "15"]}) is False
    assert vc._eol_entry_matches("google chrome", "100.0", {"match_all": ["chrome", "10"]}) is False


def test_eol_true_positives_kept():
    assert vc._eol_entry_matches("google chrome", "100.0", {"match_all": ["chrome", "100"]}) is True
    assert vc._eol_entry_matches("microsoft office professional plus 2007", "12.0.1",
                                {"match_all": ["office", "2007"]}) is True


def test_assess_eol_fixed():
    rules = _rules()
    assert vc.assess("Java", "17.0.20", "", rules, None)["score"] < 9
    r = vc.assess("Google Chrome", "100.0", "", rules, None)
    assert r["score"] == 9 and r["level"] == "Critical"


def test_python_lib_skipped():
    rules = dict(_rules(), min_safe_versions={"python": {"min": "3.10.21", "action": "Upgrade"}})
    r = vc.assess("python3-apt", "2.7.7ubuntu5.1", "", rules, None)
    assert r["score"] == 0 and r["level"] == "Safe"
    r2 = vc.assess("Python 3.12", "3.9.0", "", rules, None)
    assert r2["score"] > 0  # real interpreter still checked


# ---------- NVD CPE range matching ----------

def test_nvd_range_hit():
    m = {"versionStartIncluding": "100.0", "versionEndExcluding": "120.0"}
    assert vc._nvd_range_hit("cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*", m, "110.0") is True
    assert vc._nvd_range_hit("cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*", m, "130.0") is False
    assert vc._nvd_range_hit("cpe:2.3:a:google:chrome:100.0:*:*:*:*:*:*:*",
                            {}, "100.0") is True
    assert vc._nvd_range_hit("cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*",
                            {}, "100.0") is None


def _nvd_raw():
    return {"vulnerabilities": [
        {"cve": {"id": "CVE-2024-0001", "published": "2024-01-01T00:00Z",
                 "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8}}]},
                 "configurations": [{"nodes": [{"cpeMatch": [
                     {"criteria": "cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*",
                      "vulnerable": True, "versionEndExcluding": "120.0"}]}]}]}},
        {"cve": {"id": "CVE-2024-0002", "published": "2024-02-01T00:00Z",
                 "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 5.4}}]},
                 "configurations": [{"nodes": [{"cpeMatch": [
                     {"criteria": "cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*",
                      "vulnerable": True, "versionStartIncluding": "130.0"}]}]}]}},
    ]}


def test_enrich_nvd_cpe_version_aware(tmp_path):
    items = [{"name": "Google Chrome", "version": "100.0", "publisher": "Google",
              "family": "google chrome", "os": ["windows"], "count": 1, "hosts": ["h1"],
              "score": 0, "level": "Safe", "reasons": [], "action": "-", "cves": []}]
    out = tmp_path / "nvd.json"
    vc.enrich_nvd_cpe(items, cache_file=str(out), fetcher=lambda cpe: _nvd_raw())
    assert items[0]["score"] == 9.8
    assert items[0]["level"] == "Critical"
    assert any("CVE-2024-0001" in r for r in items[0]["reasons"])
    assert not any("CVE-2024-0002" in r for r in items[0]["reasons"])


# ---------- OSV merge ----------

def _osv_results(queries):
    out = []
    for q in queries:
        eco = q["package"]["ecosystem"]
        if q["package"]["name"] == "apt" and eco == "Ubuntu:22.04":
            out.append({"vulns": [
                {"id": "CVE-2024-0010", "published": "2024-03-01T00:00Z",
                 "summary": "x",
                 "severity": [{"type": "CVSS_V3",
                               "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]}]})
        else:
            out.append({})
    return {"results": out}


def test_enrich_osv_confirmed_cvss(tmp_path):
    items = [{"name": "python3-apt", "version": "2.7.7ubuntu5.1", "publisher": "",
              "family": "python", "os": ["linux"], "count": 1, "hosts": ["h1"],
              "score": 0, "level": "Safe", "reasons": [], "action": "-", "cves": []}]
    out = tmp_path / "osv.json"
    vc.enrich_osv(None, items, cache_file=str(out), fetcher=_osv_results)
    assert items[0]["score"] == 9.8
    assert items[0]["level"] == "Critical"
    assert any("CVE-2024-0010" in r for r in items[0]["reasons"])


def test_osv_text_severity_fallback():
    sc, approx = vc._osv_cvss({"severity": [],
                               "database_specific": {"severity": "High"}})
    assert sc == 7.5 and approx is True
    assert vc._osv_cvss({}) == (None, False)
