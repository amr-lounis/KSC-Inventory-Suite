"""Tests for vuln_check.py - offline vulnerability triage logic."""
import json
import pytest

import vuln_check as vc


@pytest.fixture
def minimal_rules():
    return {
        "aliases": {},
        "family_patterns": [
            ["google chrome", "google chrome"],
            ["microsoft edge", "microsoft edge"],
            ["firefox", "mozilla firefox"],
            ["java", "java"],
            ["vlc", "vlc media player"],
        ],
        "noise_patterns": ["windows qfe", "language pack"],
        "generic_tokens": ["microsoft", "windows", "for", "update"],
        "eol_products": [],
        "upstream_eol": [],
        "min_safe_versions": {},
        "upstream_latest": {},
    }


def test_parse_version_basic():
    assert vc.parse_version("100.0.4896.75") == (100, 0, 4896, 75)
    assert vc.parse_version("v3.0.21") == (3, 0, 21)
    assert vc.parse_version("") == ()
    assert vc.parse_version(None) == ()


def test_parse_version_truncates_to_6_parts():
    assert vc.parse_version("1.2.3.4.5.6.7.8") == (1, 2, 3, 4, 5, 6)


def test_cmp_versions_equal_unequal_lengths():
    # (1,2) == (1,2,0) after zero-padding
    assert vc.cmp_versions((1, 2), (1, 2, 0)) == 0
    assert vc.cmp_versions((1, 2), (1, 3)) < 0
    assert vc.cmp_versions((2, 0), (1, 9)) > 0


def test_cmp_versions_does_not_mutate_inputs():
    a = (1, 2)
    b = (1, 2, 0)
    vc.cmp_versions(a, b)
    assert a == (1, 2)
    assert b == (1, 2, 0)


def test_normalize_name_lowercase_and_aliases():
    rules = {"aliases": {"googlechrome": "google chrome"}}
    assert vc.normalize_name("GoogleChrome", rules) == "google chrome"
    assert vc.normalize_name("  VLC   Media  Player ", None) == "vlc media player"


def test_family_of_word_boundary():
    rules = {"family_patterns": [["java", "java"]]}
    assert vc.family_of("java 8 update 381", rules) == "java"
    # 'java' must not match 'javascript'
    assert vc.family_of("javascript runtime", rules) is None


def test_is_noise():
    rules = {"noise_patterns": ["windows qfe", "language pack"]}
    assert vc.is_noise("windows qfe update", rules) is True
    assert vc.is_noise("google chrome", rules) is False


def test_level_of_thresholds():
    assert vc.level_of(10) == "Critical"
    assert vc.level_of(9) == "Critical"
    assert vc.level_of(8) == "High"
    assert vc.level_of(7) == "High"
    assert vc.level_of(4) == "Medium"
    assert vc.level_of(1) == "Low"
    assert vc.level_of(0) == "Safe"


def test_entry_matches_substr_and_match_all():
    assert vc.entry_matches("windows 7 pro", {"match": "windows 7"}) is True
    assert vc.entry_matches("google chrome", {"match_all": ["chrome", "100"]}) is False
    assert vc.entry_matches("google chrome 100", {"match_all": ["chrome", "100"]}) is True


def test_check_eol_uses_version_field_regression(minimal_rules):
    """Regression: EOL entries like ['chrome','100'] must match version in
    separate field, not only DisplayName."""
    minimal_rules["upstream_eol"] = [
        {"match_all": ["chrome", "100"], "kind": "app", "score": 9,
         "label": "100 EOL", "action": "Upgrade"},
    ]
    # Name alone has no '100' -> old code missed this
    s, reasons, _ = vc._check_eol("google chrome", "100.0.0.0", minimal_rules)
    assert s == 9
    assert reasons == ["100 EOL"]
    # Safe version must not match
    s2, _, _ = vc._check_eol("google chrome", "152.0.0.0", minimal_rules)
    assert s2 == 0


def test_check_eol_ignores_os_kind(minimal_rules):
    minimal_rules["upstream_eol"] = [
        {"match_all": ["windows", "7"], "kind": "os", "score": 10, "label": "Win7 EOL"},
    ]
    s, _, _ = vc._check_eol("windows 7", "6.1", minimal_rules)
    assert s == 0  # app check skips kind=os


def test_check_min_version_outdated_and_current(minimal_rules):
    minimal_rules["min_safe_versions"] = {
        "vlc media player": {"min": "3.0.21", "action": "Update VLC"},
    }
    s, reasons, acts = vc._check_min_version(
        "vlc media player", "vlc media player", "3.0.0", "VLC", minimal_rules)
    assert s >= 5
    assert any("3.0.0" in r for r in reasons)
    assert acts == ["Update VLC"]

    s2, r2, _ = vc._check_min_version(
        "vlc media player", "vlc media player", "3.0.21", "VLC", minimal_rules)
    assert s2 == 0
    assert r2 == []


def test_check_min_version_missing_version_is_safe(minimal_rules):
    minimal_rules["min_safe_versions"] = {
        "vlc media player": {"min": "3.0.21", "action": "Update VLC"},
    }
    s, r, _ = vc._check_min_version(
        "vlc media player", "vlc media player", "", "VLC", minimal_rules)
    assert (s, r) == (0, [])


def test_check_freshness_edge_opera_fallback_to_chrome(minimal_rules):
    minimal_rules["upstream_latest"] = {"google chrome": {"major": 152}}
    # Edge has no direct entry -> falls back to chrome
    s, reasons, _ = vc._check_freshness("microsoft edge", "120.0", minimal_rules)
    assert s >= 8
    assert reasons
    # Opera same fallback
    s2, _, _ = vc._check_freshness("opera", "120.0", minimal_rules)
    assert s2 >= 6
    # Current version -> no score
    s3, _, _ = vc._check_freshness("google chrome", "152.0", minimal_rules)
    assert s3 == 0


def test_check_freshness_prefers_direct_entry(minimal_rules):
    minimal_rules["upstream_latest"] = {
        "google chrome": {"major": 152},
        "microsoft edge": {"major": 150},
    }
    s, reasons, _ = vc._check_freshness("microsoft edge", "140.0", minimal_rules)
    assert s > 0
    assert "150" in reasons[0]


def test_assess_empty_version_is_not_safe(minimal_rules):
    r = vc.assess("Some App", "", "", minimal_rules, None)
    assert r["score"] == 4
    assert r["level"] == "Medium"
    assert any("Version missing" in x for x in r["reasons"])


def test_assess_noise_is_safe(minimal_rules):
    r = vc.assess("Windows QFE Update KB123", "1.0", "", minimal_rules, None)
    assert r["level"] == "Safe"
    assert r["score"] == 0


def test_assess_unknown_app_without_evidence_is_safe(minimal_rules):
    r = vc.assess("My Custom Internal Tool", "1.0.0", "MyCompany", minimal_rules, None)
    assert r == {"score": 0, "level": "Safe", "reasons": [], "action": "-"}


def test_kev_bump_to_critical_when_outdated(minimal_rules):
    kev = [{"cveID": "CVE-2023-1234", "product": "VLC Media Player",
            "vendorProject": "VideoLAN", "vulnerabilityName": "RCE"}]
    index = vc.build_kev_index(kev, minimal_rules)
    s, reasons, acts = vc._check_kev("vlc media player 3.0.0", "", 8, minimal_rules, index)
    assert s == 10
    assert any("actively exploited" in r for r in reasons)
    assert acts


def test_kev_informational_when_current(minimal_rules):
    kev = [{"cveID": "CVE-2023-1234", "product": "VLC Media Player",
            "vendorProject": "VideoLAN", "vulnerabilityName": "RCE"}]
    index = vc.build_kev_index(kev, minimal_rules)
    s, reasons, _ = vc._check_kev("vlc media player", "", 0, minimal_rules, index)
    assert s == 3
    assert reasons


def test_build_kev_index_skips_vendor_only_labels(minimal_rules):
    kev = [{"cveID": "CVE-1", "product": "Microsoft",
            "vendorProject": "Microsoft", "vulnerabilityName": "X"}]
    assert vc.build_kev_index(kev, minimal_rules) == []


def test_analyze_aggregates_hosts_and_counts(minimal_rules):
    data = {
        "hosts": [
            {"host": {"ip": "10.0.0.1", "display_name": "PC1"},
             "software": [{"name": "VLC", "version": "3.0.0", "publisher": "VideoLAN"}]},
            {"host": {"ip": "10.0.0.2", "display_name": "PC2"},
             "software": [{"name": "VLC", "version": "3.0.0", "publisher": "VideoLAN"}]},
        ]
    }
    items = vc.analyze(data, minimal_rules, kev=None)
    assert len(items) == 1
    assert items[0]["count"] == 2
    assert set(items[0]["hosts"]) == {"10.0.0.1", "10.0.0.2"}


def test_summarize_counts(minimal_rules):
    items = [
        {"level": "Critical", "score": 10, "hosts": ["a"]},
        {"level": "Safe", "score": 0, "hosts": ["b"]},
    ]
    s = vc.summarize(items, [], total_hosts=2)
    assert s["total_hosts"] == 2
    assert s["unique_software"] == 2
    assert s["critical_high_items"] == 1
    assert s["by_level"]["Critical"] == 1


def test_find_eol_hosts_flags_unknown_os(minimal_rules):
    minimal_rules["eol_os"] = []
    minimal_rules["upstream_eol"] = []
    data = {"hosts": [{"host": {"ip": "1.2.3.4", "display_name": "PC",
                                "dn": "", "os": ""}}]}
    out = vc.find_eol_hosts(data, minimal_rules)
    assert len(out) == 1
    assert out[0]["label"] == "OS unknown"


def test_split_tokens_list_single_definition():
    # Regression: file had duplicated def; ensure one callable behavior
    assert vc.split_tokens_list("hello world foo", min_len=3, generic=()) == \
        ["hello", "world", "foo"]
