"""End-to-end: inventory JSON -> Excel report + risk report (offline, no network)."""
import json
from pathlib import Path

import vuln_check as vc
import json_to_excel as j2e


SAMPLE = {
    "generated_at": "2026-01-01T00:00:00+00:00",
    "ksc_server": "127.0.0.1",
    "total_hosts": 2,
    "hosts": [
        {"host": {"display_name": "PC1", "dn": "PC1", "fqdn": "",
                  "id": "PC1", "instance_id": "i1", "ip": "10.0.0.1",
                  "os": "Microsoft Windows 10 Pro", "nag_version": "",
                  "last_visible": ""},
         "software": [
             {"name": "Google Chrome", "version": "100.0.0.0",
              "publisher": "Google", "install_date": ""},
             {"name": "VLC media player", "version": "3.0.0",
              "publisher": "VideoLAN", "install_date": ""},
         ],
         "patches": [],
         "summary": {"total_products": 2, "total_patches": 0}},
        {"host": {"display_name": "SRV1", "dn": "SRV1", "fqdn": "",
                  "id": "SRV1", "instance_id": "i2", "ip": "10.0.0.2",
                  "os": "Ubuntu 22.04", "nag_version": "",
                  "last_visible": ""},
         "software": [
             {"name": "Python", "version": "2.7.18",
              "publisher": "Python", "install_date": ""},
         ],
         "patches": [],
         "summary": {"total_products": 1, "total_patches": 0}},
    ],
}

RULES = {
    "aliases": {},
    "family_patterns": [
        ["google chrome", "google chrome"],
        ["vlc", "vlc media player"],
        ["python", "python"],
    ],
    "noise_patterns": [],
    "generic_tokens": [],
    "eol_products": [],
    "upstream_eol": [
        {"match_all": ["chrome", "100"], "kind": "app", "score": 9,
         "label": "Chrome 100 EOL", "eol": "2022-04-26",
         "product": "chrome", "action": "Upgrade"},
        {"match_all": ["python", "2.7"], "kind": "app", "score": 9,
         "label": "Python 2.7 EOL", "eol": "2020-01-01",
         "product": "python", "action": "Upgrade Python"},
    ],
    "min_safe_versions": {
        "vlc media player": {"min": "3.0.21", "action": "Update VLC",
                             "source": "test"},
    },
    "upstream_latest": {"google chrome": {"major": 152}},
    "eol_os": [],
    "sources": {},
}


def test_inventory_to_excel(tmp_path):
    inp = tmp_path / "kaspersky_inventory_test.json"
    inp.write_text(json.dumps(SAMPLE), encoding="utf-8")
    out = tmp_path / "software_inventory_test.xlsx"
    assert j2e.process_one(str(inp), str(out)) == 0
    assert out.exists()
    split, counts = j2e.dedup_by_os(SAMPLE)
    assert counts == {"windows": 1, "linux": 1, "other": 0}
    assert len(split["windows"]) == 2
    assert len(split["linux"]) == 1


def test_inventory_to_risk_report(tmp_path):
    items = vc.analyze(SAMPLE, RULES, kev=None)
    by_name = {i["name"]: i for i in items}
    # Chrome 100 via EOL(version-aware) + freshness
    assert by_name["Google Chrome"]["score"] >= 9
    assert by_name["Google Chrome"]["level"] == "Critical"
    # VLC 3.0.0 < min 3.0.21
    assert by_name["VLC media player"]["score"] >= 5
    # Python 2.7 EOL
    assert by_name["Python"]["score"] == 9

    eol_hosts = vc.find_eol_hosts(SAMPLE, RULES)
    summary = vc.summarize(items, eol_hosts, total_hosts=2)
    assert summary["total_hosts"] == 2
    assert summary["critical_high_items"] >= 2

    out_json = tmp_path / "risk.json"
    out_json.write_text(json.dumps(
        {"summary": summary, "items": items, "eol_hosts": eol_hosts}),
        encoding="utf-8")
    assert out_json.exists()

    out_xlsx = tmp_path / "risk.xlsx"
    vc.write_risk_excel(items, eol_hosts, summary, str(out_xlsx))
    assert out_xlsx.exists()


def test_full_cli_vuln_check_offline(tmp_path, monkeypatch):
    inp = tmp_path / "kaspersky_inventory_cli.json"
    inp.write_text(json.dumps(SAMPLE), encoding="utf-8")
    rules_p = tmp_path / "vuln_rules.json"
    rules_p.write_text(json.dumps(RULES), encoding="utf-8")
    out = tmp_path / "risk_cli.json"
    # isolate out/ dir used by vuln_check cache helpers
    monkeypatch.setattr(vc, "get_app_dir", lambda: tmp_path)
    monkeypatch.setattr(vc, "get_out_dir", lambda: tmp_path)
    rc = vc.main([str(inp), "-o", str(out), "--rules", str(rules_p)])
    assert rc == 0
    report = json.loads(out.read_text(encoding="utf-8"))
    assert report["summary"]["total_hosts"] == 2
    assert report["summary"]["critical_high_items"] >= 2
