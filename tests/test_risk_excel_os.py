"""Risk report layout: Summary + Windows/Linux/Other Soft + EOL Hosts (all programs)."""
import json

from openpyxl import load_workbook

import vuln_check as vc


def _rules():
    return {
        "aliases": {},
        "family_patterns": [
            ["google chrome", "google chrome"],
            ["python", "python"],
        ],
        "noise_patterns": [],
        "generic_tokens": [],
        "eol_products": [],
        "upstream_eol": [
            {"match_all": ["chrome", "100"], "kind": "app", "score": 9,
             "label": "Chrome 100 EOL", "action": "Upgrade"},
        ],
        "min_safe_versions": {},
        "upstream_latest": {},
        "eol_os": [],
        "sources": {},
    }


def _data():
    return {
        "hosts": [
            {"host": {"display_name": "PC1", "dn": "PC1", "ip": "10.0.0.1",
                      "os": "Microsoft Windows 10 Pro"},
             "software": [
                 {"name": "Google Chrome", "version": "100.0", "publisher": "Google"},
                 {"name": "Safe Tool", "version": "1.0", "publisher": "X"},
             ]},
            {"host": {"display_name": "SRV1", "dn": "SRV1", "ip": "10.0.0.2",
                      "os": "Ubuntu 22.04"},
             "software": [
                 {"name": "Python", "version": "3.11", "publisher": "PSF"},
             ]},
        ]
    }


def test_classify_os():
    assert vc.classify_os("Microsoft Windows 11") == "windows"
    assert vc.classify_os("Ubuntu 22.04") == "linux"
    assert vc.classify_os("") == "other"
    assert vc.classify_os(None) == "other"


def test_analyze_tracks_os():
    items = vc.analyze(_data(), _rules(), kev=None)
    by_name = {i["name"]: i for i in items}
    assert by_name["Google Chrome"]["os"] == ["windows"]
    assert by_name["Python"]["os"] == ["linux"]
    assert by_name["Google Chrome"]["hosts_by_os"]["windows"] == ["10.0.0.1"]
    assert by_name["Python"]["os_counts"]["linux"] == 1


def test_risk_excel_has_os_sheets_and_no_old_ones(tmp_path):
    items = vc.analyze(_data(), _rules(), kev=None)
    summary = vc.summarize(items, [], total_hosts=2)
    out = tmp_path / "risk.xlsx"
    vc.write_risk_excel(items, [], summary, str(out))
    wb = load_workbook(out)
    assert wb.sheetnames == ["Summary", "Windows Soft", "Linux Soft",
                             "Other Soft", "EOL Hosts"]
    assert "Critical Actions" not in wb.sheetnames
    assert "All Findings" not in wb.sheetnames


def test_os_sheets_show_all_programs_including_safe(tmp_path):
    items = vc.analyze(_data(), _rules(), kev=None)
    summary = vc.summarize(items, [], total_hosts=2)
    out = tmp_path / "risk.xlsx"
    vc.write_risk_excel(items, [], summary, str(out))
    wb = load_workbook(out)
    win_names = {wb["Windows Soft"].cell(row=r, column=1).value
                 for r in range(2, wb["Windows Soft"].max_row + 1)}
    linux_names = {wb["Linux Soft"].cell(row=r, column=1).value
                   for r in range(2, wb["Linux Soft"].max_row + 1)}
    # Windows: Chrome (Critical) + Safe Tool (Safe) -> all programs
    assert {"Google Chrome", "Safe Tool"} <= win_names
    assert "Python" in linux_names
    assert "Python" not in win_names


def test_summary_contains_os_breakdown(tmp_path):
    items = vc.analyze(_data(), _rules(), kev=None)
    summary = vc.summarize(items, [], total_hosts=2)
    out = tmp_path / "risk.xlsx"
    vc.write_risk_excel(items, [], summary, str(out))
    wb = load_workbook(out)
    ws = wb["Summary"]
    labels = {ws.cell(row=r, column=1).value for r in range(1, ws.max_row + 1)}
    assert {"Windows software", "Linux software", "Other software"} <= labels
