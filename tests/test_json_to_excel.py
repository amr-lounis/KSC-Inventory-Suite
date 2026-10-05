"""Tests for json_to_excel.py - OS split, dedup and Excel writing."""
import json
from collections import OrderedDict

import pytest
from openpyxl import Workbook
from openpyxl.styles import Font, PatternFill, Alignment, Border, Side

import json_to_excel as j2e


def _styles():
    thin = Side(style="thin", color="B4C6E7")
    bd = Border(left=thin, right=thin, top=thin, bottom=thin)
    center = Alignment(horizontal="center", vertical="center", wrap_text=True)
    left = Alignment(horizontal="left", vertical="center", wrap_text=True)
    hdr_font = Font(bold=True, color="FFFFFF")
    hdr_fill = PatternFill(start_color="4472C4", end_color="4472C4", fill_type="solid")
    return hdr_font, hdr_fill, bd, center, left


def test_classify_os():
    assert j2e.classify_os("Microsoft Windows 10 Pro") == "windows"
    assert j2e.classify_os("Windows Server 2019") == "windows"
    assert j2e.classify_os("Ubuntu 22.04 LTS") == "linux"
    assert j2e.classify_os("Debian GNU/Linux") == "linux"
    assert j2e.classify_os("") == "other"
    assert j2e.classify_os(None) == "other"
    assert j2e.classify_os("macOS Sonoma") == "other"


def test_dedup_by_os_groups_and_counts():
    data = {
        "hosts": [
            {"host": {"os": "Windows 10", "ip": "10.0.0.1", "display_name": "PC1"},
             "software": [{"name": "Chrome", "version": "100", "publisher": "Google"}]},
            {"host": {"os": "Windows 10", "ip": "10.0.0.2", "display_name": "PC2"},
             "software": [{"name": "Chrome", "version": "100", "publisher": "Google"}]},
            {"host": {"os": "Ubuntu 22.04", "ip": "10.0.0.3", "display_name": "SRV"},
             "software": [{"name": "python3", "version": "3.10", "publisher": ""}]},
        ]
    }
    split, counts = j2e.dedup_by_os(data)
    assert counts == {"windows": 2, "linux": 1, "other": 0}
    assert len(split["windows"]) == 1
    key = ("chrome", "100")
    assert key in split["windows"]
    assert split["windows"][key]["count"] == 2
    assert set(split["windows"][key]["hosts"]) == {"10.0.0.1", "10.0.0.2"}


def test_dedup_by_os_fallback_to_display_name_when_no_ip():
    data = {"hosts": [
        {"host": {"os": "", "ip": "", "display_name": "PC-X", "dn": ""},
         "software": [{"name": "App", "version": "1", "publisher": ""}]}
    ]}
    split, counts = j2e.dedup_by_os(data)
    assert counts["other"] == 1
    assert list(split["other"].values())[0]["hosts"] == ["PC-X"]


def test_dedup_by_os_skips_empty_names():
    data = {"hosts": [
        {"host": {"os": "Windows", "ip": "1.1.1.1"},
         "software": [{"name": "", "version": "1"}, {"name": "OK", "version": ""}]}
    ]}
    split, _ = j2e.dedup_by_os(data)
    assert len(split["windows"]) == 1


def test_write_hosts_sheet_is_row_based_and_scalable():
    """Regression: old layout used 1 column per software (Excel limit 16384).
    New layout must be 3 columns regardless of product count."""
    uniq = OrderedDict()
    for i in range(100):
        uniq[(f"app{i}", "1.0")] = {
            "name": f"App{i}", "version": "1.0",
            "publisher": "P", "count": 1, "hosts": ["h1"],
        }
    wb = Workbook()
    ws = wb.active
    j2e._write_hosts_sheet(ws, uniq, *_styles())
    assert ws.max_column == 3
    assert ws.cell(row=1, column=1).value == "Software Name"
    assert ws.cell(row=1, column=3).value == "Host (IP/name)"
    assert ws.max_row == 101  # header + 100 rows


def test_write_hosts_sheet_multiple_hosts_per_software():
    uniq = OrderedDict()
    uniq[("vlc", "3.0")] = {"name": "VLC", "version": "3.0",
                            "publisher": "", "count": 2, "hosts": ["a", "b"]}
    wb = Workbook()
    ws = wb.active
    j2e._write_hosts_sheet(ws, uniq, *_styles())
    assert ws.max_row == 3
    assert ws.cell(row=2, column=3).value == "a"
    assert ws.cell(row=3, column=3).value == "b"


def test_write_excel_creates_expected_sheets(tmp_path):
    split = {
        "windows": OrderedDict({("a", "1"): {"name": "A", "version": "1",
                                             "publisher": "P", "count": 1, "hosts": ["h"]}}),
        "linux": OrderedDict(),
        "other": OrderedDict(),
    }
    out = tmp_path / "inv.xlsx"
    j2e.write_excel(split, str(out), {"windows": 1, "linux": 0, "other": 0})
    assert out.exists()

    from openpyxl import load_workbook
    wb = load_workbook(out)
    assert set(wb.sheetnames) == {"Summary", "Windows Software", "Linux Software"}
    assert "Other Software" not in wb.sheetnames
    assert "Hosts - Windows" not in wb.sheetnames
    assert "Hosts - Linux" not in wb.sheetnames
    assert "Hosts - Other" not in wb.sheetnames


def test_process_one_end_to_end(tmp_path, monkeypatch):
    inv = {
        "hosts": [
            {"host": {"os": "Windows 11", "ip": "10.0.0.5",
                      "display_name": "PC", "dn": ""},
             "software": [{"name": "Notepad++", "version": "8.0", "publisher": "Don"}]},
        ]
    }
    inp = tmp_path / "kaspersky_inventory_test.json"
    inp.write_text(json.dumps(inv), encoding="utf-8")
    out = tmp_path / "out.xlsx"
    rc = j2e.process_one(str(inp), str(out))
    assert rc == 0
    assert out.exists()


def _dup_inventory():
    return {
        "hosts": [
            {"host": {"os": "Windows 10", "ip": "10.0.0.1", "display_name": "PC1"},
             "software": [{"name": "Google Chrome", "version": "100.0",
                           "publisher": "Google"}]},
            {"host": {"os": "Windows 11", "ip": "10.0.0.2", "display_name": "PC2"},
             "software": [{"name": "google chrome", "version": "152.0",
                           "publisher": "Google"}]},
            {"host": {"os": "Windows 10", "ip": "10.0.0.3", "display_name": "PC3"},
             "software": [{"name": "Safe Tool", "version": "1.0",
                           "publisher": "X"}]},
        ]
    }


def test_merge_uniq_by_name_groups_versions():
    split, _ = j2e.dedup_by_os(_dup_inventory())
    assert len(split["windows"]) == 3  # dedup stays per-version
    merged = j2e._merge_uniq_by_name(split["windows"])
    assert len(merged) == 2
    chrome = merged["google chrome"]
    assert chrome["version"] == "100.0, 152.0"
    assert chrome["count"] == 2
    assert sorted(chrome["hosts"]) == ["10.0.0.1", "10.0.0.2"]


def test_software_sheet_has_no_duplicate_software(tmp_path):
    split, counts = j2e.dedup_by_os(_dup_inventory())
    out = tmp_path / "soft.xlsx"
    j2e.write_excel(split, str(out), counts)
    from openpyxl import load_workbook
    wb = load_workbook(out)
    ws = wb["Windows Software"]
    names = [ws.cell(row=r, column=1).value
             for r in range(2, ws.max_row + 1)]
    assert len(names) == len({n.strip().lower() for n in names}) == 2
    for r in range(2, ws.max_row + 1):
        if ws.cell(row=r, column=1).value.lower() == "google chrome":
            assert ws.cell(row=r, column=2).value == "100.0, 152.0"
            assert ws.cell(row=r, column=4).value == 2
    # Summary counts merged names; per-host Hosts sheets were removed
    assert wb["Summary"].cell(row=2, column=3).value == 2
    assert "Hosts - Windows" not in wb.sheetnames


def test_write_excel_hosts_sheets_per_host(tmp_path):
    data = {"hosts": [
        {"host": {"os": "Windows 10 Pro", "ip": "10.0.0.1", "display_name": "PC1"},
         "software": [{"name": "B Tool", "version": "2.0", "publisher": ""},
                      {"name": "A Tool", "version": "", "publisher": ""}]},
        {"host": {"os": "Ubuntu 22.04", "ip": "10.0.0.2", "display_name": "SRV"},
         "software": [{"name": "apt", "version": "2.4", "publisher": ""}]},
    ]}
    split, counts = j2e.dedup_by_os(data)
    out = tmp_path / "hosts.xlsx"
    j2e.write_excel(split, str(out), counts, data["hosts"])
    from openpyxl import load_workbook
    wb = load_workbook(out)
    assert set(wb.sheetnames) == {"Summary", "Windows Software", "Linux Software",
                                  "Windows Hosts", "Linux Hosts"}
    ws = wb["Windows Hosts"]
    assert [ws.cell(row=1, column=c).value for c in range(1, 5)] == \
        ["IP", "Host Name", "OS Version", "Software"]
    assert ws.max_row == 2
    assert ws.cell(row=2, column=1).value == "10.0.0.1"
    assert ws.cell(row=2, column=2).value == "PC1"
    assert ws.cell(row=2, column=3).value == "Windows 10 Pro"
    assert ws.cell(row=2, column=4).value == "A Tool\nB Tool 2.0"
    assert wb["Linux Hosts"].max_row == 2
