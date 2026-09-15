#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Convert Kaspersky inventory JSON to Excel (unique software by name+version).
Usage:
  python json_to_excel.py                          # convert all kaspersky_inventory_*.json files
  python json_to_excel.py -i file.json -o out.xlsx # convert single file
  python json_to_excel.py --all-hosts             # include host column (no dedup across hosts)
"""
import argparse
import json
import glob
import os
from pathlib import Path
from collections import OrderedDict

try:
    from openpyxl import Workbook
    from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
    HAS_OPENPYXL = True
except ImportError:
    HAS_OPENPYXL = False


def find_all_jsons(pattern="kaspersky_inventory_*.json"):
    files = glob.glob(pattern)
    files.sort(key=lambda p: os.path.getmtime(p))
    return files


def find_latest_json(pattern="kaspersky_inventory_*.json"):
    files = find_all_jsons(pattern)
    if not files:
        return None
    return files[-1]


def load_json(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def dedup_software(data):
    """
    Returns OrderedDict key=(name_lower, version) -> {name, version, publisher, count, hosts}
    Dedup by name+version case-insensitive for name, exact for version.
    """
    uniq = OrderedDict()
    for host in data.get("hosts", []):
        h_name = host.get("host", {}).get("display_name") or host.get("host", {}).get("dn") or "unknown"
        for sw in host.get("software", []):
            name = str(sw.get("name") or "").strip()
            version = str(sw.get("version") or "").strip()
            publisher = str(sw.get("publisher") or "").strip()
            if not name:
                continue
            key = (name.lower(), version)
            if key not in uniq:
                uniq[key] = {"name": name, "version": version, "publisher": publisher, "count": 1, "hosts": [h_name]}
            else:
                uniq[key]["count"] += 1
                if h_name not in uniq[key]["hosts"]:
                    uniq[key]["hosts"].append(h_name)
    # sort by name then version
    sorted_items = sorted(uniq.items(), key=lambda kv: (kv[0][0], kv[0][1]))
    return OrderedDict(sorted_items)


def write_excel(uniq_dict, output_path, source_json):
    if not HAS_OPENPYXL:
        raise RuntimeError("openpyxl not installed. Run: pip install openpyxl")
    wb = Workbook()
    ws = wb.active
    ws.title = "Unique Software"

    # Styles
    header_font = Font(name="Calibri", bold=True, color="FFFFFF", size=11)
    header_fill = PatternFill(start_color="4472C4", end_color="4472C4", fill_type="solid")
    thin = Side(style="thin", color="B4C6E7")
    border = Border(left=thin, right=thin, top=thin, bottom=thin)
    center = Alignment(horizontal="center", vertical="center")
    left = Alignment(horizontal="left", vertical="center")

    headers = ["Software Name", "Version", "Publisher", "Hosts Count", "Hosts"]
    ws.append(headers)
    for col, h in enumerate(headers, 1):
        c = ws.cell(row=1, column=col)
        c.font = header_font
        c.fill = header_fill
        c.alignment = center
        c.border = border

    row = 2
    for (k, v) in uniq_dict.items():
        ws.cell(row=row, column=1, value=v["name"]).alignment = left
        ws.cell(row=row, column=2, value=v["version"]).alignment = center
        ws.cell(row=row, column=3, value=v["publisher"]).alignment = left
        ws.cell(row=row, column=4, value=v["count"]).alignment = center
        ws.cell(row=row, column=5, value=", ".join(v["hosts"])).alignment = left
        for col in range(1, 6):
            ws.cell(row=row, column=col).border = border
            ws.cell(row=row, column=col).font = Font(name="Calibri", size=10)
        row += 1

    # Column widths
    ws.column_dimensions["A"].width = 60
    ws.column_dimensions["B"].width = 18
    ws.column_dimensions["C"].width = 28
    ws.column_dimensions["D"].width = 12
    ws.column_dimensions["E"].width = 30
    ws.freeze_panes = "A2"
    ws.auto_filter.ref = f"A1:E{row-1}"
    ws.sheet_properties.pageSetUpPr.fitToPage = True

    # Info sheet
    ws2 = wb.create_sheet("Info")
    ws2["A1"] = "Source JSON"
    ws2["B1"] = str(source_json)
    ws2["A2"] = "Generated"
    from datetime import datetime
    ws2["B2"] = datetime.now().isoformat()
    ws2["A3"] = "Total unique software (name+version)"
    ws2["B3"] = len(uniq_dict)
    for r in range(1, 4):
        ws2[f"A{r}"].font = Font(bold=True)
    ws2.column_dimensions["A"].width = 32
    ws2.column_dimensions["B"].width = 60

    wb.save(output_path)
    return output_path


def _process_single(inp, args, output_override=None):
    """Process a single JSON file to Excel, returns 0 on success."""
    print(f"\nInput: {inp}")
    try:
        data = load_json(inp)
    except Exception as e:
        print(f"Failed to load {inp}: {e}")
        return 1
    print(f"Hosts in JSON: {len(data.get('hosts', []))}")
    total_sw = sum(len(h.get("software", [])) for h in data.get("hosts", []))
    print(f"Total software entries (with duplicates): {total_sw}")

    if args.all_hosts:
        if not HAS_OPENPYXL:
            print("openpyxl required")
            return 1
        from openpyxl import Workbook
        from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
        wb = Workbook()
        ws = wb.active
        ws.title = "Per Host"
        header_font = Font(bold=True, color="FFFFFF")
        header_fill = PatternFill(start_color="4472C4", end_color="4472C4", fill_type="solid")
        thin = Side(style="thin", color="B4C6E7")
        border = Border(left=thin, right=thin, top=thin, bottom=thin)
        headers = ["Host", "Software Name", "Version", "Publisher"]
        ws.append(headers)
        for col in range(1, 5):
            c = ws.cell(row=1, column=col)
            c.font = header_font
            c.fill = header_fill
            c.border = border
        r = 2
        for host in data.get("hosts", []):
            hname = host.get("host", {}).get("display_name", "unknown")
            for sw in host.get("software", []):
                ws.cell(row=r, column=1, value=hname)
                ws.cell(row=r, column=2, value=sw.get("name", ""))
                ws.cell(row=r, column=3, value=sw.get("version", ""))
                ws.cell(row=r, column=4, value=sw.get("publisher", ""))
                r += 1
        ws.column_dimensions["A"].width = 22
        ws.column_dimensions["B"].width = 60
        ws.column_dimensions["C"].width = 18
        ws.column_dimensions["D"].width = 28
        out = output_override or args.output or f"software_per_host_{Path(inp).stem}.xlsx"
        wb.save(out)
        print(f"Saved per-host Excel: {out} (rows {r-2})")
        return 0

    uniq = dedup_software(data)
    print(f"Unique software (name+version): {len(uniq)}")
    dups_removed = total_sw - len(uniq)
    if dups_removed > 0:
        print(f"Deduplicated: removed {dups_removed} duplicates (same name+version)")
    if output_override:
        out = output_override
    elif args.output:
        out = args.output
    else:
        out = f"software_inventory_{Path(inp).stem}.xlsx"
    write_excel(uniq, out, inp)
    print(f"Saved Excel: {out}")
    print("Preview (first 5):")
    for i, (k, v) in enumerate(list(uniq.items())[:5], 1):
        print(f"  {i}. {v['name']} | {v['version']} | hosts={v['count']}")
    return 0


def main():
    p = argparse.ArgumentParser(description="Convert Kaspersky JSON to Excel (dedup by name+version)")
    p.add_argument("-i", "--input", help="Input JSON path (default: all kaspersky_inventory_*.json)")
    p.add_argument("-o", "--output", help="Output Excel path (only for single input; ignored when converting all)")
    p.add_argument("--all-hosts", action="store_true", help="Do not dedup, list per host (host, software, version)")
    args = p.parse_args()

    # Single file mode
    if args.input:
        if not os.path.exists(args.input):
            print(f"Input JSON not found: {args.input}")
            return 1
        return _process_single(args.input, args)

    # No input: convert all files
    all_files = find_all_jsons()
    if not all_files:
        print("No kaspersky_inventory_*.json files found")
        print("Provide -i file.json")
        return 1

    print(f"Found {len(all_files)} JSON file(s), converting all...")
    ret = 0
    for f in all_files:
        rc = _process_single(f, args)
        if rc != 0:
            ret = rc
    print(f"\nDone. Converted {len(all_files)} file(s).")
    return ret


if __name__ == "__main__":
    raise SystemExit(main())
