#!/usr/bin/env python3
import json, glob, os, sys
from pathlib import Path
from collections import OrderedDict
from openpyxl import Workbook
from openpyxl.styles import Font, PatternFill, Alignment, Border, Side

def get_app_dir():
    if getattr(sys, 'frozen', False):
        return Path(sys.executable).parent
    return Path(__file__).parent

def find_all(pattern="kaspersky_inventory_*.json"):
    base = get_app_dir()
    files = glob.glob(str(base / pattern))
    files.sort(key=os.path.getmtime)
    return files

def load_json(p): return json.loads(Path(p).read_text(encoding="utf-8"))

def classify_os(os_name):
    """Windows / Linux / Other حسب نص حقل os الخاص بالجهاز."""
    s = str(os_name or "").strip().lower()
    if not s:
        return "other"
    if "windows" in s or "microsoft" in s or "win32" in s:
        return "windows"
    linux_keywords = (
        "linux", "ubuntu", "debian", "centos", "rhel", "red hat", "fedora",
        "suse", "astra", "alt linux", "rosa", "mint", "arch", "gentoo",
        "oracle linux", "almalinux", "rocky", "kali",
    )
    if any(k in s for k in linux_keywords):
        return "linux"
    return "other"


def dedup_by_os(data):
    """تجميع البرامج الفريدة لكل نوع نظام تشغيل + عدّ الأجهزة لكل نوع."""
    split = {"windows": OrderedDict(), "linux": OrderedDict(), "other": OrderedDict()}
    host_counts = {"windows": 0, "linux": 0, "other": 0}
    for h in data.get("hosts", []):
        host_info = h.get("host", {}) if isinstance(h.get("host"), dict) else {}
        os_name = host_info.get("os", "")
        ip_raw = str(host_info.get("ip") or "").strip()
        # شيتات Hosts تعرض IP بدل اسم الجهاز (مع fallback للاسم عند غياب IP)
        fallback = host_info.get("display_name") or host_info.get("dn") or "unknown"
        hid = ip_raw.split(",")[0].strip() if ip_raw else str(fallback).strip()
        if not hid:
            hid = "unknown"
        cat = classify_os(os_name)
        host_counts[cat] += 1
        uniq = split[cat]
        for sw in h.get("software", []):
            if not isinstance(sw, dict):
                continue
            name = str(sw.get("name") or "").strip()
            ver = str(sw.get("version") or "").strip()
            pub = str(sw.get("publisher") or "").strip()
            if not name:
                continue
            key = (name.lower(), ver)
            if key not in uniq:
                uniq[key] = {"name": name, "version": ver, "publisher": pub, "count": 1, "hosts": [hid]}
            else:
                uniq[key]["count"] += 1
                if hid not in uniq[key]["hosts"]:
                    uniq[key]["hosts"].append(hid)
    for cat in split:
        split[cat] = OrderedDict(sorted(split[cat].items(), key=lambda kv: (kv[0][0], kv[0][1])))
    return split, host_counts

def dedup(data):
    # توافق قديم: دمج الكل بدون تقسيم (يُستخدم داخلياً فقط عند الحاجة)
    split, _ = dedup_by_os(data)
    merged = OrderedDict()
    for cat in ("windows", "linux", "other"):
        for key, v in split[cat].items():
            if key not in merged:
                merged[key] = {"name": v["name"], "version": v["version"],
                               "publisher": v["publisher"], "count": 0, "hosts": []}
            merged[key]["count"] += v["count"]
            for hn in v["hosts"]:
                if hn not in merged[key]["hosts"]:
                    merged[key]["hosts"].append(hn)
    return OrderedDict(sorted(merged.items(), key=lambda kv: (kv[0][0], kv[0][1])))

def _write_software_sheet(ws, uniq, hdr_font, hdr_fill, bd, center, left):
    headers = ["Software Name", "Version", "Publisher", "Hosts Count"]
    ws.append(headers)
    for c in range(1, 5):
        x = ws.cell(row=1, column=c); x.font = hdr_font; x.fill = hdr_fill; x.alignment = center; x.border = bd
    r = 2
    for v in uniq.values():
        ws.cell(row=r, column=1, value=v["name"]).alignment = left
        ws.cell(row=r, column=2, value=v["version"]).alignment = center
        ws.cell(row=r, column=3, value=v["publisher"]).alignment = left
        ws.cell(row=r, column=4, value=v["count"]).alignment = center
        for col in range(1, 5):
            ws.cell(row=r, column=col).border = bd
        r += 1
    ws.column_dimensions["A"].width = 55; ws.column_dimensions["B"].width = 18
    ws.column_dimensions["C"].width = 28; ws.column_dimensions["D"].width = 12
    ws.freeze_panes = "A2"
    if r > 2:
        ws.auto_filter.ref = f"A1:D{r-1}"
    return r

def _write_hosts_sheet(ws, uniq, hdr_font, hdr_fill, bd, center, left):
    col = 1
    max_rows = 1
    for v in uniq.values():
        hdr = f"{v['name']}"
        if v["version"]:
            hdr += f" [{v['version']}]"
        if len(hdr) > 250:
            hdr = hdr[:250] + "..."
        c = ws.cell(row=1, column=col, value=hdr); c.font = hdr_font; c.fill = hdr_fill; c.alignment = center; c.border = bd
        for idx, h in enumerate(v["hosts"], start=2):
            x = ws.cell(row=idx, column=col, value=h); x.alignment = left; x.border = bd
        try:
            ws.column_dimensions[ws.cell(row=1, column=col).column_letter].width = 22
        except Exception:
            pass
        max_rows = max(max_rows, len(v["hosts"]) + 1)
        col += 1
    if uniq:
        ws.freeze_panes = "A2"
        ws.auto_filter.ref = f"A1:{ws.cell(row=1, column=len(uniq)).column_letter}1"

def write_excel(split_or_uniq, out, host_counts=None):
    """يكتب ملف Excel مقسّماً حسب نظام التشغيل: Windows / Linux / Other.

    يقبل قاموس التقسيم {"windows":..., "linux":..., "other":...}
    أو (للتوافق القديم) قاموس uniq مدمج فيضعه في شيت واحد.
    """
    # توافق قديم: uniq مدمج وليس تقسيماً
    if split_or_uniq and all(isinstance(v, dict) and "name" in v for v in split_or_uniq.values()):
        split = {"windows": split_or_uniq, "linux": OrderedDict(), "other": OrderedDict()}
        host_counts = host_counts or {}
    else:
        split = split_or_uniq
    host_counts = host_counts or {}
    wb = Workbook()
    hdr_font = Font(bold=True, color="FFFFFF")
    hdr_fill = PatternFill(start_color="4472C4", end_color="4472C4", fill_type="solid")
    thin = Side(style="thin", color="B4C6E7"); bd = Border(left=thin, right=thin, top=thin, bottom=thin)
    center = Alignment(horizontal="center", vertical="center", wrap_text=True)
    left = Alignment(horizontal="left", vertical="center", wrap_text=True)

    # Sheet 1: Summary
    ws0 = wb.active; ws0.title = "Summary"
    ws0.append(["OS Type", "Hosts Count", "Unique Software Count"])
    for c in range(1, 4):
        x = ws0.cell(row=1, column=c); x.font = hdr_font; x.fill = hdr_fill; x.alignment = center; x.border = bd
    r = 2
    for cat, label in (("windows", "Windows"), ("linux", "Linux"), ("other", "Other")):
        uniq = split.get(cat, OrderedDict())
        ws0.cell(row=r, column=1, value=label).alignment = center
        ws0.cell(row=r, column=2, value=host_counts.get(cat, 0)).alignment = center
        ws0.cell(row=r, column=3, value=len(uniq)).alignment = center
        for col in range(1, 4):
            ws0.cell(row=r, column=col).border = bd
        r += 1
    ws0.column_dimensions["A"].width = 18; ws0.column_dimensions["B"].width = 14
    ws0.column_dimensions["C"].width = 22
    ws0.freeze_panes = "A2"

    # Sheets 2-4: Software per OS
    for cat, title in (("windows", "Windows Software"), ("linux", "Linux Software"), ("other", "Other Software")):
        ws = wb.create_sheet(title)
        _write_software_sheet(ws, split.get(cat, OrderedDict()), hdr_font, hdr_fill, bd, center, left)

    # Sheets 5-7: Hosts per Software per OS
    for cat, title in (("windows", "Hosts - Windows"), ("linux", "Hosts - Linux"), ("other", "Hosts - Other")):
        ws = wb.create_sheet(title)
        _write_hosts_sheet(ws, split.get(cat, OrderedDict()), hdr_font, hdr_fill, bd, center, left)

    wb.save(out)

def process_one(inp):
    print(f"\nInput: {inp}")
    data=load_json(inp)
    total=sum(len(h.get("software",[])) for h in data.get("hosts",[]))
    split, host_counts=dedup_by_os(data)
    nw=len(split["windows"]); nl=len(split["linux"]); no=len(split["other"])
    print(f"Hosts {len(data.get('hosts',[]))} (W={host_counts['windows']} L={host_counts['linux']} O={host_counts['other']}) total {total} unique W={nw} L={nl} O={no}")
    out = get_app_dir() / f"software_inventory_{Path(inp).stem}.xlsx"
    write_excel(split,str(out),host_counts); print(f"Saved {out}"); return 0

def main():
    files=find_all()
    if not files:
        print("No kaspersky_inventory_*.json found"); return 1
    print(f"Found {len(files)} file(s)")
    rc=0
    for f in files:
        if process_one(f)!=0: rc=1
    return rc

if __name__=="__main__":
    raise SystemExit(main())
