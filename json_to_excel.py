#!/usr/bin/env python3
import json, glob, os
from pathlib import Path
from collections import OrderedDict
from openpyxl import Workbook
from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
from openpyxl.comments import Comment

def find_all(pattern="kaspersky_inventory_*.json"):
    files=glob.glob(pattern)
    files.sort(key=os.path.getmtime)
    return files

def load_json(p): return json.loads(Path(p).read_text(encoding="utf-8"))

def dedup(data):
    uniq=OrderedDict()
    for h in data.get("hosts",[]):
        hn=h.get("host",{}).get("display_name") or h.get("host",{}).get("dn") or "unknown"
        for sw in h.get("software",[]):
            name=str(sw.get("name") or "").strip()
            ver=str(sw.get("version") or "").strip()
            pub=str(sw.get("publisher") or "").strip()
            if not name: continue
            key=(name.lower(),ver)
            if key not in uniq:
                uniq[key]={"name":name,"version":ver,"publisher":pub,"count":1,"hosts":[hn]}
            else:
                uniq[key]["count"]+=1
                if hn not in uniq[key]["hosts"]:
                    uniq[key]["hosts"].append(hn)
    return OrderedDict(sorted(uniq.items(), key=lambda kv:(kv[0][0],kv[0][1])))

def write_excel(uniq, out, max_hosts=10):
    wb=Workbook()
    ws=wb.active; ws.title="Unique Software"
    hdr_font=Font(bold=True,color="FFFFFF")
    hdr_fill=PatternFill(start_color="4472C4",end_color="4472C4",fill_type="solid")
    thin=Side(style="thin",color="B4C6E7"); bd=Border(left=thin,right=thin,top=thin,bottom=thin)
    center=Alignment(horizontal="center",vertical="center",wrap_text=True)
    left=Alignment(horizontal="left",vertical="center",wrap_text=True)
    headers=["Software Name","Version","Publisher","Hosts Count","Hosts (sample)"]
    ws.append(headers)
    for c in range(1,6):
        x=ws.cell(row=1,column=c); x.font=hdr_font; x.fill=hdr_fill; x.alignment=center; x.border=bd
    r=2
    need_details=any(len(v["hosts"])>max_hosts for v in uniq.values())
    for v in uniq.values():
        hosts=v["hosts"]
        if len(hosts)>max_hosts:
            disp=", ".join(hosts[:max_hosts])+f" +{len(hosts)-max_hosts} more"
            comm=", ".join(hosts)[:2000]
        else:
            disp=", ".join(hosts)
            comm=None
        ws.cell(row=r,column=1,value=v["name"]).alignment=left
        ws.cell(row=r,column=2,value=v["version"]).alignment=center
        ws.cell(row=r,column=3,value=v["publisher"]).alignment=left
        ws.cell(row=r,column=4,value=v["count"]).alignment=center
        c=ws.cell(row=r,column=5,value=disp); c.alignment=left
        if comm and len(hosts)>max_hosts:
            c.comment=Comment(comm,"ksc",width=400,height=80)
        for col in range(1,6):
            ws.cell(row=r,column=col).border=bd
        r+=1
    ws.column_dimensions["A"].width=55; ws.column_dimensions["B"].width=18
    ws.column_dimensions["C"].width=28; ws.column_dimensions["D"].width=12
    ws.column_dimensions["E"].width=45
    ws.freeze_panes="A2"; ws.auto_filter.ref=f"A1:E{r-1}"
    if need_details:
        ws2=wb.create_sheet("Details_FullHosts")
        ws2.append(["Software Name","Version","Host"])
        for c in range(1,4):
            x=ws2.cell(row=1,column=c); x.font=hdr_font; x.fill=hdr_fill; x.alignment=center; x.border=bd
        rr=2
        for v in uniq.values():
            for h in v["hosts"]:
                ws2.cell(row=rr,column=1,value=v["name"]); ws2.cell(row=rr,column=2,value=v["version"]); ws2.cell(row=rr,column=3,value=h)
                rr+=1
        ws2.column_dimensions["A"].width=55; ws2.column_dimensions["B"].width=18; ws2.column_dimensions["C"].width=25
        ws2.freeze_panes="A2"; ws2.auto_filter.ref=f"A1:C{rr-1}"
    # Hosts per Software: columns=software, rows=hosts
    ws3=wb.create_sheet("Hosts per Software")
    col=1
    for v in uniq.values():
        hdr=f"{v['name']}"
        if v["version"]: hdr+=f" [{v['version']}]"
        if len(hdr)>250: hdr=hdr[:250]+"..."
        c=ws3.cell(row=1,column=col,value=hdr); c.font=hdr_font; c.fill=hdr_fill; c.alignment=center; c.border=bd
        for idx,h in enumerate(v["hosts"], start=2):
            x=ws3.cell(row=idx,column=col,value=h); x.alignment=left; x.border=bd
        ws3.column_dimensions[ws3.cell(row=1,column=col).column_letter].width=22
        col+=1
    if uniq:
        ws3.freeze_panes="A2"; ws3.auto_filter.ref=f"A1:{ws3.cell(row=1,column=len(uniq)).column_letter}1"
    wb.save(out)

def process_one(inp):
    print(f"\nInput: {inp}")
    data=load_json(inp)
    total=sum(len(h.get("software",[])) for h in data.get("hosts",[]))
    uniq=dedup(data)
    print(f"Hosts {len(data.get('hosts',[]))} total {total} unique {len(uniq)}")
    out=f"software_inventory_{Path(inp).stem}.xlsx"
    write_excel(uniq,out); print(f"Saved {out}"); return 0

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
