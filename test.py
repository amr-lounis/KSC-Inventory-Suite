import os, sys, json, base64, struct, socket, platform, subprocess, requests, urllib3, re, csv
from datetime import datetime
urllib3.disable_warnings()
if hasattr(sys.stdout, "reconfigure"):
    try: sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except: pass

S=os.getenv("KSC_SERVER","192.168.10.20")
P=int(os.getenv("KSC_API_PORT","13299"))
U=os.getenv("KSC_USERNAME","Administrator")
W=os.getenv("KSC_PASSWORD","Test@12345678-+")
V=os.getenv("KSC_VERIFY_SSL","0")=="1"
B=f"https://{S}:{P}/api/v1.0"
ses=requests.Session()
ses.verify=V
ses.headers.update({"Content-Type":"application/json"})
AUTH=False

def b64(s): return base64.b64encode(s.encode()).decode()
def ip2s(v):
    try: return socket.inet_ntoa(struct.pack("<I", v & 0xFFFFFFFF)) if isinstance(v,int) else str(v)
    except: return str(v)

# ---------- Helpers: Listening Ports ----------
def _win_listening_pid_to_ports():
    """Windows: netstat -ano -> dict pid -> list[{proto,local_addr,port,state}]"""
    pid_to_ports={}
    try:
        o=subprocess.run(["netstat","-ano"],capture_output=True,text=True,timeout=10).stdout or ""
        for line in o.splitlines():
            line=line.strip()
            if not line or line.startswith("Proto") or line.startswith("Active"):
                continue
            parts=line.split()
            if len(parts) < 3:
                continue
            proto=parts[0].upper()
            if proto not in ("TCP","UDP"):
                continue
            local=parts[1] if len(parts) >=2 else ""
            pid_str=parts[-1]
            if not pid_str.isdigit():
                continue
            pid=int(pid_str)
            if pid == 0:
                continue
            if proto=="TCP":
                if len(parts) < 5:
                    continue
                state=parts[3].upper()
                if state != "LISTENING":
                    continue
                st="LISTENING"
            else:
                st="UNCONN"
            if ":" not in local:
                continue
            # local may be [::]:135 or 0.0.0.0:135
            port_str=local.rsplit(":",1)[-1].strip("[]")
            if not port_str.isdigit():
                continue
            port=int(port_str)
            addr=local.rsplit(":",1)[0].strip("[]")
            # normalize addr empty brackets
            if addr=="": addr="0.0.0.0"
            pid_to_ports.setdefault(pid, []).append({"proto":proto,"local_addr":addr,"port":port,"state":st})
    except Exception as e:
        pass
    return pid_to_ports

def _parse_win_pathname(pn):
    """'"C:\\Windows\\system32\\svchost.exe -k netsvcs"' -> ('svchost.exe', 'C:\\Windows\\system32\\svchost.exe')"""
    if not pn:
        return "", ""
    pn = pn.strip()
    exe_path = ""
    m = re.match(r'^\s*"([^"]+)"', pn)
    if m:
        exe_path = m.group(1).strip()
        # اذا كان المقتبس يحتوي وسائط بالداخل (حالة نادرة) قص الى .exe
        m_exe = re.search(r'(.+?\.exe)\b', exe_path, re.IGNORECASE)
        if m_exe:
            exe_path = m_exe.group(1).strip()
    else:
        m2 = re.search(r'(.+?\.exe)', pn, re.IGNORECASE)
        if m2:
            exe_path = m2.group(1).strip().strip('"').strip("'")
        else:
            exe_path = pn.split()[0].strip('"').strip("'") if pn.split() else ""
    exe_name = ""
    if exe_path:
        if "\\" in exe_path:
            exe_name = exe_path.rsplit("\\", 1)[-1]
        else:
            exe_name = os.path.basename(exe_path.replace("/", os.sep))
        exe_name = exe_name.strip('"').strip("'")
    return exe_name, exe_path

def _win_service_pid_map():
    """Returns (svc_to_pid: dict name->pid, pid_to_svcs: dict pid->[names], svc_to_exe: dict name->exe_info) for Windows running services"""
    svc_to_pid={}
    pid_to_svcs={}
    svc_to_exe={}
    # Try PowerShell Get-CimInstance (most accurate)
    try:
        ps_cmd = 'Get-CimInstance Win32_Service | Where-Object {$_.State -eq \'Running\'} | Select-Object Name, DisplayName, ProcessId, State, PathName | ConvertTo-Json -Compress'
        o=subprocess.run(["powershell","-NoProfile","-Command",ps_cmd],capture_output=True,text=True,timeout=15).stdout or ""
        o=o.strip()
        if o:
            # ConvertTo-Json may return single object or array
            data=json.loads(o)
            if isinstance(data, dict):
                data=[data]
            for e in data:
                try:
                    name=str(e.get("Name") or "").strip()
                    pid=int(e.get("ProcessId") or 0)
                    if not name or pid==0:
                        continue
                    svc_to_pid[name]=pid
                    # also case-insensitive key
                    svc_to_pid[name.lower()]=pid
                    pid_to_svcs.setdefault(pid, []).append(name)
                    pn=str(e.get("PathName") or "").strip()
                    exe, exe_path=_parse_win_pathname(pn)
                    info={"exe":exe,"exe_path":exe_path,"pathname":pn}
                    svc_to_exe[name]=info
                    svc_to_exe[name.lower()]=info
                except: continue
            if svc_to_pid:
                return svc_to_pid, pid_to_svcs, svc_to_exe
    except: pass
    # Fallback: tasklist /svc /fo csv
    try:
        o=subprocess.run(["tasklist","/svc","/fo","csv","/nh"],capture_output=True,text=True,timeout=10).stdout or ""
        # tasklist CSV includes header if /nh not used? we use /nh but also handle header
        reader=csv.reader(o.splitlines())
        for row in reader:
            if len(row) < 3:
                continue
            img=row[0].strip().strip('"')
            pid_str=row[1].strip().strip('"')
            svcs_str=row[2].strip().strip('"')
            if not pid_str.isdigit():
                continue
            pid=int(pid_str)
            if pid==0 or svcs_str in ("N/A",""):
                continue
            for svc in [s.strip() for s in svcs_str.split(",") if s.strip()]:
                if svc=="N/A": continue
                svc_to_pid[svc]=pid
                svc_to_pid[svc.lower()]=pid
                pid_to_svcs.setdefault(pid, []).append(svc)
                # tasklist يعطي اسم الملف المشغّل (Image Name) كبديل
                info={"exe":img,"exe_path":img,"pathname":img}
                svc_to_exe.setdefault(svc, info)
                svc_to_exe.setdefault(svc.lower(), info)
        if svc_to_pid:
            return svc_to_pid, pid_to_svcs, svc_to_exe
    except: pass
    # Fallback: wmic
    try:
        o=subprocess.run(["wmic","service","get","name,processid,state,pathname","/format:csv"],capture_output=True,text=True,timeout=15).stdout or ""
        for line in o.splitlines():
            line=line.strip()
            if not line or line.lower().startswith("node") or "ProcessId" in line:
                continue
            # CSV: Node,Name,PathName,ProcessId,State (order may vary, parse by header logic)
            # wmic csv output: Node,Name,PathName,ProcessId,State
            parts=[p.strip() for p in line.split(",")]
            if len(parts) < 5:
                # old format without pathname
                if len(parts) < 4:
                    continue
                name=parts[1]
                pid_str=parts[2]
                state=parts[3]
                pn=""
            else:
                name=parts[1]
                pn=parts[2]
                pid_str=parts[3]
                state=parts[4]
            if state.lower()!="running": continue
            if not pid_str.isdigit(): continue
            pid=int(pid_str)
            if not name or pid==0: continue
            svc_to_pid[name]=pid
            svc_to_pid[name.lower()]=pid
            pid_to_svcs.setdefault(pid, []).append(name)
            exe, exe_path=_parse_win_pathname(pn)
            info={"exe":exe,"exe_path":exe_path,"pathname":pn}
            svc_to_exe[name]=info
            svc_to_exe[name.lower()]=info
    except: pass
    return svc_to_pid, pid_to_svcs, svc_to_exe

def _win_qc_pathname(svc_name):
    """Fallback: sc.exe qc <svc> -> (exe, exe_path, pathname) للخدمات المتوقفة او التي فاتتها الخريطة"""
    try:
        o=subprocess.run(["sc.exe","qc",svc_name],capture_output=True,text=True,timeout=5).stdout or ""
        m=re.search(r'BINARY_PATH_NAME\s*:\s*(.+)', o)
        if m:
            pn=m.group(1).strip()
            exe, exe_path=_parse_win_pathname(pn)
            return exe, exe_path, pn
    except: pass
    return "", "", ""

def _win_pid_to_exe(pid):
    """Fallback: tasklist by PID -> exe name اذا لم نجد PathName"""
    try:
        o=subprocess.run(["tasklist","/FI",f"PID eq {pid}","/FO","CSV","/NH"],capture_output=True,text=True,timeout=5).stdout or ""
        reader=csv.reader(o.splitlines())
        for row in reader:
            if len(row) >= 1:
                img=row[0].strip().strip('"')
                if img and img.lower() not in ("info:", "image"):
                    return img, img, img
    except: pass
    return "", "", ""

def _linux_pid_to_exe(pid):
    """Linux PID -> (exe, exe_path, cmdline) عبر /proc + ps"""
    exe, exe_path, cmdline = "", "", ""
    try:
        exe_path=subprocess.run(["readlink",f"/proc/{pid}/exe"],capture_output=True,text=True,timeout=3).stdout.strip()
        if exe_path:
            exe=os.path.basename(exe_path)
    except: pass
    try:
        cmdline=subprocess.run(["ps","-p",str(pid),"-o","args="],capture_output=True,text=True,timeout=3).stdout.strip()
        if cmdline and not exe:
            # اول توكن هو الملف المشغّل
            first=cmdline.split()[0].strip()
            exe=os.path.basename(first)
            if not exe_path:
                exe_path=first
    except: pass
    return exe, exe_path, cmdline

def _linux_service_exec(svc_name):
    """systemctl show <svc> -> (exe, exe_path, exec_start)"""
    try:
        o=subprocess.run(["systemctl","show",svc_name,"--property=ExecStart,FragmentPath"],capture_output=True,text=True,timeout=3).stdout or ""
        m=re.search(r'ExecStart=\{[^}]*path=([^ ;\}]+)[^}]*\}', o)
        if m:
            exe_path=m.group(1).strip()
            exe=os.path.basename(exe_path)
            return exe, exe_path, o.strip().splitlines()[0] if o else ""
        # صيغة بديلة: ExecStart=/usr/sbin/sshd -D
        for line in o.splitlines():
            if line.startswith("ExecStart=") and "=" in line and len(line) > 10:
                val=line.split("=",1)[1].strip()
                if val and val != "":
                    first=val.split()[0].strip().strip('"')
                    # تجاهل الصيغة { path=... }
                    if first.startswith("{"):
                        continue
                    return os.path.basename(first), first, val
    except: pass
    return "", "", ""

def _linux_listening_pid_to_ports():
    """Linux: ss -tulnp / netstat -tulnp -> pid_to_ports dict and pid_to_proc dict"""
    pid_to_ports={}
    pid_to_proc={}
    # candidates in order
    candidates=[
        ["ss","-tulnp"],
        ["ss","-tulpn"],
        ["netstat","-tulnp"],
        ["ss","-tuln"],
    ]
    for cmd in candidates:
        try:
            o=subprocess.run(cmd,capture_output=True,text=True,timeout=10).stdout or ""
            if not o or ("LISTEN" not in o and "UNCONN" not in o and "tcp" not in o.lower()):
                continue
            # parse each line
            for line in o.splitlines():
                line=line.strip()
                if not line or line.startswith("Netid") or line.startswith("Proto") or line.startswith("State"):
                    continue
                # must contain pid= for -p case, if not -p then we skip (cannot map)
                m_pid=re.search(r'pid=(\d+)', line)
                if not m_pid:
                    continue
                pid=int(m_pid.group(1))
                if pid==0:
                    continue
                m_proc=re.search(r'"([^"]+)"', line)
                proc=m_proc.group(1) if m_proc else ""
                if proc:
                    pid_to_proc[pid]=proc
                # proto detection
                proto="TCP"
                if line.lower().startswith("udp"):
                    proto="UDP"
                elif line.lower().startswith("tcp"):
                    proto="TCP"
                else:
                    # tokens first field
                    tok=line.split()[0].upper() if line.split() else ""
                    if tok.startswith("UDP"): proto="UDP"
                    elif tok.startswith("TCP"): proto="TCP"
                    else: continue
                # filter state: TCP must be LISTEN, UDP UNCONN is ok
                if proto=="TCP" and "LISTEN" not in line:
                    continue
                # extract local address:port - heuristic: find tokens like *:port or ip:port
                # For ss: tokens[4] is Local Address:Port, for netstat tokens[3]
                # Use regex to find all ip:port candidates, take first that is not peer (peer is second)
                # Find all occurrences of :port
                # Local is usually 4th token for ss, 3rd for netstat, but we pick first valid that isn't :*
                tokens=line.split()
                local=None
                # Try to locate Local column position: search for token matching ip:port pattern
                # Collect tokens that look like address:port (endswith :digits)
                candidates_ports=[]
                for tok in tokens:
                    if re.search(r':\d+$', tok):
                        # exclude peer with :* or tokens that are pid related
                        if tok.endswith(":*"):
                            continue
                        # tok may be like 0.0.0.0:22 or [::]:22 or *:22 or 127.0.0.1:631
                        # ensure port part numeric and tok not containing pid=
                        if "pid=" in tok:
                            continue
                        candidates_ports.append(tok)
                if candidates_ports:
                    # First candidate is usually Local, second is Peer
                    local=candidates_ports[0]
                else:
                    # fallback regex on whole line
                    m=re.search(r'(\S+):(\d+)\s+\S+:\S+', line)
                    if m:
                        local=m.group(1)+":"+m.group(2)
                if not local or ":" not in local:
                    continue
                port_str=local.rsplit(":",1)[-1].strip("[]")
                if not port_str.isdigit():
                    continue
                port=int(port_str)
                addr=local.rsplit(":",1)[0].strip("[]")
                if addr in ("","*"): addr="0.0.0.0"
                st="LISTENING" if proto=="TCP" else "UNCONN"
                pid_to_ports.setdefault(pid, []).append({"proto":proto,"local_addr":addr,"port":port,"state":st,"process":proc})
            if pid_to_ports:
                break
        except: continue
    return pid_to_ports, pid_to_proc

def _linux_pid_to_service(pid):
    """Map Linux PID -> systemd service name. Tries ps unit, cgroup, then comm"""
    try:
        o=subprocess.run(["ps","-p",str(pid),"-o","unit="],capture_output=True,text=True,timeout=5).stdout.strip()
        if o and o.endswith(".service"):
            return o.replace(".service","").strip().split("/")[-1]
        if o and ".service" in o:
            m=re.search(r'([^/\s]+\.service)', o)
            if m: return m.group(1).replace(".service","")
    except: pass
    try:
        with open(f"/proc/{pid}/cgroup","r",encoding="utf-8",errors="ignore") as f:
            c=f.read()
            m=re.search(r'/system\.slice/([^/\.\s]+)\.service', c)
            if m: return m.group(1)
            m=re.search(r'/([^/\s]+\.service)', c)
            if m: return m.group(1).replace(".service","")
    except: pass
    try:
        o=subprocess.run(["ps","-p",str(pid),"-o","comm="],capture_output=True,text=True,timeout=5).stdout.strip()
        if o:
            return o.split("/")[-1].strip()
    except: pass
    try:
        # try readlink exe
        o=subprocess.run(["readlink",f"/proc/{pid}/exe"],capture_output=True,text=True,timeout=5).stdout.strip()
        if o:
            return os.path.basename(o)
    except: pass
    return ""

def os_svcs(only_with_ports=False):
    r=[]
    try:
        if platform.system()=="Windows":
            o=subprocess.run(["sc.exe","query","state=","all"],capture_output=True,text=True,timeout=15).stdout or ""
            for b in re.split(r"SERVICE_NAME:\s*",o)[1:]:
                l=b.splitlines()
                if not l: continue
                n=l[0].strip()
                d=s=""
                for x in l:
                    if "DISPLAY_NAME:" in x: d=x.split("DISPLAY_NAME:",1)[1].strip()
                    if "STATE" in x:
                        m=re.search(r"STATE\s*:\s*\d+\s+(\w+)",x)
                        if m: s=m.group(1)
                if n: r.append({"name":n,"display_name":d or n,"state":s or "UNKNOWN"})
            # Enrich with PID + exe (اسم الملف المشغّل)
            svc_to_pid, pid_to_svcs, svc_to_exe = _win_service_pid_map()
            for svc in r:
                pid=svc_to_pid.get(svc["name"], svc_to_pid.get(svc["name"].lower(), 0))
                svc["pid"]=pid
                info=svc_to_exe.get(svc["name"], svc_to_exe.get(svc["name"].lower(), {}))
                svc["exe"]=info.get("exe","") if isinstance(info,dict) else ""
                svc["exe_path"]=info.get("exe_path","") if isinstance(info,dict) else ""
                svc["pathname"]=info.get("pathname","") if isinstance(info,dict) else ""
            if only_with_ports:
                pid_to_ports=_win_listening_pid_to_ports()
                if not pid_to_ports:
                    print("[!] No listening ports found or netstat unavailable")
                    return []
                # Filter: فقط الخدمات التي لديها على الاقل منفذ TCP LISTENING
                # نحتفظ بكل المنافذ (TCP+UDP) للخدمة في التفاصيل لكن الشرط هو وجود TCP
                filtered=[]
                for svc in r:
                    pid=svc.get("pid",0)
                    ports=pid_to_ports.get(pid, [])
                    has_tcp=any(p.get("proto")=="TCP" and p.get("state")=="LISTENING" for p in ports)
                    if pid and has_tcp:
                        svc["listening_ports"]=ports
                        # تكملة اسم الملف اذا كان ناقصا: sc qc ثم tasklist
                        if not svc.get("exe"):
                            exe, exe_path, pn=_win_qc_pathname(svc["name"])
                            if not exe:
                                exe, exe_path, pn=_win_pid_to_exe(pid)
                            svc["exe"]=exe
                            svc["exe_path"]=exe_path
                            svc["pathname"]=pn
                        filtered.append(svc)
                print(f"[+] Filtered {len(filtered)}/{len(r)} services with TCP LISTENING ports (unique PIDs listening: {len(pid_to_ports)})")
                return filtered
            else:
                # if not filtering, still add empty listening_ports for consistency if needed
                # don't call netstat to save time
                # تكملة النواقص عبر sc qc فقط عند الطلب الكامل (قد يكون بطيئا) - نترك القيم من الخريطة
                return r
        else:
            o=subprocess.run(["systemctl","list-units","--type=service","--all","--no-pager","--plain"],capture_output=True,text=True,timeout=10).stdout
            for line in o.splitlines():
                if ".service" in line:
                    p=line.split()
                    n=p[0].replace(".service","") if p else ""
                    if n: r.append({"name":n,"display_name":n,"state":p[3] if len(p)>3 else "unknown","pid":0})
            # Try to enrich Linux services with PID via systemctl show? expensive, skip unless filtering
            if only_with_ports:
                pid_to_ports, pid_to_proc = _linux_listening_pid_to_ports()
                if not pid_to_ports:
                    print("[!] No listening ports found (ss/netstat requires root for -p) or no listeners")
                    return []
                # Build set of service names that have listening ports (يشترط TCP LISTENING)
                listening_svcs={}
                for pid, ports in pid_to_ports.items():
                    has_tcp=any(p.get("proto")=="TCP" for p in ports)
                    if not has_tcp:
                        continue
                    svc_name=_linux_pid_to_service(pid)
                    if not svc_name:
                        svc_name=pid_to_proc.get(pid,"")
                    if svc_name:
                        svc_name=svc_name.replace(".service","").strip()
                        listening_svcs[svc_name.lower()]=ports
                        listening_svcs[svc_name]=ports
                pid_to_ports_map=pid_to_ports
                filtered=[]
                for svc in r:
                    key=svc["name"].lower()
                    if key in listening_svcs:
                        svc["listening_ports"]=listening_svcs[key]
                        for pid, proc in pid_to_proc.items():
                            if proc.lower()==key or _linux_pid_to_service(pid).lower()==key:
                                svc["pid"]=pid
                                break
                        # enrich exe
                        pid=svc.get("pid",0)
                        if pid:
                            exe, exe_path, cmd=_linux_pid_to_exe(pid)
                            if not exe:
                                exe, exe_path, _cmd2=_linux_service_exec(svc["name"])
                                cmd=cmd or _cmd2
                            svc["exe"]=exe
                            svc["exe_path"]=exe_path
                            svc["exec_start"]=cmd
                        else:
                            exe, exe_path, cmd=_linux_service_exec(svc["name"])
                            svc["exe"]=exe
                            svc["exe_path"]=exe_path
                            svc["exec_start"]=cmd
                        filtered.append(svc)
                    else:
                        try:
                            out=subprocess.run(["systemctl","show","--property=MainPID",svc["name"]],capture_output=True,text=True,timeout=3).stdout or ""
                            m=re.search(r'MainPID=(\d+)', out)
                            if m:
                                pid=int(m.group(1))
                                svc["pid"]=pid
                                ports=pid_to_ports_map.get(pid,[])
                                has_tcp=any(p.get("proto")=="TCP" for p in ports)
                                if pid in pid_to_ports_map and has_tcp:
                                    svc["listening_ports"]=ports
                                    exe, exe_path, cmd=_linux_pid_to_exe(pid)
                                    if not exe:
                                        exe, exe_path, _cmd2=_linux_service_exec(svc["name"])
                                        cmd=cmd or _cmd2
                                    svc["exe"]=exe
                                    svc["exe_path"]=exe_path
                                    svc["exec_start"]=cmd
                                    filtered.append(svc)
                                    continue
                        except: pass
                print(f"[+] Filtered {len(filtered)}/{len(r)} services with TCP LISTENING ports (unique PIDs: {len(pid_to_ports)})")
                return filtered
            # غير مفلتر: اضف exe عبر systemctl show بسرعة؟ نترك فارغا لتوفير الوقت، او املأ عند الحاجة
            for svc in r:
                svc["exe"]=""
                svc["exe_path"]=""
                svc["exec_start"]=""
            return r
    except Exception as e:
        # debug
        # print(f"[-] os_svcs error: {e}")
        pass
    return r

def login():
    global AUTH
    try:
        a=f'KSCBasic user="{b64(U)}", pass="{b64(W)}", internal="0"'
        h=ses.post(f"{B}/login",headers={"Authorization":a},json={},timeout=10)
        if h.status_code==200:
            print(f"[+] Login {U}")
            AUTH=True
            ses.headers.pop("Authorization",None)
            return True
        print(f"[-] Login {h.status_code}")
    except Exception as e: print(e)
    return False

def api(m,p=None):
    try:
        r=ses.post(f"{B}/{m}",json=p or {},timeout=30)
        if r.status_code!=200:
            print(f"[-] {m} {r.status_code}")
            return None
        return r.json() if r.content else {}
    except Exception as e:
        print(f"[-] {m} {e}")
        return None

def hosts():
    print("[*] Fetching hosts")
    r=api("HostGroup.FindHosts",{"wstrFilter":"","vecFieldsToReturn":["KLHST_WKS_HOSTNAME","KLHST_WKS_DN","KLHST_WKS_FQDN","KLHST_WKS_IP","KLHST_WKS_OS_NAME","KLHST_WKS_LAST_VISIBLE","KLHST_INSTANCEID","KLHST_WKS_NAG_VERSION"],"lMaxLifeTime":3600})
    if not r or "strAccessor" not in r: return []
    a=r["strAccessor"]
    hs=[]
    s=0
    while True:
        c=api("ChunkAccessor.GetItemsChunk",{"strAccessor":a,"nStart":s,"nCount":1000})
        if not c: break
        pc=c.get("pChunk",c) if isinstance(c,dict) else c
        arr=pc.get("KLCSP_ITERATOR_ARRAY",[]) if isinstance(pc,dict) else []
        cur=[{"pInfo":x.get("value",x)} if isinstance(x.get("value",x),dict) and any(k.startswith("KLHST_") for k in x.get("value",x)) else x.get("value",x) for x in arr]
        if not cur: break
        hs.extend(cur)
        if len(cur)<1000: break
        s+=1000
    try: api("ChunkAccessor.Release",{"strAccessor":a})
    except: pass
    print(f"[+] Found {len(hs)} hosts")
    return hs

def inv(hid):
    pro,pat=[],[] 
    r=api("InventoryApi.GetHostInvProducts",{"szwHostId":hid})
    if r and "PxgRetVal" in r:
        for x in r["PxgRetVal"].get("GNRL_EA_PARAM_1",[]):
            v=x.get("value",x) if isinstance(x,dict) else {}
            if isinstance(v,dict) and v.get("DisplayName"):
                pro.append({"name":v.get("DisplayName",""),"version":v.get("DisplayVersion",""),"publisher":v.get("Publisher",""),"install_date":v.get("InstallDate","")})
    r=api("InventoryApi.GetHostInvPatches",{"szwHostId":hid})
    if r and "PxgRetVal" in r:
        for x in r["PxgRetVal"].get("GNRL_EA_PARAM_1",[]):
            v=x.get("value",x) if isinstance(x,dict) else {}
            if isinstance(v,dict): pat.append({"name":v.get("DisplayName",""),"patch_id":v.get("PatchID",""),"classification":v.get("Classification","")})
    return pro,pat

def main():
    if not login(): return
    hs=hosts()
    if not hs: print("No hosts"); return
    out=[]
    for h in hs:
        info=h.get("pInfo",h) if isinstance(h,dict) else {}
        if "value" in info and isinstance(info["value"],dict): info=info["value"]
        hid=str(info.get("KLHST_WKS_HOSTNAME") or "")
        dn=str(info.get("KLHST_WKS_DN") or "")
        fqdn=str(info.get("KLHST_WKS_FQDN") or "")
        dsp=dn or fqdn or hid
        ip=info.get("KLHST_WKS_IP")
        ips=ip2s(ip) if isinstance(ip,int) else (", ".join(ip2s(x) if isinstance(x,int) else str(x) for x in ip) if isinstance(ip,list) else str(ip or ""))
        print(f" -> {dsp} : inventory")
        pro,pat=inv(hid) if hid else ([],[])
        out.append({"host":{"display_name":dsp,"dn":dn,"fqdn":fqdn,"id":hid,"instance_id":str(info.get("KLHST_INSTANCEID") or ""),"ip":ips,"os":str(info.get("KLHST_WKS_OS_NAME") or ""),"nag_version":str(info.get("KLHST_WKS_NAG_VERSION") or ""),"last_visible":str(info.get("KLHST_WKS_LAST_VISIBLE") or "")},"software":pro,"os_services":[],"patches":pat,"summary":{"total_products":len(pro),"total_os_services":0,"total_patches":len(pat)}})
    data={"generated_at":datetime.now().isoformat(),"ksc_server":S,"total_hosts":len(out),"hosts":out}
    fn=f"kaspersky_inventory_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    open(fn,"w",encoding="utf-8").write(json.dumps(data,ensure_ascii=False,indent=2))
    print(f"[+] JSON saved: {fn} (hosts={len(out)})")
    try: api("Session.Logout",{})
    except: pass

if __name__=="__main__": main()
