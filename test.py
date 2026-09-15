import os, sys, json, base64, struct, socket, requests, urllib3
from datetime import datetime

urllib3.disable_warnings()
if hasattr(sys.stdout, "reconfigure"):
    try: sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except: pass

# Config
S = os.getenv("KSC_SERVER", "192.168.10.20")
P = int(os.getenv("KSC_API_PORT", "13299"))
U = os.getenv("KSC_USERNAME", "Administrator")
W = os.getenv("KSC_PASSWORD", "Test@12345678-+")
V = os.getenv("KSC_VERIFY_SSL", "0") == "1"
B = f"https://{S}:{P}/api/v1.0"

ses = requests.Session()
ses.verify = V
ses.headers.update({"Content-Type": "application/json"})

def b64(s: str) -> str:
    return base64.b64encode(s.encode()).decode()

def ip2s(v) -> str:
    if isinstance(v, int):
        try: return socket.inet_ntoa(struct.pack("<I", v & 0xFFFFFFFF))
        except: return str(v)
    if isinstance(v, list):
        return ", ".join(ip2s(x) for x in v)
    return str(v or "")

def api(method: str, params: dict = None):
    try:
        r = ses.post(f"{B}/{method}", json=params or {}, timeout=30)
        if r.status_code != 200:
            print(f"[-] {method} {r.status_code}")
            return None
        return r.json() if r.content else {}
    except Exception as e:
        print(f"[-] {method} {e}")
        return None

def login() -> bool:
    try:
        auth = f'KSCBasic user="{b64(U)}", pass="{b64(W)}", internal="0"'
        r = ses.post(f"{B}/login", headers={"Authorization": auth}, json={}, timeout=10)
        if r.status_code == 200:
            print(f"[+] Login {U}")
            ses.headers.pop("Authorization", None)
            return True
        print(f"[-] Login {r.status_code}")
    except Exception as e:
        print(e)
    return False

def get_hosts():
    print("[*] Fetching hosts")
    r = api("HostGroup.FindHosts", {
        "wstrFilter": "",
        "vecFieldsToReturn": ["KLHST_WKS_HOSTNAME","KLHST_WKS_DN","KLHST_WKS_FQDN","KLHST_WKS_IP","KLHST_WKS_OS_NAME","KLHST_WKS_LAST_VISIBLE","KLHST_INSTANCEID","KLHST_WKS_NAG_VERSION"],
        "lMaxLifeTime": 3600
    })
    if not r or "strAccessor" not in r:
        return []
    accessor = r["strAccessor"]
    hosts, start = [], 0
    while True:
        c = api("ChunkAccessor.GetItemsChunk", {"strAccessor": accessor, "nStart": start, "nCount": 1000})
        if not c: break
        chunk = c.get("pChunk", c) if isinstance(c, dict) else c
        arr = chunk.get("KLCSP_ITERATOR_ARRAY", []) if isinstance(chunk, dict) else []
        cur = []
        for x in arr:
            v = x.get("value", x)
            # KSC يرجع أحيانا {value:{KLHST_...}}
            if isinstance(v, dict) and any(k.startswith("KLHST_") for k in v):
                cur.append({"pInfo": v})
            else:
                cur.append(v if isinstance(v, dict) else {"pInfo": v})
            # أبسط: اذا كان value dict نحتفظ به
            if isinstance(x.get("value"), dict) and any(k.startswith("KLHST_") for k in x["value"]):
                cur[-1] = {"pInfo": x["value"]}
        if not cur: break
        hosts.extend(cur)
        if len(cur) < 1000: break
        start += 1000
    try: api("ChunkAccessor.Release", {"strAccessor": accessor})
    except: pass
    print(f"[+] Found {len(hosts)} hosts")
    return hosts

def get_inventory(host_id: str):
    products, patches = [], []
    r = api("InventoryApi.GetHostInvProducts", {"szwHostId": host_id})
    if r and "PxgRetVal" in r:
        for x in r["PxgRetVal"].get("GNRL_EA_PARAM_1", []):
            v = x.get("value", x) if isinstance(x, dict) else {}
            if isinstance(v, dict) and v.get("DisplayName"):
                products.append({"name": v.get("DisplayName",""), "version": v.get("DisplayVersion",""), "publisher": v.get("Publisher",""), "install_date": v.get("InstallDate","")})
    r = api("InventoryApi.GetHostInvPatches", {"szwHostId": host_id})
    if r and "PxgRetVal" in r:
        for x in r["PxgRetVal"].get("GNRL_EA_PARAM_1", []):
            v = x.get("value", x) if isinstance(x, dict) else {}
            if isinstance(v, dict):
                patches.append({"name": v.get("DisplayName",""), "patch_id": v.get("PatchID",""), "classification": v.get("Classification","")})
    return products, patches

def main():
    if not login(): return
    hosts = get_hosts()
    if not hosts:
        print("No hosts"); return

    out = []
    for h in hosts:
        info = h.get("pInfo", h) if isinstance(h, dict) else {}
        if "value" in info and isinstance(info["value"], dict):
            info = info["value"]

        hid  = str(info.get("KLHST_WKS_HOSTNAME") or "")
        dn   = str(info.get("KLHST_WKS_DN") or "")
        fqdn = str(info.get("KLHST_WKS_FQDN") or "")
        dsp  = dn or fqdn or hid
        ips  = ip2s(info.get("KLHST_WKS_IP"))

        print(f" -> {dsp} : inventory")
        pro, pat = get_inventory(hid) if hid else ([], [])

        out.append({
            "host": {"display_name": dsp, "dn": dn, "fqdn": fqdn, "id": hid, "instance_id": str(info.get("KLHST_INSTANCEID") or ""), "ip": ips, "os": str(info.get("KLHST_WKS_OS_NAME") or ""), "nag_version": str(info.get("KLHST_WKS_NAG_VERSION") or ""), "last_visible": str(info.get("KLHST_WKS_LAST_VISIBLE") or "")},
            "software": pro,
            "patches": pat,
            "summary": {"total_products": len(pro), "total_patches": len(pat)}
        })

    data = {"generated_at": datetime.now().isoformat(), "ksc_server": S, "total_hosts": len(out), "hosts": out}
    fn = f"kaspersky_inventory_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(fn, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    print(f"[+] JSON saved: {fn} (hosts={len(out)})")
    try: api("Session.Logout", {})
    except: pass

if __name__ == "__main__":
    main()
