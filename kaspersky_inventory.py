#!/usr/bin/env python3
import os, json, base64, struct, socket, logging, argparse, warnings
from datetime import datetime, timezone
import requests, urllib3

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("ksc")

# load .env
def load_dotenv(p=".env"):
    if not os.path.exists(p):
        return
    for line in open(p, encoding="utf-8"):
        line=line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k,v=line.split("=",1)
        k=k.strip(); v=v.strip().strip('"').strip("'")
        if k and k not in os.environ:
            os.environ[k]=v
load_dotenv()

KSC_SERVER = os.getenv("KSC_SERVER") or "127.0.0.1"
KSC_PORT = int(os.getenv("KSC_API_PORT") or "13299")
KSC_VERIFY_SSL = (os.getenv("KSC_VERIFY_SSL") or "0") == "1"
KSC_USERNAME = os.getenv("KSC_USERNAME")
KSC_PASSWORD = os.getenv("KSC_PASSWORD")
if not KSC_USERNAME or not KSC_PASSWORD:
    log.warning("Missing KSC_USERNAME/KSC_PASSWORD in .env")

if not KSC_VERIFY_SSL:
    warnings.filterwarnings("ignore", category=urllib3.exceptions.InsecureRequestWarning)
    log.warning("SSL verification disabled (KSC_VERIFY_SSL=0)")

BASE_URL = f"https://{KSC_SERVER}:{KSC_PORT}/api/v1.0"
session = requests.Session()
session.verify = KSC_VERIFY_SSL
session.headers["Content-Type"] = "application/json"

def b64(s): return base64.b64encode(s.encode()).decode()

def ksc_dt(v):
    if isinstance(v, dict):
        return str(v.get("value",""))
    return str(v or "")

def ip_str(v):
    if isinstance(v,int):
        try: return socket.inet_ntoa(struct.pack("<I", v & 0xFFFFFFFF))
        except: return str(v)
    if isinstance(v,list):
        return ", ".join(ip_str(x) for x in v if x is not None)
    return str(v or "")

def api(method, params=None, timeout=30):
    try:
        r = session.post(f"{BASE_URL}/{method}", json=params or {}, timeout=timeout)
        if r.status_code != 200:
            log.error("API %s failed %s %s", method, r.status_code, r.text[:300])
            return None
        return r.json() if r.content else {}
    except Exception as e:
        log.error("API %s error %s", method, e)
        return None

def login():
    if not KSC_USERNAME or not KSC_PASSWORD:
        log.error("Missing credentials")
        return False
    auth = f'KSCBasic user="{b64(KSC_USERNAME)}", pass="{b64(KSC_PASSWORD)}", internal="0"'
    try:
        r = session.post(f"{BASE_URL}/login", headers={"Authorization": auth}, json={}, timeout=10)
        if r.status_code == 200:
            log.info("Login ok as %s", KSC_USERNAME)
            return True
        log.error("Login failed %s %s", r.status_code, r.text[:300])
    except Exception as e:
        log.error("Login error %s", e)
    return False

def logout():
    try: api("Session.Logout", {}, timeout=10)
    except: pass

def extract_pinfo(item):
    if not isinstance(item, dict):
        return {}
    if "pInfo" in item and isinstance(item["pInfo"], dict):
        return item["pInfo"]
    if "value" in item and isinstance(item["value"], dict):
        v=item["value"]
        if any(k.startswith("KLHST_") for k in v):
            return v
        if "pInfo" in v:
            return v["pInfo"]
        return v
    if any(k.startswith("KLHST_") for k in item):
        return item
    return item

def get_hosts():
    log.info("Fetching hosts...")
    r = api("HostGroup.FindHosts", {"wstrFilter":"", "vecFieldsToReturn":["KLHST_WKS_HOSTNAME","KLHST_WKS_DN","KLHST_WKS_FQDN","KLHST_WKS_IP","KLHST_WKS_OS_NAME","KLHST_WKS_LAST_VISIBLE","KLHST_INSTANCEID","KLHST_WKS_NAG_VERSION"], "lMaxLifeTime":3600})
    if not r or "strAccessor" not in r:
        log.error("FindHosts failed %s", r)
        return []
    accessor=r["strAccessor"]
    hosts=[]; start=0
    try:
        while True:
            c=api("ChunkAccessor.GetItemsChunk", {"strAccessor":accessor,"nStart":start,"nCount":1000})
            if not c: break
            chunk=c.get("pChunk",c) if isinstance(c,dict) else c
            arr=chunk.get("KLCSP_ITERATOR_ARRAY",[]) if isinstance(chunk,dict) else []
            if not arr: break
            cur=[{"pInfo": extract_pinfo(x)} for x in arr]
            hosts.extend(cur)
            if len(cur)<1000: break
            start+=1000
    finally:
        try: api("ChunkAccessor.Release", {"strAccessor":accessor}, timeout=10)
        except: pass
    log.info("Found %s hosts", len(hosts))
    return hosts

def get_inventory(host_id):
    if not host_id: return [],[]
    pro, pat = [],[]
    r=api("InventoryApi.GetHostInvProducts", {"szwHostId":host_id})
    if r and "PxgRetVal" in r:
        for x in r["PxgRetVal"].get("GNRL_EA_PARAM_1",[]):
            v=x.get("value",x) if isinstance(x,dict) else {}
            if isinstance(v,dict) and v.get("DisplayName"):
                pro.append({"name":str(v.get("DisplayName","")), "version":str(v.get("DisplayVersion","")), "publisher":str(v.get("Publisher","")), "install_date":str(v.get("InstallDate",""))})
    r=api("InventoryApi.GetHostInvPatches", {"szwHostId":host_id})
    if r and "PxgRetVal" in r:
        for x in r["PxgRetVal"].get("GNRL_EA_PARAM_1",[]):
            v=x.get("value",x) if isinstance(x,dict) else {}
            if isinstance(v,dict):
                n=str(v.get("DisplayName","")).strip()
                if not n and not v.get("PatchID"): continue
                pat.append({"name":n, "patch_id":str(v.get("PatchID","")), "classification":str(v.get("Classification",""))})
    return pro,pat

def main(argv=None):
    p=argparse.ArgumentParser(description="KSC inventory exporter")
    p.add_argument("-o","--output",help="output JSON path")
    p.add_argument("--no-patches",action="store_true",help="skip patches")
    p.add_argument("-v","--verbose",action="store_true")
    a=p.parse_args(argv)
    if a.verbose: logging.getLogger().setLevel(logging.DEBUG)
    if not login(): return 1
    hosts=get_hosts()
    if not hosts:
        log.warning("No hosts"); logout(); return 0
    out=[]
    for h in hosts:
        info=h.get("pInfo",h) if isinstance(h,dict) else {}
        if "value" in info and isinstance(info["value"], dict):
            info=info["value"]
        host_id=str(info.get("KLHST_WKS_HOSTNAME") or "").strip()
        instance_id=str(info.get("KLHST_INSTANCEID") or "").strip()
        dn=str(info.get("KLHST_WKS_DN") or "").strip()
        fqdn=str(info.get("KLHST_WKS_FQDN") or "").strip()
        display=dn or fqdn or host_id or "unknown"
        pro,pat=get_inventory(host_id) if host_id else ([],[])
        if a.no_patches: pat=[]
        out.append({"host":{"display_name":display,"dn":dn,"fqdn":fqdn,"id":host_id,"instance_id":instance_id,"ip":ip_str(info.get("KLHST_WKS_IP")),"os":str(info.get("KLHST_WKS_OS_NAME") or ""),"nag_version":str(info.get("KLHST_WKS_NAG_VERSION") or ""),"last_visible":ksc_dt(info.get("KLHST_WKS_LAST_VISIBLE"))},"software":pro,"patches":pat,"summary":{"total_products":len(pro),"total_patches":len(pat)}})
        log.info(" -> %s (%s) products=%s patches=%s", display, host_id[:8], len(pro), len(pat))
    data={"generated_at":datetime.now(timezone.utc).isoformat(),"ksc_server":KSC_SERVER,"total_hosts":len(out),"hosts":out}
    fn=a.output or f"kaspersky_inventory_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(fn,"w",encoding="utf-8") as f: json.dump(data,f,ensure_ascii=False,indent=2)
    log.info("Saved %s hosts=%s", fn, len(out))
    logout()
    return 0

if __name__=="__main__":
    raise SystemExit(main())
