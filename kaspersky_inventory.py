#!/usr/bin/env python3
import os, json, base64, struct, socket, logging, argparse, warnings, getpass, sys
from pathlib import Path
from datetime import datetime, timezone
import requests, urllib3

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("ksc")

from lib import get_app_dir, get_out_dir

# ---------- settings.json handling ----------
SETTINGS_PATH = get_app_dir() / "settings.json"
DEFAULT_SETTINGS = {
    "KSC_SERVER": "127.0.0.1",
    "KSC_API_PORT": 13299,
    "KSC_VERIFY_SSL": False,
    "KSC_USERNAME": "",
    "KSC_PASSWORD": ""
}

def load_settings(path=SETTINGS_PATH):
    if not Path(path).exists():
        return {}
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8-sig"))
        if isinstance(data, dict):
            return data
    except Exception as e:
        log.warning("Failed to load %s: %s", path, e)
    return {}

def save_settings(settings, path=SETTINGS_PATH):
    try:
        p = Path(path)
        p.write_text(json.dumps(settings, indent=2, ensure_ascii=False), encoding="utf-8")
        try:
            # settings.json contains a plaintext password: restrict permissions when possible.
            os.chmod(p, 0o600)
        except Exception:
            pass
        log.warning("settings.json contains a plaintext password - restrict file access")
        log.info("Settings saved to %s", path)
    except Exception as e:
        log.error("Failed to save settings %s: %s", path, e)

def _prompt_text(label, default=""):
    d = str(default) if default is not None else ""
    suffix = f" [{d}]" if d else ""
    try:
        val = input(f"{label}{suffix}: ").strip()
    except EOFError:
        val = ""
    if val == "":
        return d
    return val

def _prompt_int(label, default):
    while True:
        raw = _prompt_text(label, str(default))
        try:
            iv = int(raw)
            if 1 <= iv <= 65535:
                return iv
            print("  -> Port must be 1-65535")
        except ValueError:
            print("  -> Invalid number, try again")

def _prompt_bool(label, default):
    # default bool
    def_str = "Y/n" if default else "y/N"
    while True:
        raw = _prompt_text(f"{label} ({def_str})", "")
        if raw == "":
            return default
        low = raw.strip().lower()
        if low in ("y", "yes", "1", "true"):
            return True
        if low in ("n", "no", "0", "false"):
            return False
        print("  -> Enter y or n")

def _prompt_password(label, default=""):
    has_default = bool(default)
    hint = "******" if has_default else ""
    suffix = f" [{hint}]" if has_default else ""
    prompt = f"{label}{suffix}: "
    try:
        # getpass hides input; if no tty fallback to input
        if sys.stdin.isatty():
            val = getpass.getpass(prompt)
        else:
            val = input(prompt).strip()
    except EOFError:
        val = ""
    except Exception:
        val = input(prompt).strip()
    if val == "" and has_default:
        return default
    return val

def prompt_for_config(existing):
    """Interactive prompt, pre-filled from existing (settings.json). Returns new dict."""
    print("\n=== Kaspersky Security Center - Configuration ===")
    if Path(SETTINGS_PATH).exists():
        print(f"Found {SETTINGS_PATH} - press Enter to keep current value, or type new value.\n")
    else:
        print(f"No {SETTINGS_PATH} found - you will be asked for each value. It will be created.\n")

    # merge defaults + existing to show pre-filled
    cur = {**DEFAULT_SETTINGS, **(existing or {})}
    # normalize types from json (port may be str, verify may be 0/1)
    try:
        cur["KSC_API_PORT"] = int(cur.get("KSC_API_PORT", 13299))
    except:
        cur["KSC_API_PORT"] = 13299
    v = cur.get("KSC_VERIFY_SSL", False)
    if isinstance(v, str):
        cur["KSC_VERIFY_SSL"] = v == "1" or v.lower() in ("true", "yes", "y")
    elif isinstance(v, int):
        cur["KSC_VERIFY_SSL"] = bool(v)
    else:
        cur["KSC_VERIFY_SSL"] = bool(v)

    new = {}
    new["KSC_SERVER"] = _prompt_text("KSC_SERVER (IP/hostname)", cur.get("KSC_SERVER", "127.0.0.1"))
    new["KSC_API_PORT"] = _prompt_int("KSC_API_PORT", cur.get("KSC_API_PORT", 13299))
    new["KSC_VERIFY_SSL"] = _prompt_bool("Verify SSL", cur.get("KSC_VERIFY_SSL", False))
    new["KSC_USERNAME"] = _prompt_text("KSC_USERNAME", cur.get("KSC_USERNAME", ""))
    # validate username not empty
    while not new["KSC_USERNAME"].strip():
        print("  -> Username cannot be empty")
        new["KSC_USERNAME"] = _prompt_text("KSC_USERNAME", "")

    new["KSC_PASSWORD"] = _prompt_password("KSC_PASSWORD", cur.get("KSC_PASSWORD", ""))
    while not new["KSC_PASSWORD"]:
        print("  -> Password cannot be empty")
        new["KSC_PASSWORD"] = _prompt_password("KSC_PASSWORD", "")

    # save logic: only ask if settings.json does not exist, otherwise auto-save
    existed_before = Path(SETTINGS_PATH).exists()
    if existed_before:
        save_settings(new, SETTINGS_PATH)
    else:
        save_q = _prompt_text(f"Save to {SETTINGS_PATH}? (Y/n)", "Y")
        do_save = save_q.strip().lower() not in ("n", "no")
        if do_save:
            save_settings(new, SETTINGS_PATH)
        else:
            print("  -> Not saved (using in-memory only)")

    return new

def init_config(args):
    """
    Load settings.json, optionally prompt interactively.
    Returns config dict and applies globals BASE_URL / session.verify.
    """
    global KSC_SERVER, KSC_PORT, KSC_VERIFY_SSL, KSC_USERNAME, KSC_PASSWORD, BASE_URL, SETTINGS_PATH

    # allow custom path via --settings
    settings_path = Path(getattr(args, "settings", None) or SETTINGS_PATH)
    existing = load_settings(settings_path)

    # --no-input : never prompt, just use settings.json / defaults
    no_input = bool(getattr(args, "no_input", False))

    # also respect --ksc-server etc if passed via CLI (optional, for automation)
    cli_overrides = {}
    for k in ("KSC_SERVER", "KSC_API_PORT", "KSC_VERIFY_SSL", "KSC_USERNAME", "KSC_PASSWORD"):
        # argparse may have lowercased names
        attr = k.lower()
        if hasattr(args, attr) and getattr(args, attr) is not None:
            cli_overrides[k] = getattr(args, attr)

    if cli_overrides:
        # CLI takes precedence, no prompt needed
        cfg = {**DEFAULT_SETTINGS, **existing, **cli_overrides}
        # normalize
        cfg["KSC_API_PORT"] = int(cfg["KSC_API_PORT"])
        cfg["KSC_VERIFY_SSL"] = bool(cfg["KSC_VERIFY_SSL"]) if not isinstance(cfg["KSC_VERIFY_SSL"], str) else cfg["KSC_VERIFY_SSL"] in ("1", "true", "True", "yes")
    elif no_input:
        cfg = {**DEFAULT_SETTINGS, **existing}
        try:
            cfg["KSC_API_PORT"] = int(cfg["KSC_API_PORT"])
        except:
            cfg["KSC_API_PORT"] = 13299
        v = cfg.get("KSC_VERIFY_SSL", False)
        if isinstance(v, str):
            cfg["KSC_VERIFY_SSL"] = v == "1" or v.lower() in ("true", "yes")
        elif isinstance(v, int):
            cfg["KSC_VERIFY_SSL"] = bool(v)
        SETTINGS_PATH = settings_path
        if not cfg.get("KSC_USERNAME") or not cfg.get("KSC_PASSWORD"):
            log.error("Settings %s missing username/password. Run without --no-input to create it.", settings_path)
    else:
        # interactive: always prompt (pre-filled from settings.json if exists)
        # if stdin is not a tty but input is piped, _prompt_* will handle EOF gracefully
        if not sys.stdin.isatty() and (not existing or not existing.get("KSC_USERNAME")):
            log.warning("stdin is not a tty - trying to prompt anyway (piped input?)")
        SETTINGS_PATH = settings_path
        try:
            cfg = prompt_for_config(existing)
        except (EOFError, KeyboardInterrupt):
            log.warning("Prompt interrupted / no input - falling back to %s", settings_path)
            cfg = {**DEFAULT_SETTINGS, **existing}
            try:
                cfg["KSC_API_PORT"] = int(cfg["KSC_API_PORT"])
            except:
                cfg["KSC_API_PORT"] = 13299

    # apply globals
    KSC_SERVER = str(cfg.get("KSC_SERVER") or DEFAULT_SETTINGS["KSC_SERVER"]).strip()
    KSC_PORT = int(cfg.get("KSC_API_PORT") or 13299)
    KSC_VERIFY_SSL = bool(cfg.get("KSC_VERIFY_SSL"))
    KSC_USERNAME = str(cfg.get("KSC_USERNAME") or "").strip()
    KSC_PASSWORD = str(cfg.get("KSC_PASSWORD") or "")

    BASE_URL = f"https://{KSC_SERVER}:{KSC_PORT}/api/v1.0"
    session.verify = KSC_VERIFY_SSL
    session.headers["Content-Type"] = "application/json"

    if not KSC_VERIFY_SSL:
        warnings.filterwarnings("ignore", category=urllib3.exceptions.InsecureRequestWarning)
        log.warning("SSL verification disabled (KSC_VERIFY_SSL=0)")
    else:
        warnings.filterwarnings("default", category=urllib3.exceptions.InsecureRequestWarning)

    return cfg

# will be set by init_config()
KSC_SERVER = DEFAULT_SETTINGS["KSC_SERVER"]
KSC_PORT = DEFAULT_SETTINGS["KSC_API_PORT"]
KSC_VERIFY_SSL = DEFAULT_SETTINGS["KSC_VERIFY_SSL"]
KSC_USERNAME = DEFAULT_SETTINGS["KSC_USERNAME"]
KSC_PASSWORD = DEFAULT_SETTINGS["KSC_PASSWORD"]
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
    p.add_argument("--settings",help="path to settings.json (default: ./settings.json)", default=str(SETTINGS_PATH))
    p.add_argument("--no-input",action="store_true",help="do not prompt, use settings.json directly (for automation)")
    # optional CLI overrides for automation (if provided, no prompt)
    p.add_argument("--ksc-server", dest="ksc_server", help=argparse.SUPPRESS)
    p.add_argument("--ksc-api-port", dest="ksc_api_port", type=int, help=argparse.SUPPRESS)
    p.add_argument("--ksc-username", dest="ksc_username", help=argparse.SUPPRESS)
    p.add_argument("--ksc-password", dest="ksc_password", help=argparse.SUPPRESS)
    a=p.parse_args(argv)
    if a.verbose: logging.getLogger().setLevel(logging.DEBUG)

    # map CLI overrides to expected keys for init_config
    # init_config reads a.ksc_* directly
    # normalize: create KSC_* attrs on a for init_config
    if getattr(a, "ksc_server", None) is not None:
        a.KSC_SERVER = a.ksc_server
    if getattr(a, "ksc_api_port", None) is not None:
        a.KSC_API_PORT = a.ksc_api_port
    if getattr(a, "ksc_username", None) is not None:
        a.KSC_USERNAME = a.ksc_username
    if getattr(a, "ksc_password", None) is not None:
        a.KSC_PASSWORD = a.ksc_password

    init_config(a)

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
        # Prefer hostname (historical behavior) but fall back to instance_id
        # when hostname yields nothing (duplicates/empty).
        pro, pat = ([], [])
        if host_id:
            pro, pat = get_inventory(host_id)
        if not pro and instance_id and instance_id != host_id:
            alt_pro, alt_pat = get_inventory(instance_id)
            if alt_pro or alt_pat:
                pro, pat = alt_pro, alt_pat
        if a.no_patches: pat=[]
        out.append({"host":{"display_name":display,"dn":dn,"fqdn":fqdn,"id":host_id,"instance_id":instance_id,"ip":ip_str(info.get("KLHST_WKS_IP")),"os":str(info.get("KLHST_WKS_OS_NAME") or ""),"nag_version":str(info.get("KLHST_WKS_NAG_VERSION") or ""),"last_visible":ksc_dt(info.get("KLHST_WKS_LAST_VISIBLE"))},"software":pro,"patches":pat,"summary":{"total_products":len(pro),"total_patches":len(pat)}})
        log.info(" -> %s (%s) products=%s patches=%s", display, (host_id or "?")[:8], len(pro), len(pat))
    data={"generated_at":datetime.now(timezone.utc).isoformat(),"ksc_server":KSC_SERVER,"total_hosts":len(out),"hosts":out}
    default_fn = get_out_dir() / f"kaspersky_inventory_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    fn = Path(a.output) if a.output else default_fn
    # if output is relative, make it relative to out dir (avoid out/out duplication)
    if not fn.is_absolute():
        if fn.parts and fn.parts[0].lower() == "out":
            fn = get_app_dir() / fn
        else:
            fn = get_out_dir() / fn
    fn.parent.mkdir(parents=True, exist_ok=True)
    with open(fn,"w",encoding="utf-8") as f: json.dump(data,f,ensure_ascii=False,indent=2)
    log.info("Saved %s hosts=%s", fn, len(out))
    logout()
    return 0

if __name__=="__main__":
    raise SystemExit(main())
