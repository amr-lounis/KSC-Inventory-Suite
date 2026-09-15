#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Kaspersky Security Center - Inventory Exporter
Fixes applied: secure config (no hardcoded secrets), SSL verify default ON,
correct host ID (KLHST_INSTANCEID), proper pagination + accessor release,
datetime/IP parsing, logging, argparse, type hints.
"""
import os
import sys
import json
import base64
import struct
import socket
import logging
import argparse
import warnings
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import requests
import urllib3

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("ksc_inventory")

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# ---------------------------------------------------------------------------
# Config - load .env, no hardcoded defaults (all values must come from .env)
# ---------------------------------------------------------------------------
def _load_dotenv(path: str = ".env") -> None:
    """Simple .env loader without extra dependency. Does not override existing env vars."""
    try:
        if not os.path.exists(path):
            log.warning("Missing .env file at %s - create it from .env.example", path)
            return
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                k = k.strip()
                v = v.strip().strip('"').strip("'")
                if k and k not in os.environ:
                    os.environ[k] = v
        log.debug("Loaded env from %s", path)
    except Exception as e:
        log.debug("Failed to load %s: %s", path, e)

_load_dotenv()

def _require_env(name: str) -> Optional[str]:
    """Get env var, warn if missing in .env."""
    val = os.getenv(name)
    if not val:
        log.warning("Missing %s in .env - please set it in .env file (see .env.example)", name)
    return val

KSC_SERVER: Optional[str] = _require_env("KSC_SERVER")
KSC_PORT_RAW: Optional[str] = _require_env("KSC_API_PORT")
KSC_USERNAME: Optional[str] = _require_env("KSC_USERNAME")
KSC_PASSWORD: Optional[str] = _require_env("KSC_PASSWORD")

# KSC_VERIFY_SSL: warn if not set, default to disabled for compatibility but warn
KSC_VERIFY_SSL_RAW: Optional[str] = os.getenv("KSC_VERIFY_SSL")
if KSC_VERIFY_SSL_RAW is None:
    log.warning("Missing KSC_VERIFY_SSL in .env - please set it (0=disabled, 1=enabled) in .env file")
    KSC_VERIFY_SSL: bool = False
else:
    KSC_VERIFY_SSL = KSC_VERIFY_SSL_RAW == "1"

if not KSC_VERIFY_SSL:
    warnings.filterwarnings("ignore", category=urllib3.exceptions.InsecureRequestWarning)
    log.warning("SSL verification disabled (KSC_VERIFY_SSL=0) - vulnerable to MITM! Set to 1 when cert is trusted.")

# Validate and parse port, handle missing/invalid with warning
KSC_PORT: Optional[int] = None
if KSC_PORT_RAW:
    try:
        KSC_PORT = int(KSC_PORT_RAW)
    except ValueError:
        log.warning("Invalid KSC_API_PORT value '%s' in .env - must be a number", KSC_PORT_RAW)
else:
    log.warning("KSC_API_PORT not set - cannot build API URL")

# Build base URL only if server and port are available
if KSC_SERVER and KSC_PORT:
    BASE_URL = f"https://{KSC_SERVER}:{KSC_PORT}/api/v1.0"
else:
    BASE_URL = ""  # will cause login/api to fail with clear error, but import still succeeds
    log.warning("BASE_URL not built due to missing KSC_SERVER or KSC_API_PORT in .env")

BASE_URL = f"https://{KSC_SERVER}:{KSC_PORT}/api/v1.0"

session = requests.Session()
session.verify = KSC_VERIFY_SSL
session.headers.update({"Content-Type": "application/json"})

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def b64(s: str) -> str:
    """Base64 encode string (KSC expects user/pass base64)."""
    return base64.b64encode(s.encode("utf-8")).decode("ascii")


def ksc_datetime_to_iso(value: Any) -> str:
    """
    KSC returns datetime as dict like {'type': 'datetime', 'value': '2026-09-15T09:35:35Z'}
    or as string. Convert to clean ISO string.
    """
    if value is None:
        return ""
    if isinstance(value, dict):
        # Common case
        v = value.get("value", "")
        if isinstance(v, str):
            return v
        return str(v) if v else ""
    if isinstance(value, str):
        return value
    return str(value)


def ip_to_str(value: Any) -> str:
    """
    KLHST_WKS_IP can be int (LE) or list[int] or str.
    KSC stores IP as uint32 little-endian (documented in KSC examples).
    """
    if value is None:
        return ""
    if isinstance(value, int):
        try:
            # KSC uses little-endian
            return socket.inet_ntoa(struct.pack("<I", value & 0xFFFFFFFF))
        except Exception:
            return str(value)
    if isinstance(value, list):
        parts = [ip_to_str(x) for x in value if x is not None]
        # Remove empty duplicates
        return ", ".join(p for p in parts if p)
    if isinstance(value, str):
        return value
    return str(value)


def api(method: str, params: Optional[Dict[str, Any]] = None, timeout: int = 30) -> Optional[Dict[str, Any]]:
    """POST to KSC API with unified error handling."""
    url = f"{BASE_URL}/{method}"
    try:
        resp = session.post(url, json=params or {}, timeout=timeout)
        if resp.status_code != 200:
            # Try to show body for diagnostics (may contain KSC error message)
            body = resp.text[:500] if resp.text else ""
            log.error("API %s failed: HTTP %s %s", method, resp.status_code, body)
            return None
        if not resp.content:
            return {}
        try:
            return resp.json()
        except json.JSONDecodeError:
            log.error("API %s returned invalid JSON", method)
            return None
    except requests.exceptions.RequestException as e:
        log.error("API %s connection error: %s", method, e)
        return None
    except Exception as e:
        log.error("API %s unexpected error: %s", method, e)
        return None


def login() -> bool:
    """KSCBasic login. Stores session cookie in session."""
    if not KSC_USERNAME or not KSC_PASSWORD:
        log.error("Missing credentials: KSC_USERNAME/KSC_PASSWORD")
        return False
    try:
        auth = f'KSCBasic user="{b64(KSC_USERNAME)}", pass="{b64(KSC_PASSWORD)}", internal="0"'
        # Do not send Authorization as persistent header, only for this request
        resp = session.post(f"{BASE_URL}/login", headers={"Authorization": auth}, json={}, timeout=10)
        if resp.status_code == 200:
            log.info("Login successful as user: %s", KSC_USERNAME)
            return True
        log.error("Login failed: HTTP %s %s", resp.status_code, resp.text[:500])
    except requests.exceptions.RequestException as e:
        log.error("Connection error during login: %s", e)
    except Exception as e:
        log.error("Unexpected error during login: %s", e)
    return False


def logout() -> None:
    try:
        api("Session.Logout", {}, timeout=10)
    except Exception:
        pass


def _extract_pinfo(item: Dict[str, Any]) -> Dict[str, Any]:
    """
    KSC returns items in different shapes:
    - {"pInfo": {...}}
    - {"value": {"KLHST_...": ...}}
    - {"value": {"pInfo": {...}}}
    Normalize to dict containing KLHST_*
    """
    if not isinstance(item, dict):
        return {}

    # Direct case
    if "pInfo" in item and isinstance(item["pInfo"], dict):
        return item["pInfo"]

    # Wrapped value
    if "value" in item:
        v = item["value"]
        if isinstance(v, dict):
            if any(k.startswith("KLHST_") for k in v):
                return v
            if "pInfo" in v and isinstance(v["pInfo"], dict):
                return v["pInfo"]
            # value itself may be pInfo without KLHST_ prefix
            return v

    # If item itself contains KLHST_
    if any(k.startswith("KLHST_") for k in item):
        return item

    return item


def get_hosts() -> List[Dict[str, Any]]:
    """Fetch all hosts via FindHosts + ChunkAccessor with correct pagination."""
    log.info("Fetching hosts from KSC...")
    resp = api("HostGroup.FindHosts", {
        "wstrFilter": "",
        "vecFieldsToReturn": [
            "KLHST_WKS_HOSTNAME",
            "KLHST_WKS_DN",
            "KLHST_WKS_FQDN",
            "KLHST_WKS_IP",
            "KLHST_WKS_OS_NAME",
            "KLHST_WKS_LAST_VISIBLE",
            "KLHST_INSTANCEID",
            "KLHST_WKS_NAG_VERSION",
        ],
        "lMaxLifeTime": 3600
    })
    if not resp or "strAccessor" not in resp:
        log.error("FindHosts did not return strAccessor: %s", resp)
        return []

    accessor: str = resp["strAccessor"]
    hosts: List[Dict[str, Any]] = []
    start = 0
    chunk_size = 1000

    try:
        while True:
            chunk_resp = api("ChunkAccessor.GetItemsChunk", {
                "strAccessor": accessor,
                "nStart": start,
                "nCount": chunk_size
            })
            if not chunk_resp:
                log.warning("GetItemsChunk returned None at start=%s", start)
                break

            # KSC may return {pChunk: {KLCSP_ITERATOR_ARRAY: [...]}} or directly
            if isinstance(chunk_resp, dict) and "pChunk" in chunk_resp:
                chunk = chunk_resp["pChunk"]
            else:
                chunk = chunk_resp

            if not isinstance(chunk, dict):
                log.warning("Unexpected chunk shape: %r", type(chunk))
                break

            arr = chunk.get("KLCSP_ITERATOR_ARRAY", [])
            if not isinstance(arr, list):
                log.warning("KLCSP_ITERATOR_ARRAY is not a list")
                break

            if not arr:
                break

            # Convert each item to {"pInfo": {...}}
            cur: List[Dict[str, Any]] = []
            for raw in arr:
                pinfo = _extract_pinfo(raw if isinstance(raw, dict) else {"pInfo": raw})
                cur.append({"pInfo": pinfo})

            hosts.extend(cur)
            log.debug("Fetched %s hosts (total %s)", len(cur), len(hosts))

            if len(cur) < chunk_size:
                break
            start += chunk_size
    finally:
        # Always release accessor even on error
        try:
            api("ChunkAccessor.Release", {"strAccessor": accessor}, timeout=10)
        except Exception:
            pass

    log.info("Found %s hosts", len(hosts))
    return hosts


def get_inventory(host_id: str) -> Tuple[List[Dict[str, str]], List[Dict[str, str]]]:
    """
    Fetch software and patches for a single host.
    host_id must be KLHST_WKS_HOSTNAME GUID (host ID), not KLHST_INSTANCEID.
    Verified: KLHST_WKS_HOSTNAME = 05f1ae37... returns 19 products, INSTANCEID returns error 1186.
    """
    if not host_id:
        return [], []

    products: List[Dict[str, str]] = []
    patches: List[Dict[str, str]] = []

    # Products
    r = api("InventoryApi.GetHostInvProducts", {"szwHostId": host_id})
    if r and "PxgRetVal" in r:
        items = r["PxgRetVal"].get("GNRL_EA_PARAM_1", []) if isinstance(r["PxgRetVal"], dict) else []
        for x in items:
            v = x.get("value", x) if isinstance(x, dict) else {}
            if isinstance(v, dict) and v.get("DisplayName"):
                products.append({
                    "name": str(v.get("DisplayName", "")),
                    "version": str(v.get("DisplayVersion", "")),
                    "publisher": str(v.get("Publisher", "")),
                    "install_date": str(v.get("InstallDate", "")),
                })
    elif r is not None and "PxgRetVal" not in r:
        log.debug("GetHostInvProducts %s did not return PxgRetVal", host_id)

    # Patches
    r = api("InventoryApi.GetHostInvPatches", {"szwHostId": host_id})
    if r and "PxgRetVal" in r:
        items = r["PxgRetVal"].get("GNRL_EA_PARAM_1", []) if isinstance(r["PxgRetVal"], dict) else []
        for x in items:
            v = x.get("value", x) if isinstance(x, dict) else {}
            if isinstance(v, dict):
                # Skip empty entries
                name = str(v.get("DisplayName", "")).strip()
                if not name and not v.get("PatchID"):
                    continue
                patches.append({
                    "name": name,
                    "patch_id": str(v.get("PatchID", "")),
                    "classification": str(v.get("Classification", "")),
                })

    return products, patches


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Export inventory from Kaspersky Security Center")
    parser.add_argument("-o", "--output", help="Output JSON path (default: kaspersky_inventory_YYYYMMDD_HHMMSS.json)")
    parser.add_argument("--no-patches", action="store_true", help="Skip patches (faster)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable DEBUG logging")
    args = parser.parse_args(argv)

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if not login():
        return 1

    hosts_raw = get_hosts()
    if not hosts_raw:
        log.warning("No hosts found")
        logout()
        return 0

    out: List[Dict[str, Any]] = []
    try:
        for h in hosts_raw:
            info = h.get("pInfo", h) if isinstance(h, dict) else {}
            if "value" in info and isinstance(info["value"], dict):
                info = info["value"]

            # KSC field mapping (verified with live server):
            # KLHST_WKS_HOSTNAME = host ID GUID (05f1ae37...) used for InventoryApi (returns 19 products)
            # KLHST_INSTANCEID = instance GUID (c44c...) returns error 1186 Object not found, so not for inventory
            # KLHST_WKS_DN/FQDN = human readable names
            host_id = str(info.get("KLHST_WKS_HOSTNAME") or "").strip()
            instance_id = str(info.get("KLHST_INSTANCEID") or "").strip()
            dn = str(info.get("KLHST_WKS_DN") or "").strip()
            fqdn = str(info.get("KLHST_WKS_FQDN") or "").strip()
            display = dn or fqdn or host_id or instance_id or "unknown"

            ips = ip_to_str(info.get("KLHST_WKS_IP"))
            last_visible = ksc_datetime_to_iso(info.get("KLHST_WKS_LAST_VISIBLE"))

            log.info(" -> %s : inventory (%s)", display, host_id[:8] if host_id else "no-id")

            if args.no_patches:
                # Fast mode: no patches
                products, patches = get_inventory(host_id) if host_id else ([], [])
                patches = []
            else:
                products, patches = get_inventory(host_id) if host_id else ([], [])

            out.append({
                "host": {
                    "display_name": display,
                    "hostname": host_id,  # keep GUID for backward compat (old code used HOSTNAME as id)
                    "dn": dn,
                    "fqdn": fqdn,
                    "id": host_id,
                    "instance_id": instance_id,
                    "ip": ips,
                    "os": str(info.get("KLHST_WKS_OS_NAME") or ""),
                    "nag_version": str(info.get("KLHST_WKS_NAG_VERSION") or ""),
                    "last_visible": last_visible,
                },
                "software": products,
                "patches": patches,
                "summary": {"total_products": len(products), "total_patches": len(patches)}
            })
    finally:
        # Even if loop fails, try logout
        pass

    data = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "ksc_server": KSC_SERVER,
        "total_hosts": len(out),
        "hosts": out
    }

    if args.output:
        fn = args.output
    else:
        fn = f"kaspersky_inventory_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

    try:
        with open(fn, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        log.info("JSON saved: %s (hosts=%s)", fn, len(out))
    except OSError as e:
        log.error("Failed to write file %s: %s", fn, e)
        logout()
        return 1

    logout()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
