"""Tests for kaspersky_inventory.py - pure helpers + mocked API."""
import json
import struct
import socket
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

import kaspersky_inventory as ksc


def test_b64():
    assert ksc.b64("admin") == "YWRtaW4="


def test_ksc_dt():
    assert ksc.ksc_dt({"value": "2024-01-01"}) == "2024-01-01"
    assert ksc.ksc_dt("plain") == "plain"
    assert ksc.ksc_dt(None) == ""


def test_ip_str_int_list_str():
    ip_int = struct.unpack("<I", socket.inet_aton("10.0.0.5"))[0]
    assert ksc.ip_str(ip_int) == "10.0.0.5"
    assert ksc.ip_str([ip_int, ip_int]) == "10.0.0.5, 10.0.0.5"
    assert ksc.ip_str("1.2.3.4") == "1.2.3.4"
    assert ksc.ip_str(None) == ""


def test_extract_pinfo_variants():
    assert ksc.extract_pinfo({"pInfo": {"KLHST_WKS_HOSTNAME": "PC"}}) == \
        {"KLHST_WKS_HOSTNAME": "PC"}
    assert ksc.extract_pinfo({"value": {"KLHST_WKS_HOSTNAME": "PC"}}) == \
        {"KLHST_WKS_HOSTNAME": "PC"}
    assert ksc.extract_pinfo({"KLHST_WKS_HOSTNAME": "PC"}) == \
        {"KLHST_WKS_HOSTNAME": "PC"}
    assert ksc.extract_pinfo("bad") == {}
    assert ksc.extract_pinfo({}) == {}


def test_load_settings_missing_and_bad(tmp_path):
    missing = tmp_path / "no.json"
    assert ksc.load_settings(missing) == {}
    bad = tmp_path / "bad.json"
    bad.write_text("not json", encoding="utf-8")
    assert ksc.load_settings(bad) == {}


def test_save_settings_writes_json(tmp_path):
    target = tmp_path / "settings.json"
    ksc.save_settings({"KSC_SERVER": "1.2.3.4"}, target)
    assert json.loads(target.read_text(encoding="utf-8"))["KSC_SERVER"] == "1.2.3.4"


def test_api_returns_none_on_http_error(monkeypatch):
    fake_resp = MagicMock()
    fake_resp.status_code = 500
    fake_resp.text = "err"
    monkeypatch.setattr(ksc.session, "post", lambda *a, **k: fake_resp)
    assert ksc.api("Some.Method") is None


def test_api_returns_none_on_exception(monkeypatch):
    def boom(*a, **k):
        raise ConnectionError("down")
    monkeypatch.setattr(ksc.session, "post", boom)
    assert ksc.api("Some.Method") is None


def test_login_fails_without_credentials(monkeypatch):
    monkeypatch.setattr(ksc, "KSC_USERNAME", "")
    monkeypatch.setattr(ksc, "KSC_PASSWORD", "")
    assert ksc.login() is False


def test_login_ok(monkeypatch):
    monkeypatch.setattr(ksc, "KSC_USERNAME", "u")
    monkeypatch.setattr(ksc, "KSC_PASSWORD", "p")
    fake = MagicMock()
    fake.status_code = 200
    monkeypatch.setattr(ksc.session, "post", lambda *a, **k: fake)
    assert ksc.login() is True


def test_get_hosts_empty_on_bad_response(monkeypatch):
    monkeypatch.setattr(ksc, "api", lambda *a, **k: {"nope": 1})
    assert ksc.get_hosts() == []


def test_get_hosts_pagination_and_release(monkeypatch):
    calls = []

    def fake_api(method, params=None, timeout=30):
        calls.append(method)
        if method == "HostGroup.FindHosts":
            return {"strAccessor": "ACC"}
        if method == "ChunkAccessor.GetItemsChunk":
            return {"pChunk": {"KLCSP_ITERATOR_ARRAY": [
                {"pInfo": {"KLHST_WKS_HOSTNAME": "PC1"}}]}}
        if method == "ChunkAccessor.Release":
            return {}
        return None

    monkeypatch.setattr(ksc, "api", fake_api)
    hosts = ksc.get_hosts()
    assert len(hosts) == 1
    assert hosts[0]["pInfo"]["KLHST_WKS_HOSTNAME"] == "PC1"
    assert "ChunkAccessor.Release" in calls


def test_get_inventory_parses_products_and_patches(monkeypatch):
    def fake_api(method, params=None, timeout=30):
        if "Products" in method:
            return {"PxgRetVal": {"GNRL_EA_PARAM_1": [
                {"value": {"DisplayName": "VLC", "DisplayVersion": "3.0",
                           "Publisher": "VideoLAN", "InstallDate": "2024"}},
                {"value": {"DisplayName": "", "DisplayVersion": "x"}},
            ]}}
        if "Patches" in method:
            return {"PxgRetVal": {"GNRL_EA_PARAM_1": [
                {"value": {"DisplayName": "KB1", "PatchID": "1", "Classification": "Sec"}},
                {"value": {"DisplayName": "", "PatchID": ""}},
            ]}}
        return None

    monkeypatch.setattr(ksc, "api", fake_api)
    pro, pat = ksc.get_inventory("PC1")
    assert pro == [{"name": "VLC", "version": "3.0",
                    "publisher": "VideoLAN", "install_date": "2024"}]
    assert pat == [{"name": "KB1", "patch_id": "1", "classification": "Sec"}]
    assert ksc.get_inventory("") == ([], [])


def test_output_path_avoids_out_out(tmp_path, monkeypatch):
    """Regression: -o out/x.json must not become out/out/x.json."""
    import argparse
    monkeypatch.setattr(ksc, "login", lambda: True)
    monkeypatch.setattr(ksc, "get_hosts", lambda: [
        {"pInfo": {"KLHST_WKS_HOSTNAME": "PC1", "KLHST_WKS_DN": "PC1"}}])
    monkeypatch.setattr(ksc, "get_inventory", lambda hid: ([], []))
    monkeypatch.setattr(ksc, "logout", lambda: None)
    # run main with relative out/ path inside tmp app dir
    monkeypatch.setattr(ksc, "get_app_dir", lambda: tmp_path)
    monkeypatch.setattr(ksc, "get_out_dir", lambda: tmp_path / "out")
    (tmp_path / "out").mkdir(exist_ok=True)
    rc = ksc.main(["--no-input", "--settings", str(tmp_path / "s.json"),
                   "-o", "out/custom.json"])
    assert rc == 0
    assert (tmp_path / "out" / "custom.json").exists()
    assert not (tmp_path / "out" / "out").exists()
