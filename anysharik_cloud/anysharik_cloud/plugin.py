# /// script
# requires-python = ">=3.9"
# dependencies = []
#
# [tool.orcaslicer.plugin]
# id = "anysharik_cloud"
# name = "AnySharik"
# description = "Anycubic Cloud printer control, printing and telemetry"
# author = "AnySharik"
# version = "0.3.26"
# ///
from __future__ import annotations

import base64
import hashlib
import http.client
import json
import os
import shlex
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import zipfile
from datetime import datetime
from pathlib import Path

import orca

from . import _remove_tree
from .cloud_api import CloudApi, CloudError
from .cloud_mqtt import MqttTelemetry

def _resolve_data_dir(root: Path = None) -> Path:
    """Return persistent plugin data dir outside __whl_extracted__ when running in OrcaSlicer."""
    base = root or Path(__file__).resolve().parent
    for parent in base.parents:
        if parent.name == "__whl_extracted__":
            return parent.parent
    return base


ROOT = Path(__file__).resolve().parent
DATA_DIR = _resolve_data_dir(ROOT)
STATE_FILE = DATA_DIR / "state.json"
LEGACY_STATE_FILE = ROOT / "state.json"
LOGIN_PROFILE_DIR = DATA_DIR / "login_profile"
AGENT_ID = "anysharik_cloud"
_agent = None


def _parse_state_file(path: Path):
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            return {
                "token": str(data.get("token") or ""),
                "email": str(data.get("email") or ""),
                "printer_id": int(data.get("printer_id") or 0),
            }
    except (OSError, ValueError, TypeError):
        pass
    return None


def load_state():
    state = _parse_state_file(STATE_FILE)
    if state is not None:
        return state
    if LEGACY_STATE_FILE != STATE_FILE:
        legacy = _parse_state_file(LEGACY_STATE_FILE)
        if legacy is not None:
            save_state(legacy)
            return legacy
    return {"token": "", "email": "", "printer_id": 0}


def save_state(state):
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(json.dumps(state), encoding="utf-8")


def _login_browser_command(browser: str, profile: Path, port: int = 19223) -> list[str]:
    """Build the browser launch command for Anycubic Cloud sign-in."""
    return [
        browser,
        "--app=https://cloud-universe.anycubic.com/",
        f"--user-data-dir={profile}",
        f"--remote-debugging-port={port}",
        "--no-first-run",
        "--no-default-browser-check",
        "--disable-extensions",
    ]


def _login_browser():
    names = ("msedge.exe", "chrome.exe") if sys.platform == "win32" else ("microsoft-edge", "google-chrome", "chromium", "chromium-browser")
    browser = next((shutil.which(name) for name in names if shutil.which(name)), None)
    if not browser and sys.platform == "win32":
        roots = (os.environ.get("PROGRAMFILES(X86)", ""), os.environ.get("PROGRAMFILES", ""))
        browser = next((str(path) for root in roots for path in (Path(root) / "Microsoft/Edge/Application/msedge.exe", Path(root) / "Google/Chrome/Application/chrome.exe") if root and path.is_file()), None)
    if not browser:
        raise CloudError("Install Microsoft Edge or Google Chrome to sign in")
    port = 19223
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=0.2):
            raise CloudError("Local sign-in port is already in use; close other login windows and retry")
    except OSError:
        pass
    profile = LOGIN_PROFILE_DIR
    _remove_tree(profile, retries=3, delay=0.1)
    profile.mkdir(parents=True, exist_ok=True)
    process = subprocess.Popen(_login_browser_command(browser, profile, port))
    deadline = time.monotonic() + 300
    try:
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise CloudError("Login window was closed before signing in")
            try:
                conn = http.client.HTTPConnection("127.0.0.1", port, timeout=1)
                conn.request("GET", "/json/list")
                response = conn.getresponse()
                targets = json.loads(response.read() or b"[]")
                conn.close()
                for target in targets:
                    ws = target.get("webSocketDebuggerUrl", "")
                    if target.get("type") != "page" or not ws:
                        continue
                    parsed = urllib.parse.urlparse(ws)
                    key = base64.b64encode(os.urandom(16)).decode()
                    path = parsed.path + ("?" + parsed.query if parsed.query else "")
                    with socket.create_connection((parsed.hostname, parsed.port), timeout=2) as sock:
                        sock.settimeout(2)
                        sock.sendall((f"GET {path} HTTP/1.1\r\nHost: {parsed.hostname}:{parsed.port}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n").encode())
                        headers = b""
                        while b"\r\n\r\n" not in headers:
                            headers += sock.recv(4096)
                        if b" 101 " not in headers.split(b"\r\n", 1)[0]:
                            continue
                        expected = base64.b64encode(hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest())
                        if expected.lower() not in headers.lower():
                            continue
                        expression = "window.localStorage ? (window.localStorage.getItem('XX-Token') || '') : ''"
                        message = json.dumps({"id": 1, "method": "Runtime.evaluate", "params": {"expression": expression, "returnByValue": True}}).encode()
                        mask = os.urandom(4)
                        length = len(message)
                        head = bytes([0x81, 0x80 | length]) if length < 126 else bytes([0x81, 0xfe]) + struct.pack("!H", length)
                        sock.sendall(head + mask + bytes(b ^ mask[i % 4] for i, b in enumerate(message)))
                        while True:
                            first, second = sock.recv(2)
                            size = second & 127
                            if size == 126:
                                size = struct.unpack("!H", sock.recv(2))[0]
                            elif size == 127:
                                size = struct.unpack("!Q", sock.recv(8))[0]
                            frame = bytearray()
                            while len(frame) < size:
                                frame.extend(sock.recv(size - len(frame)))
                            if first & 15 != 1:
                                continue
                            try:
                                result = json.loads(frame)
                                if result.get("id") == 1:
                                    token = result.get("result", {}).get("result", {}).get("value", "")
                                    if token:
                                        return token.strip()
                                    break
                            except ValueError:
                                break
            except (OSError, ValueError, KeyError, TypeError):
                pass
            time.sleep(.5)
        raise CloudError("Anycubic Cloud sign-in timed out")
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
        _remove_tree(profile)


def _login_worker(page):
    try:
        token = _login_browser()
        profile = CloudApi(token).profile()
        email = str(profile.get("user_email") or profile.get("email") or profile.get("user_nickname") or "")
        state = load_state()
        state.update(token=token, email=email)
        save_state(state)
        if _agent:
            _agent.refresh_page(page, banner="Connected to Anycubic Cloud.")
    except Exception as exc:
        page.post_message({"auth": False, "error": str(exc), "message": str(exc)})


def extract_gcode(value, plate=0):
    src = Path(value)
    if src.suffix.lower() != ".3mf":
        return src, None
    with zipfile.ZipFile(src) as z:
        names = [n for n in z.namelist() if n.lower().endswith(".gcode")]
        if not names:
            raise CloudError("The 3MF file contains no G-code")
        selected = next((n for n in names if f"plate_{plate}" in n.lower()), names[0])
        tmp = tempfile.NamedTemporaryFile(prefix="anysharik-", suffix=".gcode", delete=False)
        try:
            tmp.write(z.read(selected))
        finally:
            tmp.close()
    path = Path(tmp.name)
    return path, path


def _pick_dict(payload, *keys):
    if not isinstance(payload, dict):
        return {}
    for key in keys:
        nested = payload.get(key)
        if isinstance(nested, dict):
            return nested
    return payload


def _pick_value(sources, *keys):
    for src in sources:
        if not isinstance(src, dict):
            continue
        for key in keys:
            val = src.get(key)
            if val not in (None, ""):
                return val
    return None


def _to_number(value):
    if value is None or isinstance(value, bool):
        return None
    try:
        num = float(value)
    except (TypeError, ValueError):
        return None
    return int(num) if num.is_integer() else round(num, 1)


def _format_firmware(value) -> str:
    if isinstance(value, dict):
        value = value.get("firmware_version") or value.get("target_version") or value.get("version") or ""
    text = str(value).strip() if value not in (None, "") else ""
    return text or "-"


def _format_bind_time(value) -> str:
    if value in (None, "", 0, "0"):
        return "-"
    if isinstance(value, (int, float)) or (isinstance(value, str) and value.strip().isdigit()):
        ts = float(value)
        if ts > 1e12:
            ts /= 1000.0
        try:
            return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
        except (OSError, OverflowError, ValueError):
            pass
    return str(value)


def _extract_device_info(printer, raw_status=None):
    """Extract Cloud device metadata (CN, firmware, MAC, ACE, stats) from API payloads."""
    status_data = _pick_dict(raw_status, "data") if isinstance(raw_status, dict) else {}
    base = _pick_dict(raw_status, "base") if isinstance(raw_status, dict) else {}
    sources = (base, status_data, raw_status if isinstance(raw_status, dict) else {}, printer if isinstance(printer, dict) else {})
    cn = _pick_value(sources, "description", "cn", "sn", "device_sn", "key", "printer_key") or printer.get("id")
    firmware = _pick_value(sources, "firmware_version", "version", "fw_version")
    mac = _pick_value(sources, "machine_mac", "mac", "mac_address")
    bind_time = _pick_value(sources, "bind_time", "create_time")
    print_time = _pick_value(sources, "print_totaltime", "print_time")
    filament = _pick_value(sources, "material_used", "filament")
    print_count = _pick_value((printer if isinstance(printer, dict) else {}, base, status_data), "print_count")
    ace_ver_raw = _pick_value(sources, "multi_color_box_version")
    ace_raw = _pick_value(sources, "multi_color_box", "ace", "ams")
    ace_item = ace_ver_raw[0] if isinstance(ace_ver_raw, list) and ace_ver_raw else (
        ace_raw[0] if isinstance(ace_raw, list) and ace_raw else (ace_raw if isinstance(ace_raw, dict) else {})
    )
    ace_fw = _format_firmware(ace_item.get("firmware_version") or ace_item.get("version") or "")
    ace_name = ace_item.get("box_name") or ace_item.get("name") or "ACE Pro"
    online = printer.get("online")
    if online is None:
        online = int(printer.get("device_status") or 0) == 1
    return {
        "id": printer.get("id"),
        "name": printer.get("name"),
        "model": printer.get("model"),
        "online": bool(online),
        "cn": str(cn) if cn not in (None, "") else "-",
        "firmware": _format_firmware(firmware),
        "mac": str(mac) if mac not in (None, "") else "-",
        "bind_time": _format_bind_time(bind_time),
        "print_time": str(print_time).replace("hour", "h ").replace("min", "m") if print_time not in (None, "") else "-",
        "filament": str(filament) if filament not in (None, "") else "-",
        "print_count": str(print_count) if print_count not in (None, "") else "-",
        "ace_name": str(ace_name),
        "ace_firmware": "" if ace_fw == "-" else ace_fw,
        "has_ace": bool(ace_ver_raw or ace_raw),
    }


def _rgb_to_hex(rgb) -> str:
    if isinstance(rgb, list) and len(rgb) >= 3:
        return f"#{int(rgb[0]):02X}{int(rgb[1]):02X}{int(rgb[2]):02X}"
    return "#28302A"


def _extract_ace_status(sources):
    ext_raw = _pick_value(sources, "external_shelves")
    ext_spool = None
    if isinstance(ext_raw, dict):
        ext_type = str(ext_raw.get("type") or "").strip()
        ext_spool = {
            "type": ext_type or "Empty",
            "color": "" if not ext_type else _rgb_to_hex(ext_raw.get("color")),
        }

    ace_raw = _pick_value(sources, "multi_color_box")
    ace = ace_raw[0] if isinstance(ace_raw, list) and ace_raw else (ace_raw if isinstance(ace_raw, dict) else None)
    if not isinstance(ace, dict):
        return None, None, ext_spool
    slots = []
    for item in (ace.get("slots") or [])[:4]:
        if not isinstance(item, dict):
            continue
        empty = int(item.get("status") or 0) == 4 or not item.get("type")
        slots.append({"type": "Empty" if empty else str(item.get("type")), "color": "" if empty else _rgb_to_hex(item.get("color"))})
    dry_raw = ace.get("drying_status") if isinstance(ace.get("drying_status"), dict) else None
    ace_temp = _to_number(ace.get("temp") if ace.get("temp") is not None else ace.get("curr_temp"))
    drying = None
    if dry_raw is not None or ace_temp is not None:
        dry_obj = dry_raw or {}
        remain = int(dry_obj.get("remain_time") or 0)
        drying = {
            "on": int(dry_obj.get("status") or 0) == 1,
            "cur": ace_temp,
            "target": _to_number(dry_obj.get("target_temp")) or 55,
            "hours": round(remain / 60, 1) if remain else round(int(dry_obj.get("duration") or 480) / 60, 1),
            "remain_min": remain,
        }
    return (slots or None), drying, ext_spool


def _normalize_status(payload):
    if not isinstance(payload, dict):
        return {"state": "Idle", "progress": 0, "file": "No active print", "nozzle": None, "bed": None}

    inner = _pick_dict(payload, "data", "status")
    project = inner.get("project") if isinstance(inner.get("project"), dict) else (
        payload.get("project") if isinstance(payload.get("project"), dict) else {}
    )
    parameter = _pick_dict(inner, "parameter")
    if parameter is inner:
        parameter = _pick_dict(payload, "parameter")
    ace_raw = _pick_value((inner, payload), "multi_color_box")
    ace_dict = ace_raw[0] if isinstance(ace_raw, list) and ace_raw else (ace_raw if isinstance(ace_raw, dict) else {})
    sources = (inner, parameter, project, ace_dict, payload)

    raw_state = _pick_value(sources, "state", "print_status", "status_text", "device_status", "msg", "status")
    state_map = {"0": "Idle", "1": "Ready", "2": "Offline"}
    if raw_state is None:
        state = "Idle"
    else:
        state_text = str(raw_state).strip()
        state = state_map.get(state_text, state_text) or "Idle"

    raw_progress = _pick_value(sources, "progress", "percent", "print_progress")
    progress_num = _to_number(raw_progress)
    progress = max(0, min(100, int(round(progress_num)))) if progress_num is not None else 0
    if state == "Ready" and progress > 0:
        state = "Printing"

    raw_file = _pick_value(sources, "file", "filename", "gcode_name", "project_name")
    if raw_file is None and project:
        raw_file = project.get("name")
    file_name = str(raw_file) if raw_file not in (None, "") else "No active print"

    nozzle = _to_number(_pick_value(sources, "nozzle", "nozzle_temp", "curr_nozzle_temp", "temp_nozzle"))
    nozzle_target = _to_number(_pick_value(sources, "nozzle_target", "target_nozzle_temp"))
    bed = _to_number(_pick_value(sources, "bed", "bed_temp", "hotbed_temp", "curr_hotbed_temp"))
    bed_target = _to_number(_pick_value(sources, "bed_target", "target_hotbed_temp", "target_bed_temp"))
    slots, drying, ext_spool = _extract_ace_status((inner, payload))

    result = {
        "state": state,
        "progress": progress,
        "file": file_name,
        "nozzle": nozzle,
        "nozzle_target": nozzle_target,
        "bed": bed,
        "bed_target": bed_target,
    }
    if slots is not None:
        result["slots"] = slots
    if drying is not None:
        result["drying"] = drying
    if ext_spool is not None:
        result["external_spool"] = ext_spool
    return result


PAGE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
:root {
  color-scheme: dark;
  --bg: var(--orca-bg, #141517);
  --fg: var(--orca-fg, #e9edf2);
  --muted: var(--orca-muted, #8e96a3);
  --accent: var(--orca-accent, #1677ff);
  --accent-fg: var(--orca-accent-fg, #ffffff);
  --border: var(--orca-border, rgba(255, 255, 255, 0.08));
  --font: var(--orca-font, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif);
  --surface: color-mix(in srgb, var(--bg) 93%, #ffffff);
  --surface-2: color-mix(in srgb, var(--bg) 86%, #ffffff);
  --accent-soft: color-mix(in srgb, var(--accent) 14%, transparent);
  --ok: #26b864;
  --warn: #e0912c;
  --danger: #e05252;
  --danger-soft: color-mix(in srgb, #e05252 15%, transparent);
}
* {
  box-sizing: border-box;
  scrollbar-width: thin;
  scrollbar-color: rgba(255, 255, 255, 0.18) transparent;
}
*::-webkit-scrollbar {
  width: 6px;
  height: 6px;
}
*::-webkit-scrollbar-track {
  background: transparent;
}
*::-webkit-scrollbar-thumb {
  background: rgba(255, 255, 255, 0.18);
  border-radius: 999px;
}
*::-webkit-scrollbar-thumb:hover {
  background: rgba(255, 255, 255, 0.3);
}
body {
  margin: 0;
  background: var(--bg);
  color: var(--fg);
  font: 13px/1.45 var(--font);
}
button, input {
  font: inherit;
  color: inherit;
}
button {
  border: 1px solid var(--border);
  background: var(--surface-2);
  border-radius: 7px;
  padding: 7px 12px;
  cursor: pointer;
  transition: border-color .15s ease, background-color .15s ease, opacity .15s ease;
}
button:hover:not(:disabled) {
  border-color: var(--accent);
  background: var(--accent-soft);
}
button:disabled {
  opacity: .45;
  cursor: default;
}
button.primary {
  background: var(--accent);
  border-color: var(--accent);
  color: var(--accent-fg);
  font-weight: 600;
}
button.primary:hover:not(:disabled) {
  filter: brightness(1.08);
  background: var(--accent);
}
button.danger {
  color: var(--danger);
  border-color: color-mix(in srgb, var(--danger) 40%, var(--border));
}
button.danger:hover:not(:disabled) {
  background: var(--danger-soft);
  border-color: var(--danger);
}
button.danger.armed {
  background: var(--danger);
  border-color: var(--danger);
  color: #fff;
  font-weight: 600;
}

.layout {
  display: grid;
  grid-template-columns: 268px minmax(0, 1fr);
  min-height: 100vh;
}
.sidebar {
  border-right: 1px solid var(--border);
  background: var(--surface);
  padding: 18px 14px;
  display: flex;
  flex-direction: column;
  gap: 14px;
}
.brand {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 2px 4px 12px;
  border-bottom: 1px solid var(--border);
}
.brand-left {
  display: flex;
  align-items: center;
  gap: 10px;
}
.brand-mark {
  width: 28px;
  height: 28px;
  border-radius: 8px;
  background: var(--accent);
  color: var(--accent-fg);
  display: grid;
  place-items: center;
  font-weight: 700;
  font-size: 14px;
  box-shadow: 0 2px 8px color-mix(in srgb, var(--accent) 30%, transparent);
}
.brand-name {
  font-weight: 700;
  font-size: 14px;
  letter-spacing: -.01em;
}
.brand-sub {
  font-size: 11px;
  color: var(--muted);
}
.icon-btn {
  width: 30px;
  height: 30px;
  padding: 0;
  display: inline-grid;
  place-items: center;
  border-radius: 7px;
  background: var(--surface-2);
}
.section-label {
  font-size: 11px;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: .07em;
  color: var(--muted);
  padding: 2px 6px 0;
}
.printer-list {
  display: grid;
  gap: 6px;
  overflow-y: auto;
}
.printer-item {
  width: 100%;
  text-align: left;
  padding: 10px 11px;
  border-radius: 8px;
  background: transparent;
  border: 1px solid transparent;
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 10px;
}
.printer-item:hover {
  background: var(--surface-2);
  border-color: var(--border);
}
.printer-item.selected {
  background: color-mix(in srgb, var(--accent) 12%, var(--surface-2));
  border-color: var(--accent);
}
.printer-item.selected.is-offline {
  background: color-mix(in srgb, var(--danger) 10%, var(--surface-2));
  border-color: color-mix(in srgb, var(--danger) 55%, var(--border));
}
.printer-left {
  display: flex;
  align-items: center;
  gap: 10px;
  min-width: 0;
}
.printer-icon {
  width: 28px;
  height: 28px;
  border-radius: 7px;
  background: var(--surface-2);
  border: 1px solid var(--border);
  display: grid;
  place-items: center;
  color: var(--muted);
  flex: none;
}
.printer-item.selected .printer-icon {
  color: var(--accent);
  border-color: color-mix(in srgb, var(--accent) 45%, var(--border));
}
.printer-meta {
  min-width: 0;
}
.printer-name {
  font-weight: 600;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}
.printer-model {
  font-size: 11px;
  color: var(--muted);
  margin-top: 2px;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}
.pill {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  font-size: 11px;
  color: var(--muted);
  white-space: nowrap;
}
.badge {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  padding: 3px 9px;
  border-radius: 999px;
  font-size: 11px;
  font-weight: 600;
  background: var(--surface-2);
  border: 1px solid var(--border);
  color: var(--fg);
}
.badge.ok {
  border-color: color-mix(in srgb, var(--ok) 45%, var(--border));
  color: var(--ok);
}
.badge.warn {
  border-color: color-mix(in srgb, var(--warn) 45%, var(--border));
  color: var(--warn);
}
.badge.danger {
  border-color: color-mix(in srgb, var(--danger) 55%, var(--border));
  background: var(--danger-soft);
  color: #ff8a8a;
}
.dot {
  width: 7px;
  height: 7px;
  border-radius: 50%;
  background: var(--muted);
  flex: none;
}
.dot.online { background: var(--ok); box-shadow: 0 0 0 3px color-mix(in srgb, var(--ok) 20%, transparent); }
.dot.warn { background: var(--warn); }
.dot.offline { background: var(--danger); }

.sidebar-foot {
  margin-top: auto;
  padding-top: 12px;
  border-top: 1px solid var(--border);
  display: grid;
  gap: 8px;
}
.account-btn {
  width: 100%;
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
  padding: 9px 10px;
  text-align: left;
}
.account-email {
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  font-size: 12px;
}

.main {
  padding: 24px 28px;
  width: 100%;
  display: flex;
  flex-direction: column;
  gap: 16px;
}
.topbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  padding-bottom: 14px;
  border-bottom: 1px solid var(--border);
}
.title-wrap h1 {
  margin: 0;
  font-size: 22px;
  font-weight: 700;
  letter-spacing: -.015em;
}
.subtitle {
  margin-top: 4px;
  color: var(--muted);
  font-size: 12px;
  display: flex;
  align-items: center;
  gap: 10px;
  flex-wrap: wrap;
}
.top-actions {
  display: flex;
  gap: 8px;
  flex-wrap: wrap;
}
.btn-inline {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 6px;
}

.banner {
  position: fixed;
  left: 50%;
  bottom: 24px;
  transform: translateX(-50%);
  z-index: 1500;
  display: none;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  width: max-content;
  max-width: min(520px, calc(100vw - 32px));
  padding: 10px 15px;
  border-radius: 10px;
  border: 1px solid var(--border);
  background: color-mix(in srgb, var(--surface) 96%, #ffffff);
  box-shadow: 0 12px 30px rgba(0, 0, 0, .48);
  font-size: 12px;
}
.banner.visible { display: flex; }
.banner.error {
  border-color: color-mix(in srgb, var(--danger) 55%, var(--border));
  background: color-mix(in srgb, var(--danger) 18%, var(--surface));
  color: var(--fg);
}
.banner.ok {
  border-color: color-mix(in srgb, var(--ok) 45%, var(--border));
  background: color-mix(in srgb, var(--ok) 14%, var(--surface));
}
.banner-close {
  border: 0;
  background: transparent;
  padding: 2px 6px;
  color: var(--muted);
  font-size: 14px;
  line-height: 1;
}
.banner-close:hover:not(:disabled) {
  background: transparent;
  color: var(--fg);
}

.grid {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 16px;
  align-items: stretch;
}
.card {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 12px;
  padding: 18px 20px;
  display: flex;
  flex-direction: column;
  min-width: 0;
  overflow: hidden;
}
.card-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
  margin-bottom: 16px;
}
.card-title {
  font-size: 14px;
  font-weight: 700;
  letter-spacing: .01em;
}
.card-job, .card-temps, .card-info { grid-column: span 1; }

.job-body {
  display: flex;
  align-items: center;
  gap: 22px;
  margin-bottom: 18px;
  flex: 1;
}
.ring-wrap {
  position: relative;
  width: 96px;
  height: 96px;
  flex: none;
  display: grid;
  place-items: center;
}
.ring {
  width: 96px;
  height: 96px;
  border-radius: 50%;
  background: conic-gradient(var(--accent) calc(var(--p, 0) * 1%), color-mix(in srgb, var(--border) 75%, transparent) 0);
  display: grid;
  place-items: center;
}
.ring::after {
  content: "";
  width: 76px;
  height: 76px;
  border-radius: 50%;
  background: var(--surface);
}
.ring-text {
  position: absolute;
  font-size: 18px;
  font-weight: 700;
}
.job-meta {
  min-width: 0;
  flex: 1;
  display: grid;
  gap: 7px;
  justify-items: start;
}
.job-state {
  font-size: 20px;
  font-weight: 700;
  line-height: 1.2;
}
.job-file {
  color: var(--muted);
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
  max-width: 100%;
  font-size: 12px;
}
.controls {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 8px;
}
.controls button {
  min-width: 0;
  padding: 8px 10px;
  font-weight: 500;
}

.temp-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 12px;
  flex: 1;
}
.metric-box {
  background: var(--surface-2);
  border: 1px solid var(--border);
  border-radius: 10px;
  padding: 14px;
  display: flex;
  flex-direction: column;
  justify-content: space-between;
  gap: 8px;
}
.metric-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
}
.metric-label {
  font-size: 11px;
  font-weight: 600;
  color: var(--muted);
  display: inline-flex;
  align-items: center;
  gap: 5px;
  white-space: nowrap;
  min-width: 0;
  max-width: 100%;
  overflow: hidden;
  text-overflow: ellipsis;
}
.metric-label svg {
  flex: none;
}
.card.is-offline .ace-tray,
.card.is-offline .camera-box {
  opacity: .55;
}
.metric-val-row {
  display: flex;
  align-items: baseline;
  gap: 3px;
  flex-wrap: nowrap;
  min-width: 0;
}
.metric-val {
  font-size: 16px;
  font-weight: 700;
  letter-spacing: -.02em;
  white-space: nowrap;
}
.metric-sub {
  font-size: 11px;
  color: var(--muted);
  white-space: nowrap;
}
.temp-bar {
  height: 4px;
  border-radius: 999px;
  background: color-mix(in srgb, var(--border) 60%, transparent);
  overflow: hidden;
}
.temp-bar > span {
  display: block;
  height: 100%;
  width: 0%;
  border-radius: 999px;
  background: var(--accent);
  transition: width .25s ease;
}

.device-card-body {
  display: flex;
  align-items: center;
  gap: 14px;
  flex: 1;
  min-width: 0;
}
.device-preview {
  width: 82px;
  height: 92px;
  background: transparent;
  border: 0;
  display: grid;
  place-items: center;
  color: var(--muted);
  flex: none;
}
.device-details {
  min-width: 0;
  flex: 1;
  display: grid;
  gap: 8px;
}
.device-title-row {
  display: flex;
  flex-direction: column;
  align-items: flex-start;
  gap: 5px;
  min-width: 0;
}
.device-title-row .badge {
  border-radius: 5px;
  border: 0;
  padding: 2px 8px;
}
.device-title-row .badge .dot {
  display: none;
}
.device-name {
  font-size: 15px;
  font-weight: 700;
  max-width: 100%;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}
.device-kv {
  display: grid;
  grid-template-columns: auto minmax(0, 1fr);
  gap: 4px 14px;
  align-items: center;
  min-width: 0;
  font-size: 12px;
}
.device-kv .k {
  color: var(--muted);
  white-space: nowrap;
}
.device-kv .v {
  font-weight: 600;
  min-width: 0;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}
.card-info {
  position: relative;
  overflow: visible;
}
.more-btn {
  border: 0;
  background: transparent;
  width: 28px;
  height: 28px;
  padding: 0;
  border-radius: 6px;
  color: var(--muted);
  display: inline-grid;
  place-items: center;
}
.more-btn:hover:not(:disabled) {
  border: 0;
  background: var(--surface-2);
  color: var(--fg);
}
.device-menu {
  position: absolute;
  top: 44px;
  right: 16px;
  min-width: 176px;
  background: color-mix(in srgb, var(--surface) 96%, #ffffff);
  border: 1px solid var(--border);
  border-radius: 10px;
  padding: 6px;
  box-shadow: 0 12px 28px rgba(0, 0, 0, .45);
  display: none;
  z-index: 30;
}
.device-menu.open {
  display: grid;
  gap: 2px;
}
.device-menu button {
  width: 100%;
  text-align: left;
  border: 0;
  background: transparent;
  padding: 7px 10px;
  border-radius: 7px;
  font-size: 12px;
}
.device-menu button:hover:not(:disabled) {
  background: var(--surface-2);
}
.device-menu hr {
  border: 0;
  border-top: 1px solid var(--border);
  margin: 4px 2px;
}
.device-dots {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 6px;
  margin-top: 8px;
}
.device-dot-btn {
  width: 6px;
  height: 6px;
  padding: 0;
  border: 0;
  border-radius: 50%;
  background: var(--border);
}
.device-dot-btn.active {
  background: var(--fg);
}
.device-slide-nav {
  width: 26px;
  height: 26px;
  padding: 0;
  border-radius: 50%;
  border: 0;
  background: var(--surface-2);
  color: var(--muted);
  display: inline-grid;
  place-items: center;
  flex: none;
}
.copy-btn {
  border: 0;
  background: transparent;
  padding: 2px 4px;
  color: var(--muted);
  display: inline-flex;
  align-items: center;
  vertical-align: middle;
}
.copy-btn:hover:not(:disabled) {
  border: 0;
  background: var(--surface-2);
  color: var(--fg);
}
.modal.wide {
  max-width: 680px;
}
.modal-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 14px;
}
.modal-head h2 {
  margin: 0;
}
.details-grid {
  display: grid;
  grid-template-columns: 220px minmax(0, 1fr);
  gap: 20px;
  align-items: start;
}
.details-stats {
  background: var(--surface-2);
  border: 1px solid var(--border);
  border-radius: 10px;
  padding: 12px 14px;
  display: grid;
  gap: 8px;
  font-size: 12px;
}
.details-stats .stat-row {
  display: flex;
  justify-content: space-between;
  gap: 8px;
}
.details-stats .k { color: var(--muted); }
.details-stats .v { font-weight: 600; }
.details-kv {
  display: grid;
  grid-template-columns: 120px minmax(0, 1fr);
  gap: 12px 14px;
  align-items: center;
  font-size: 13px;
}
.details-kv .k { color: var(--muted); }
.details-kv .v { font-weight: 600; word-break: break-all; }
.fw-card {
  background: var(--surface-2);
  border: 1px solid var(--border);
  border-radius: 10px;
  padding: 14px 16px;
  display: flex;
  align-items: center;
  gap: 16px;
  margin-bottom: 12px;
}
@media (max-width: 680px) {
  .details-grid { grid-template-columns: 1fr; }
}

.empty-box {
  border: 1px dashed var(--border);
  border-radius: 8px;
  padding: 20px 12px;
  text-align: center;
  color: var(--muted);
  font-size: 12px;
}

.modal-backdrop {
  position: fixed;
  inset: 0;
  background: rgba(0, 0, 0, 0.55);
  display: none;
  place-items: center;
  padding: 16px;
  z-index: 20;
}
.modal-backdrop.open { display: grid; }
.modal {
  width: 100%;
  max-width: 400px;
  background: var(--bg);
  border: 1px solid var(--border);
  border-radius: 10px;
  padding: 18px 20px;
}
.modal h2 {
  margin: 0 0 6px;
  font-size: 16px;
}
.modal p {
  margin: 0 0 14px;
  color: var(--muted);
  font-size: 12px;
}
.field {
  display: grid;
  gap: 5px;
  margin-bottom: 12px;
}
.field label {
  font-size: 12px;
  color: var(--muted);
}
.field input {
  width: 100%;
  padding: 8px 10px;
  border-radius: 6px;
  border: 1px solid var(--border);
  background: var(--surface);
  outline: none;
}
.field input:focus {
  border-color: var(--accent);
}
.modal-actions {
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 8px;
  margin-top: 14px;
}
.modal-right {
  display: flex;
  gap: 8px;
}

@media (max-width: 1180px) {
  .grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .card-info { grid-column: span 1; }
}
@media (max-width: 860px) {
  .layout { grid-template-columns: 1fr; }
  .sidebar { border-right: 0; border-bottom: 1px solid var(--border); }
  .grid { grid-template-columns: 1fr; }
  .card-job, .card-temps, .card-info { grid-column: span 1; }
}
.wb-tabs {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
  padding-bottom: 10px;
  border-bottom: 1px solid var(--border);
}
.wb-tab {
  font-size: 12px;
  font-weight: 600;
  color: var(--fg);
  padding: 4px 2px;
  border-bottom: 2px solid var(--accent);
}
.printer-status-tag {
  font-size: 11px;
  font-weight: 600;
  color: var(--ok);
  white-space: nowrap;
}
.printer-status-tag.offline { color: var(--danger); }
.main {
  padding: 16px 20px;
  width: 100%;
  display: flex;
  flex-direction: column;
  gap: 12px;
}
.control-grid {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 8px;
  flex: 1;
}
.control-tile {
  background: var(--surface-2);
  border: 1px solid var(--border);
  border-radius: 10px;
  padding: 9px 10px;
  display: flex;
  flex-direction: column;
  justify-content: space-between;
  gap: 6px;
  min-width: 0;
  overflow: hidden;
  cursor: pointer;
}
.control-tile:hover {
  border-color: color-mix(in srgb, var(--accent) 45%, var(--border));
}
.inline-val {
  cursor: text;
  border-radius: 5px;
  padding: 1px 3px;
  margin: -1px -3px;
}
.inline-val:hover {
  background: rgba(255, 255, 255, 0.06);
}
.inline-num-input {
  width: 64px;
  padding: 2px 6px;
  border-radius: 5px;
  border: 1px solid var(--accent);
  background: var(--bg);
  color: var(--fg);
  font-size: 14px;
  font-weight: 700;
  outline: none;
}
.ctrl-modal-grid {
  display: grid;
  grid-template-columns: 180px minmax(0, 1fr);
  gap: 20px;
  align-items: center;
}
.ctrl-rows {
  display: grid;
  gap: 10px;
}
.ctrl-row {
  display: grid;
  grid-template-columns: 120px minmax(0, 1fr);
  align-items: center;
  gap: 10px;
}
.ctrl-input-wrap {
  display: flex;
  align-items: center;
  background: var(--surface-2);
  border: 1px solid var(--border);
  border-radius: 7px;
  overflow: hidden;
}
.ctrl-input-wrap:focus-within {
  border-color: var(--accent);
}
.ctrl-input-wrap input {
  width: 100%;
  border: 0;
  background: transparent;
  padding: 7px 10px;
  outline: none;
  min-width: 0;
}
.ctrl-hint {
  font-size: 11px;
  color: var(--muted);
  white-space: nowrap;
  padding-right: 8px;
}
.ctrl-unit {
  padding: 7px 10px;
  background: rgba(255, 255, 255, 0.04);
  border-left: 1px solid var(--border);
  font-size: 12px;
  color: var(--muted);
}
@media (max-width: 680px) {
  .ctrl-modal-grid { grid-template-columns: 1fr; }
}
.control-tile .metric-val { font-size: 15px; }
.control-tile .metric-sub { font-size: 11px; }
.camera-box {
  position: relative;
  flex: 1;
  min-height: 210px;
  border-radius: 10px;
  background: #07080a;
  border: 1px solid var(--border);
  display: grid;
  place-items: center;
  overflow: hidden;
}
.camera-empty {
  color: var(--muted);
  font-size: 12px;
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 8px;
}
.camera-play {
  position: absolute;
  left: 12px;
  bottom: 12px;
  width: 34px;
  height: 34px;
  border-radius: 50%;
  padding: 0;
  background: var(--accent);
  border-color: var(--accent);
  color: var(--accent-fg);
  display: grid;
  place-items: center;
}
.camera-fs {
  position: absolute;
  right: 12px;
  bottom: 12px;
  width: 30px;
  height: 30px;
  padding: 0;
  border-radius: 8px;
  background: rgba(255,255,255,0.06);
  display: grid;
  place-items: center;
}
.seg-tabs {
  display: flex;
  gap: 6px;
  padding-left: 10px;
}
.seg-tab {
  border: 0;
  background: transparent;
  padding: 7px 14px;
  font-size: 12px;
  font-weight: 600;
  color: var(--muted);
  border-radius: 8px 8px 0 0;
}
.seg-tab.active {
  color: var(--fg);
  background: var(--surface-2);
}
.seg-tab.locked {
  opacity: .55;
  cursor: not-allowed;
}
.ace-tray {
  background: var(--surface-2);
  border: 0;
  border-radius: 10px;
  padding: 16px 12px 12px;
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 10px;
  margin-bottom: 12px;
}
.spool-slot {
  border: 0;
  background: transparent;
  padding: 4px 2px;
  border-radius: 8px;
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 7px;
}
.spool-slot:hover:not(:disabled) {
  background: rgba(255,255,255,0.04);
}
.spool-drum {
  width: 44px;
  height: 58px;
  border-radius: 8px;
  background:
    linear-gradient(90deg, rgba(130,136,146,.85) 0 18%, transparent 18% 82%, rgba(130,136,146,.85) 82% 100%),
    linear-gradient(180deg, rgba(255,255,255,.16), rgba(0,0,0,.22)),
    var(--spool-color, #2f3532);
  border: 1px solid rgba(255,255,255,0.12);
}
.spool-drum.empty {
  background:
    linear-gradient(90deg, rgba(120,126,136,.6) 0 18%, transparent 18% 82%, rgba(120,126,136,.6) 82% 100%),
    linear-gradient(180deg, transparent 0 28%, rgba(160,166,176,.35) 28% 72%, transparent 72% 100%);
  border-color: transparent;
  opacity: .55;
}
.spool-type {
  font-size: 11px;
  color: var(--fg);
}
.spool-num {
  width: 16px;
  height: 16px;
  border-radius: 50%;
  background: rgba(255,255,255,0.06);
  font-size: 10px;
  color: var(--muted);
  display: grid;
  place-items: center;
}
.drying-sep {
  border-top: 1px dashed var(--border);
  padding-top: 10px;
  display: grid;
  gap: 8px;
}
.drying-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  font-size: 12px;
  color: var(--fg);
}
.dry-left {
  display: inline-flex;
  align-items: center;
  gap: 8px;
}
.dry-chip {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  padding: 2px 8px;
  border-radius: 999px;
  background: rgba(224, 145, 44, 0.16);
  color: #f09537;
  font-size: 11px;
  font-weight: 600;
}
.switch {
  width: 36px;
  height: 20px;
  border-radius: 999px;
  border: 0;
  padding: 2px;
  background: rgba(255,255,255,0.16);
  display: inline-flex;
  align-items: center;
  transition: background-color .15s ease;
}
.switch.on {
  background: var(--accent);
}
.switch-knob {
  width: 16px;
  height: 16px;
  border-radius: 50%;
  background: #fff;
  transition: transform .15s ease;
}
.switch.on .switch-knob {
  transform: translateX(16px);
}
.dry-summary {
  width: 100%;
  border: 0;
  background: var(--surface-2);
  border-radius: 8px;
  padding: 9px 12px;
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 10px;
  text-align: left;
  font-size: 12px;
}
.mat-modal-grid {
  display: grid;
  grid-template-columns: 180px minmax(0, 1fr);
  gap: 20px;
  align-items: start;
}
.swatch-grid {
  display: grid;
  grid-template-columns: repeat(7, 28px);
  gap: 10px;
  margin-top: 10px;
}
.swatch {
  width: 28px;
  height: 28px;
  border-radius: 50%;
  padding: 0;
  border: 2px solid rgba(255,255,255,0.18);
}
.swatch.active {
  border-color: var(--accent);
  box-shadow: 0 0 0 2px var(--bg);
}
.preset-grid {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  margin: 10px 0 14px;
}
.preset-chip {
  border: 0;
  border-radius: 999px;
  padding: 6px 14px;
  font-size: 12px;
  background: var(--surface-2);
  color: var(--muted);
}
.preset-chip.active {
  background: color-mix(in srgb, var(--accent) 22%, var(--surface-2));
  color: #5ca2ff;
  font-weight: 600;
}
@media (max-width: 680px) {
  .mat-modal-grid { grid-template-columns: 1fr; }
}
.select-wrap {
  position: relative;
}
.select-trigger {
  width: 100%;
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 8px 11px;
  border-radius: 7px;
  border: 1px solid var(--border);
  background: var(--surface-2);
  color: var(--fg);
  text-align: left;
}
.select-menu {
  position: absolute;
  top: calc(100% + 6px);
  left: 0;
  right: 0;
  max-height: 220px;
  overflow-y: auto;
  background: color-mix(in srgb, var(--surface) 97%, #ffffff);
  border: 1px solid var(--border);
  border-radius: 9px;
  padding: 5px;
  box-shadow: 0 12px 28px rgba(0, 0, 0, .5);
  display: none;
  z-index: 40;
}
.select-menu.open {
  display: grid;
  gap: 2px;
}
.select-opt {
  width: 100%;
  border: 0;
  background: transparent;
  padding: 7px 10px;
  border-radius: 6px;
  text-align: left;
  font-size: 12px;
  display: flex;
  align-items: center;
  gap: 8px;
}
.select-opt:hover:not(:disabled) {
  background: var(--surface-2);
}
.select-opt.active {
  background: var(--surface-2);
  font-weight: 600;
}
.step-switch {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  background: var(--surface-2);
  border-radius: 999px;
  padding: 3px;
  margin-bottom: 14px;
}
.step-btn {
  border: 0;
  background: transparent;
  border-radius: 999px;
  padding: 5px 8px;
  font-size: 12px;
  color: var(--muted);
}
.step-btn.active {
  background: var(--accent);
  color: var(--accent-fg);
  font-weight: 600;
}
.axis-stage {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  flex: 1;
}
.axis-col {
  display: grid;
  gap: 10px;
}
.axis-circle-btn {
  width: 36px;
  height: 36px;
  border-radius: 50%;
  padding: 0;
  display: grid;
  place-items: center;
}
.dpad {
  position: relative;
  width: 112px;
  height: 112px;
  border-radius: 50%;
  background: var(--surface-2);
  border: 1px solid var(--border);
  display: grid;
  place-items: center;
}
.dpad-btn {
  position: absolute;
  border: 0;
  background: transparent;
  width: 28px;
  height: 28px;
  padding: 0;
  font-size: 11px;
  font-weight: 600;
  color: var(--muted);
  display: grid;
  place-items: center;
}
.dpad-n { top: 6px; left: 50%; transform: translateX(-50%); }
.dpad-s { bottom: 6px; left: 50%; transform: translateX(-50%); }
.dpad-w { left: 6px; top: 50%; transform: translateY(-50%); }
.dpad-e { right: 6px; top: 50%; transform: translateY(-50%); }
.dpad-home {
  width: 34px;
  height: 34px;
  border-radius: 50%;
  padding: 0;
  background: var(--surface);
  display: grid;
  place-items: center;
}
.z-rail {
  background: var(--surface-2);
  border: 1px solid var(--border);
  border-radius: 18px;
  padding: 4px;
  display: grid;
  gap: 4px;
}
.z-rail button {
  width: 30px;
  height: 30px;
  border: 0;
  background: transparent;
  padding: 0;
  border-radius: 50%;
  font-size: 11px;
  font-weight: 600;
}
.axis-hint {
  margin-top: 10px;
  font-size: 11px;
  color: var(--muted);
  line-height: 1.4;
}
</style>
</head>
<body>
<div class="layout">
  <aside class="sidebar">
    <div class="wb-tabs">
      <span class="wb-tab">Cloud Printers</span>
      <button class="icon-btn" onclick="refreshPrinters()" title="Refresh printers">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12a9 9 0 1 1-2.64-6.36"/><polyline points="21 3 21 9 15 9"/></svg>
      </button>
    </div>

    <div id="printer-list" class="printer-list">
      <div class="empty-box">Connect your account to load printers.</div>
    </div>

    <div class="sidebar-foot">
      <button class="account-btn" onclick="openAccountModal()">
        <span class="pill"><span class="dot offline" id="auth-dot"></span><span class="account-email" id="auth-label">Not connected</span></span>
        <span style="color:var(--muted)">&#9881;</span>
      </button>
    </div>
  </aside>

  <main class="main">
    <div id="banner" class="banner"><span id="banner-text"></span><button class="banner-close" onclick="showBanner('')" title="Dismiss">&times;</button></div>

    <div class="grid">
      <section class="card card-job">
        <div class="card-head">
          <span class="card-title" id="printer-title">No printer selected</span>
          <span class="pill" id="mqtt-pill"><span class="dot" id="mqtt-dot"></span><span id="mqtt-label">Telemetry idle</span></span>
        </div>
        <div class="job-body">
          <div class="ring-wrap">
            <div class="ring" id="progress-ring"></div>
            <span class="ring-text" id="progress-text">0%</span>
          </div>
          <div class="job-meta">
            <span class="badge" id="job-badge"><span class="dot" id="job-badge-dot"></span><span id="job-badge-text">Idle</span></span>
            <div class="job-state" id="job-state">Idle</div>
            <div class="job-file" id="job-file">No active print</div>
            <div class="metric-sub" id="last-update">Waiting for status</div>
          </div>
        </div>
        <div class="controls" id="job-controls" style="display:none">
          <button id="btn-pause" class="btn-inline" onclick="sendControl('pause')" disabled>
            <svg width="12" height="12" viewBox="0 0 24 24" fill="currentColor"><rect x="6" y="4" width="4" height="16" rx="1"/><rect x="14" y="4" width="4" height="16" rx="1"/></svg>
            Pause
          </button>
          <button id="btn-resume" class="btn-inline" onclick="sendControl('resume')" disabled>
            <svg width="12" height="12" viewBox="0 0 24 24" fill="currentColor"><polygon points="6,4 20,12 6,20"/></svg>
            Resume
          </button>
          <button id="btn-stop" class="danger btn-inline" onclick="handleStop()" disabled>
            <svg width="12" height="12" viewBox="0 0 24 24" fill="currentColor"><rect x="5" y="5" width="14" height="14" rx="2"/></svg>
            Stop
          </button>
        </div>
      </section>

      <section class="card card-temps">
        <div class="card-head">
          <span class="card-title">Control</span>
          <span class="pill" id="printer-subtitle">Anycubic Cloud</span>
        </div>
        <div class="control-grid">
          <div class="control-tile" onclick="openControlModal()">
            <div class="metric-label">
              <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2v11"/><path d="M8 13h8l-2 5h-4z"/><path d="M12 18v4"/></svg>
              Nozzle
            </div>
            <div class="metric-val-row inline-val" id="ctrl-val-nozzle" onclick="editInlineControl(event, 'nozzle')" title="Click number to edit target">
              <div class="metric-val" id="temp-nozzle">--&deg;C</div>
              <div class="metric-sub" id="temp-nozzle-target">/ --</div>
            </div>
            <div class="temp-bar"><span id="bar-nozzle"></span></div>
          </div>
          <div class="control-tile" onclick="openControlModal()">
            <div class="metric-label">
              <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="13" width="18" height="4" rx="1"/><path d="M7 9c0-1.5 1-2 1-3.5"/><path d="M12 9c0-1.5 1-2 1-3.5"/><path d="M17 9c0-1.5 1-2 1-3.5"/></svg>
              Hotbed
            </div>
            <div class="metric-val-row inline-val" id="ctrl-val-bed" onclick="editInlineControl(event, 'bed')" title="Click number to edit target">
              <div class="metric-val" id="temp-bed">--&deg;C</div>
              <div class="metric-sub" id="temp-bed-target">/ --</div>
            </div>
            <div class="temp-bar"><span id="bar-bed"></span></div>
          </div>
          <div class="control-tile" onclick="openControlModal()">
            <div class="metric-label">
              <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 14.76V3.5a2.5 2.5 0 0 0-5 0v11.26a4.5 4.5 0 1 0 5 0z"/></svg>
              Chamber
            </div>
            <div class="metric-val-row inline-val" id="ctrl-val-chamber" onclick="editInlineControl(event, 'chamber')" title="Click number to edit target">
              <div class="metric-val" id="temp-chamber">-- &deg;C</div>
              <div class="metric-sub" id="temp-chamber-target">/ --</div>
            </div>
            <div class="temp-bar"><span id="bar-chamber"></span></div>
          </div>
          <div class="control-tile" onclick="openControlModal()">
            <div class="metric-label">Model Fan</div>
            <div class="metric-val inline-val" id="fan-model" onclick="editInlineControl(event, 'fan_model')" title="Click number to edit">--</div>
          </div>
          <div class="control-tile" onclick="openControlModal()">
            <div class="metric-label">Aux Fan</div>
            <div class="metric-val inline-val" id="fan-aux" onclick="editInlineControl(event, 'fan_aux')" title="Click number to edit">--</div>
          </div>
          <div class="control-tile" onclick="openControlModal()">
            <div class="metric-label">Exhaust</div>
            <div class="metric-val inline-val" id="fan-exhaust" onclick="editInlineControl(event, 'fan_exhaust')" title="Click number to edit">--</div>
          </div>
        </div>
      </section>

      <section class="card card-info">
        <div class="card-head">
          <span class="card-title">About Device</span>
          <button class="more-btn" onclick="toggleDeviceMenu(event)" title="Device options">&#8943;</button>
        </div>
        <div id="device-menu" class="device-menu">
          <button onclick="closeDeviceMenu();openFirmwareModal()">Firmware info</button>
          <button onclick="closeDeviceMenu();openDetailsModal()">Details</button>
          <button onclick="closeDeviceMenu();refreshPrinters()">Refresh printers</button>
          <button onclick="closeDeviceMenu();openAccountModal()">Account settings</button>
          <hr>
          <button class="danger-item" onclick="closeDeviceMenu();logoutAccount()">Disconnect</button>
        </div>
        <div class="device-card-body">
          <div class="device-preview" id="device-slide-icon">
            <svg width="64" height="72" viewBox="0 0 52 58" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linejoin="round">
              <rect x="6" y="4" width="40" height="48" rx="4"/>
              <rect x="12" y="12" width="28" height="28" rx="2" stroke-opacity=".55"/>
              <path d="M16 17h20M26 17v9"/>
              <path d="M23 26h6l-1.5 4h-3z"/>
              <line x1="15" y1="36" x2="37" y2="36" stroke-width="2.2"/>
              <rect x="10" y="52" width="6" height="3" rx="1"/>
              <rect x="36" y="52" width="6" height="3" rx="1"/>
            </svg>
          </div>
          <div class="device-details" id="device-slide-0">
            <div class="device-title-row">
              <div class="device-name" id="info-name">-</div>
              <span class="badge" id="info-online-badge"><span class="dot" id="info-online-dot"></span><span id="info-online">-</span></span>
            </div>
            <div class="device-kv">
              <span class="k">Model</span><span class="v" id="info-model">-</span>
              <span class="k">CN</span><span class="v"><span id="info-id">-</span> <button class="copy-btn" onclick="copyDeviceCn()" title="Copy CN"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg></button></span>
              <span class="k">Firmware</span><span class="v" id="info-fw">-</span>
            </div>
          </div>
          <div class="device-details" id="device-slide-1" style="display:none">
            <div class="device-title-row">
              <div class="device-name" id="ace-name">ACE Pro</div>
              <span class="badge" id="ace-badge"><span class="dot"></span><span id="ace-status">Not connected</span></span>
            </div>
            <div class="device-kv">
              <span class="k">Firmware</span><span class="v" id="ace-fw">-</span>
              <span class="k">Temp</span><span class="v" id="ace-temp">--</span>
              <span class="k">Telemetry</span><span class="v" id="info-telemetry">Idle</span>
            </div>
          </div>
          <button class="device-slide-nav" onclick="setDeviceSlide(app.deviceSlide ? 0 : 1)" title="Switch device view" id="device-slide-arrow">&rsaquo;</button>
        </div>
        <div class="device-dots">
          <button class="device-dot-btn active" id="device-dot-0" onclick="setDeviceSlide(0)" title="Printer"></button>
          <button class="device-dot-btn" id="device-dot-1" onclick="setDeviceSlide(1)" title="ACE Pro"></button>
        </div>
      </section>

      <section class="card" id="card-camera">
        <div class="card-head">
          <span class="card-title">Camera</span>
          <span class="pill" id="camera-status">Cloud</span>
        </div>
        <div class="camera-box">
          <div class="camera-empty">
            <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6"><path d="M23 7l-7 5 7 5V7z"/><rect x="1" y="5" width="15" height="14" rx="2"/></svg>
            <span id="camera-msg">Press Play to request camera</span>
          </div>
          <button class="camera-play" id="camera-play-btn" onclick="unsupportedAction('Camera stream')" title="Play camera">
            <svg width="13" height="13" viewBox="0 0 24 24" fill="currentColor"><polygon points="7,4 20,12 7,20"/></svg>
          </button>
          <button class="camera-fs" id="camera-fs-btn" onclick="unsupportedAction('Fullscreen camera')" title="Fullscreen">
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="15 3 21 3 21 9"/><polyline points="9 21 3 21 3 15"/><line x1="21" y1="3" x2="14" y2="10"/><line x1="3" y1="21" x2="10" y2="14"/></svg>
          </button>
        </div>
      </section>

      <section class="card" id="card-materials">
        <div class="card-head">
          <span class="card-title">Materials</span>
          <span class="pill">ACE</span>
        </div>
        <div class="seg-tabs">
          <button class="seg-tab locked" id="tab-spool" onclick="setMaterialTab(this, 'spool')">Spool</button>
          <button class="seg-tab active" id="tab-ace1" onclick="setMaterialTab(this, 'ace1')">ACE 1</button>
        </div>
        <div class="ace-tray" id="ace-tray"></div>
        <div class="drying-sep" id="drying-section">
          <div class="drying-row">
            <span class="dry-left"><span>Drying</span><span class="dry-chip" id="dry-chip">32&deg;C</span></span>
            <button class="switch" id="dry-switch" onclick="toggleDrying()" title="Toggle drying"><span class="switch-knob"></span></button>
          </div>
          <button class="dry-summary" id="dry-summary" onclick="openDryingModal()" style="display:none">
            <span><span class="k" style="color:var(--muted)">Drying temp</span><br><strong id="dry-temp-label">32&deg;C</strong> <span style="color:var(--muted)" id="dry-target-label">/ 55&deg;C</span></span>
            <span><span class="k" style="color:var(--muted)">Remaining</span><br><strong id="dry-time-label">8h</strong></span>
            <span style="color:var(--muted)">&rsaquo;</span>
          </button>
        </div>
      </section>

      <section class="card" id="card-axis">
        <div class="card-head">
          <span class="card-title">Axis Control</span>
        </div>
        <div class="step-switch">
          <button class="step-btn active" onclick="setAxisStep(this)">1mm</button>
          <button class="step-btn" onclick="setAxisStep(this)">15mm</button>
          <button class="step-btn" onclick="setAxisStep(this)">50mm</button>
        </div>
        <div class="axis-stage">
          <div class="axis-col">
            <button class="axis-circle-btn" onclick="unsupportedAction('Home all')" title="Home"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 10.5 12 3l9 7.5"/><path d="M5 10v10h14V10"/></svg></button>
            <button class="axis-circle-btn" onclick="unsupportedAction('Auto level')" title="Level">&#8853;</button>
          </div>
          <div class="dpad">
            <button class="dpad-btn dpad-n" onclick="unsupportedAction('Move Y+')">Y</button>
            <button class="dpad-btn dpad-w" onclick="unsupportedAction('Move X-')">X</button>
            <button class="dpad-home" onclick="unsupportedAction('Home XY')" title="Home XY"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 10.5 12 3l9 7.5"/><path d="M5 10v10h14V10"/></svg></button>
            <button class="dpad-btn dpad-e" onclick="unsupportedAction('Move X+')">X</button>
            <button class="dpad-btn dpad-s" onclick="unsupportedAction('Move Y-')">Y</button>
          </div>
          <div class="z-rail">
            <button onclick="unsupportedAction('Move Z+')">Z+</button>
            <button onclick="unsupportedAction('Home Z')" title="Home Z"><svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 10.5 12 3l9 7.5"/><path d="M5 10v10h14V10"/></svg></button>
            <button onclick="unsupportedAction('Move Z-')">Z-</button>
          </div>
        </div>
        <div class="axis-hint">Cloud API: print jobs &amp; pause/resume/stop.</div>
      </section>
    </div>
  </main>
</div>

<div id="details-modal" class="modal-backdrop" onclick="if(event.target===this)closeDetailsModal()">
  <div class="modal wide">
    <div class="modal-head">
      <h2>Details</h2>
      <button class="banner-close" onclick="closeDetailsModal()" title="Close">&times;</button>
    </div>
    <div class="details-grid">
      <div>
        <div class="device-preview" style="margin:0 auto 14px;width:110px;height:124px">
          <svg width="88" height="98" viewBox="0 0 52 58" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linejoin="round">
            <rect x="6" y="4" width="40" height="48" rx="4"/><rect x="12" y="12" width="28" height="28" rx="2" stroke-opacity=".55"/>
            <path d="M16 17h20M26 17v9"/><path d="M23 26h6l-1.5 4h-3z"/><line x1="15" y1="36" x2="37" y2="36" stroke-width="2.2"/>
            <rect x="10" y="52" width="6" height="3" rx="1"/><rect x="36" y="52" width="6" height="3" rx="1"/>
          </svg>
        </div>
        <div class="details-stats">
          <div class="stat-row"><span class="k">Print time</span><span class="v" id="det-time">-</span></div>
          <div class="stat-row"><span class="k">Filament used</span><span class="v" id="det-filament">-</span></div>
          <div class="stat-row"><span class="k">Print count</span><span class="v" id="det-count">-</span></div>
        </div>
      </div>
      <div class="details-kv">
        <span class="k">Device name</span><span class="v" id="det-name">-</span>
        <span class="k">CN</span><span class="v"><span id="det-cn">-</span> <button class="copy-btn" onclick="copyDeviceCn()" title="Copy CN">&#10697;</button></span>
        <span class="k">Firmware</span><span class="v" id="det-fw">-</span>
        <span class="k">Model</span><span class="v" id="det-model">-</span>
        <span class="k">MAC address</span><span class="v" id="det-mac">-</span>
        <span class="k">Bind time</span><span class="v" id="det-bind">-</span>
      </div>
    </div>
  </div>
</div>

<div id="firmware-modal" class="modal-backdrop" onclick="if(event.target===this)closeFirmwareModal()">
  <div class="modal wide" style="max-width:520px">
    <div class="modal-head">
      <h2>Firmware info</h2>
      <button class="banner-close" onclick="closeFirmwareModal()" title="Close">&times;</button>
    </div>
    <div class="fw-card">
      <div class="device-preview" style="width:64px;height:72px">
        <svg width="52" height="58" viewBox="0 0 52 58" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linejoin="round"><rect x="6" y="4" width="40" height="48" rx="4"/><rect x="12" y="12" width="28" height="28" rx="2" stroke-opacity=".55"/></svg>
      </div>
      <div>
        <div class="device-name" id="fw-printer-name">-</div>
        <div class="metric-sub" id="fw-printer-model">-</div>
        <div style="margin-top:6px;font-weight:700" id="fw-printer-ver">-</div>
      </div>
    </div>
    <div class="fw-card" id="fw-ace-card">
      <div>
        <div class="device-name" id="fw-ace-name">ACE Pro</div>
        <div class="metric-sub" id="fw-ace-ver">-</div>
      </div>
    </div>
  </div>
</div>

<div id="material-modal" class="modal-backdrop" onclick="if(event.target===this)closeMaterialModal()">
  <div class="modal wide" style="max-width:620px">
    <div class="modal-head">
      <h2>Material settings</h2>
      <button class="banner-close" onclick="closeMaterialModal()" title="Close">&times;</button>
    </div>
    <div class="mat-modal-grid">
      <div style="text-align:center">
        <div class="spool-drum" id="mat-preview-drum" style="margin:0 auto 10px;width:62px;height:80px"></div>
        <div style="font-weight:700" id="mat-preview-type">PETG</div>
        <div class="metric-sub" id="mat-preview-hex">#28302A</div>
        <div style="display:flex;gap:8px;justify-content:center;margin-top:12px">
          <button onclick="unsupportedAction('Feed filament')">Feed</button>
          <button onclick="unsupportedAction('Retract filament')">Retract</button>
        </div>
      </div>
      <div>
        <div class="field">
          <label>Material type</label>
          <div class="select-wrap" id="mat-select-wrap">
            <button type="button" class="select-trigger" id="mat-type-trigger" onclick="toggleMaterialMenu(event)">
              <span id="mat-type-label">PETG</span>
              <span style="color:var(--muted);font-size:10px">&#9662;</span>
            </button>
            <div class="select-menu" id="mat-type-menu"></div>
          </div>
        </div>
        <div class="metric-sub">Color</div>
        <div class="swatch-grid" id="mat-swatches"></div>
      </div>
    </div>
    <div class="modal-actions" style="justify-content:flex-end">
      <div class="modal-right">
        <button onclick="closeMaterialModal()">Cancel</button>
        <button class="primary" onclick="saveMaterialSlot()">Save</button>
      </div>
    </div>
  </div>
</div>

<div id="drying-modal" class="modal-backdrop" onclick="if(event.target===this)closeDryingModal()">
  <div class="modal wide" style="max-width:560px">
    <div class="modal-head">
      <h2>Drying settings</h2>
      <button class="banner-close" onclick="closeDryingModal()" title="Close">&times;</button>
    </div>
    <div class="metric-sub">Popular materials</div>
    <div class="preset-grid" id="dry-presets"></div>
    <div class="dry-summary" style="cursor:default">
      <span><span class="k" style="color:var(--muted)">Drying temp (max 55&deg;C)</span><br><input id="dry-modal-temp-input" type="number" min="25" max="55" value="55" style="width:72px;padding:4px 8px;border-radius:6px;border:1px solid var(--border);background:var(--bg);color:var(--fg);font-weight:700"> &deg;C</span>
      <span><span class="k" style="color:var(--muted)">Duration</span><br><input id="dry-modal-hours-input" type="number" min="1" max="24" value="8" style="width:64px;padding:4px 8px;border-radius:6px;border:1px solid var(--border);background:var(--bg);color:var(--fg);font-weight:700"> h</span>
    </div>
    <div class="modal-actions" style="justify-content:flex-end">
      <div class="modal-right">
        <button onclick="closeDryingModal()">Cancel</button>
        <button class="primary" onclick="saveDryingSettings()">Save</button>
      </div>
    </div>
  </div>
</div>

<div id="control-modal" class="modal-backdrop" onclick="if(event.target===this)closeControlModal()">
  <div class="modal wide" style="max-width:640px">
    <div class="modal-head">
      <h2>Control</h2>
      <button class="banner-close" onclick="closeControlModal()" title="Close">&times;</button>
    </div>
    <div class="ctrl-modal-grid">
      <div class="device-preview" style="margin:0 auto;width:130px;height:146px">
        <svg width="104" height="116" viewBox="0 0 52 58" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linejoin="round">
          <rect x="6" y="4" width="40" height="48" rx="4"/><rect x="12" y="12" width="28" height="28" rx="2" stroke-opacity=".55"/>
          <path d="M16 17h20M26 17v9"/><path d="M23 26h6l-1.5 4h-3z"/><line x1="15" y1="36" x2="37" y2="36" stroke-width="2.2"/>
          <rect x="10" y="52" width="6" height="3" rx="1"/><rect x="36" y="52" width="6" height="3" rx="1"/>
        </svg>
      </div>
      <div class="ctrl-rows">
        <div class="ctrl-row"><span class="metric-label">Nozzle</span><div class="ctrl-input-wrap"><input id="cm-nozzle" type="number" min="0" max="320" value="0"><span class="ctrl-hint" id="cm-nozzle-hint">Max 320&deg;C</span><span class="ctrl-unit">&deg;C</span></div></div>
        <div class="ctrl-row"><span class="metric-label">Model Fan</span><div class="ctrl-input-wrap"><input id="cm-fan-model" type="number" min="0" max="100" value="0"><span class="ctrl-unit">%</span></div></div>
        <div class="ctrl-row"><span class="metric-label">Exhaust Fan</span><div class="ctrl-input-wrap"><input id="cm-fan-exhaust" type="number" min="0" max="100" value="0"><span class="ctrl-unit">%</span></div></div>
        <div class="ctrl-row"><span class="metric-label">Aux Fan</span><div class="ctrl-input-wrap"><input id="cm-fan-aux" type="number" min="0" max="100" value="0"><span class="ctrl-unit">%</span></div></div>
        <div class="ctrl-row"><span class="metric-label">Hotbed</span><div class="ctrl-input-wrap"><input id="cm-bed" type="number" min="0" max="120" value="0"><span class="ctrl-hint" id="cm-bed-hint">Max 120&deg;C</span><span class="ctrl-unit">&deg;C</span></div></div>
        <div class="ctrl-row"><span class="metric-label">Chamber</span><div class="ctrl-input-wrap"><input id="cm-chamber" type="number" min="0" max="65" value="0"><span class="ctrl-hint">65&deg;C</span><span class="ctrl-unit">&deg;C</span></div></div>
      </div>
    </div>
    <div class="modal-actions" style="justify-content:flex-end">
      <div class="modal-right">
        <button onclick="closeControlModal()">Cancel</button>
        <button class="primary" onclick="saveControlModal()">Save</button>
      </div>
    </div>
  </div>
</div>

<div id="account-modal" class="modal-backdrop" onclick="if(event.target===this)closeAccountModal()">
  <div class="modal">
    <h2>Anycubic Cloud Account</h2>
    <p>Sign in on the official Anycubic Cloud page. Your password is never sent to this plugin.</p>
    <div class="modal-actions">
      <button class="danger" onclick="logoutAccount()">Disconnect</button>
      <div class="modal-right">
        <button onclick="closeAccountModal()">Cancel</button>
        <button class="primary" onclick="startBrowserLogin()">Sign in</button>
      </div>
    </div>
  </div>
</div>

<script>
const q = id => document.getElementById(id);
const MATERIAL_TYPES = ["PLA", "PLA+", "PLA Silk", "PETG", "ABS", "ASA", "TPU", "PA", "PC", "Empty"];
const SWATCHES = ["#28302A","#F2F4F7","#EEDEC9","#B6BCC4","#858A94","#D91E18","#DF4C73","#F493A7","#F36D21","#F2B705","#784B32","#5BA64B","#1E54A8","#42BCE6"];
const DRY_PRESETS = [
  { name: "PLA", temp: 45, hours: 4 },
  { name: "PLA-CF", temp: 55, hours: 8 },
  { name: "PETG", temp: 55, hours: 8 },
  { name: "TPU", temp: 55, hours: 8 },
  { name: "ASA", temp: 55, hours: 8 },
  { name: "ABS", temp: 55, hours: 8 },
  { name: "PA", temp: 55, hours: 12 },
  { name: "PC", temp: 55, hours: 12 },
];
const app = {
  auth: false, email: "", printers: [], selected: 0, stopArmed: false, stopTimer: null, bannerTimer: null, deviceSlide: 0,
  matTab: "ace1", editSlot: 0, draftType: "PETG", draftColor: "#28302A",
  externalSpool: { type: "Empty", color: "" },
  slots: [
    { type: "PETG", color: "#28302A" },
    { type: "PETG", color: "#28302A" },
    { type: "ABS", color: "#F2F4F7" },
    { type: "Empty", color: "" },
  ],
  drying: { on: false, cur: 32, target: 55, hours: 8, preset: "PETG" },
  targets: { nozzle: 0, bed: 0, chamber: 0, fan_model: 0, fan_aux: 0, fan_exhaust: 0 },
  lastStatus: null,
  editingInline: false,
};

function esc(v) {
  return String(v).replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

function showBanner(text, kind) {
  const el = q("banner");
  const txt = q("banner-text");
  if (app.bannerTimer) {
    clearTimeout(app.bannerTimer);
    app.bannerTimer = null;
  }
  if (!text) {
    el.className = "banner";
    txt.textContent = "";
    return;
  }
  txt.textContent = text;
  el.className = "banner visible " + (kind || "");
  app.bannerTimer = setTimeout(() => showBanner(""), kind === "error" ? 4500 : 3000);
}

function disarmStop() {
  app.stopArmed = false;
  if (app.stopTimer) {
    clearTimeout(app.stopTimer);
    app.stopTimer = null;
  }
  const btn = q("btn-stop");
  btn.classList.remove("armed");
  btn.textContent = "Stop";
}

function handleStop() {
  if (!app.stopArmed) {
    app.stopArmed = true;
    const btn = q("btn-stop");
    btn.classList.add("armed");
    btn.textContent = "Confirm Stop";
    app.stopTimer = setTimeout(disarmStop, 4000);
    return;
  }
  disarmStop();
  sendControl("stop");
}

function sendControl(action) {
  if (!app.selected) return;
  showBanner("Sending " + action + " command...", "");
  orca.postMessage({ action });
}

function refreshPrinters() {
  showBanner("Refreshing printer list...", "");
  orca.postMessage({ action: "refresh" });
}

function selectPrinter(id) {
  app.selected = Number(id) || 0;
  disarmStop();
  renderPrinters();
  orca.postMessage({ action: "select", id: app.selected });
}

function openAccountModal() {
  q("account-modal").classList.add("open");
}

function closeAccountModal() {
  q("account-modal").classList.remove("open");
}

function startBrowserLogin() {
  closeAccountModal();
  showBanner("Waiting for Anycubic sign-in...", "");
  orca.postMessage({ action: "login" });
}

function toggleDeviceMenu(ev) {
  ev.stopPropagation();
  q("device-menu").classList.toggle("open");
}

function closeDeviceMenu() {
  const menu = q("device-menu");
  if (menu) menu.classList.remove("open");
  const matMenu = q("mat-type-menu");
  if (matMenu) matMenu.classList.remove("open");
}

document.addEventListener("click", closeDeviceMenu);

function setDeviceSlide(index) {
  app.deviceSlide = index ? 1 : 0;
  q("device-slide-0").style.display = app.deviceSlide === 0 ? "grid" : "none";
  q("device-slide-1").style.display = app.deviceSlide === 1 ? "grid" : "none";
  q("device-dot-0").classList.toggle("active", app.deviceSlide === 0);
  q("device-dot-1").classList.toggle("active", app.deviceSlide === 1);
  q("device-slide-arrow").innerHTML = app.deviceSlide === 0 ? "&rsaquo;" : "&lsaquo;";
}

function copyDeviceCn() {
  const cn = q("info-id").textContent || "";
  if (!cn || cn === "-") return;
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(cn).then(() => showBanner("Copied CN: " + cn, "ok")).catch(() => {});
  } else {
    showBanner("CN: " + cn, "ok");
  }
}

function openDetailsModal() { q("details-modal").classList.add("open"); }
function closeDetailsModal() { q("details-modal").classList.remove("open"); }
function openFirmwareModal() { q("firmware-modal").classList.add("open"); }
function closeFirmwareModal() { q("firmware-modal").classList.remove("open"); }

function unsupportedAction(name) {
  showBanner(name + " is not available via Anycubic Cloud API yet.", "ok");
}

function setMaterialTab(btn, tab) {
  const chosen = app.printers.find(p => Number(p.id) === Number(app.selected));
  const hasAce = chosen ? chosen.has_ace !== false : true;
  if (tab === "spool" && hasAce) {
    showBanner("External spool holder is unavailable while ACE 1 is connected.", "error");
    return;
  }
  if (tab === "ace1" && !hasAce) {
    showBanner("ACE Pro is not connected to this printer.", "error");
    return;
  }
  btn.parentElement.querySelectorAll(".seg-tab").forEach(el => el.classList.remove("active"));
  btn.classList.add("active");
  app.matTab = tab || "ace1";
  renderMaterials();
}

function renderMaterials() {
  const tray = q("ace-tray");
  if (!tray) return;
  const chosen = app.printers.find(p => Number(p.id) === Number(app.selected));
  const hasAce = chosen ? chosen.has_ace !== false : true;
  q("tab-spool").classList.toggle("locked", hasAce);
  q("tab-ace1").classList.toggle("locked", !hasAce);
  q("tab-spool").classList.toggle("active", !hasAce);
  q("tab-ace1").classList.toggle("active", hasAce);
  if (!hasAce) {
    const ext = app.externalSpool || { type: "Empty", color: "" };
    const empty = !ext.type || ext.type === "Empty";
    const style = empty ? "" : `style="--spool-color:${esc(ext.color || "#28302A")}"`;
    tray.innerHTML = `<button class="spool-slot" style="grid-column:1/-1;justify-self:center;min-width:96px" onclick="openMaterialModal(-1)" title="External spool">
      <div class="spool-drum ${empty ? "empty" : ""}" ${style}></div>
      <span class="spool-type">${esc(empty ? "Empty" : ext.type)}</span>
      <span class="spool-num" style="width:auto;padding:0 6px;border-radius:999px">Spool</span>
    </button>`;
    q("drying-section").style.display = "none";
    q("ace-temp").textContent = "--";
    return;
  }
  q("drying-section").style.display = "grid";
  q("dry-switch").disabled = !(chosen && chosen.online);
  const aceTempText = app.drying.cur != null ? app.drying.cur + "°C" : "--";
  q("ace-temp").textContent = aceTempText;
  tray.innerHTML = app.slots.map((s, idx) => {
    const empty = !s.type || s.type === "Empty";
    const style = empty ? "" : `style="--spool-color:${esc(s.color || "#28302A")}"`;
    return `<button class="spool-slot" onclick="openMaterialModal(${idx})" title="Configure slot ${idx + 1}">
      <div class="spool-drum ${empty ? "empty" : ""}" ${style}></div>
      <span class="spool-type">${esc(empty ? "Empty" : s.type)}</span>
      <span class="spool-num">${idx + 1}</span>
    </button>`;
  }).join("");
  q("dry-switch").classList.toggle("on", !!app.drying.on);
  q("dry-chip").textContent = aceTempText;
  q("dry-summary").style.display = app.drying.on ? "flex" : "none";
  q("dry-temp-label").textContent = aceTempText;
  q("dry-target-label").textContent = "/ " + app.drying.target + "°C";
  q("dry-time-label").textContent = app.drying.remain_min
    ? Math.floor(app.drying.remain_min / 60) + "h " + (app.drying.remain_min % 60) + "m"
    : app.drying.hours + "h";
}

function toggleMaterialMenu(ev) {
  ev.stopPropagation();
  q("mat-type-menu").classList.toggle("open");
}

function pickMaterialType(type) {
  app.draftType = type;
  q("mat-type-menu").classList.remove("open");
  renderMaterialTypeMenu();
  updateMaterialDraft();
}

function renderMaterialTypeMenu() {
  q("mat-type-label").textContent = app.draftType;
  q("mat-type-menu").innerHTML = MATERIAL_TYPES.map(t =>
    `<button type="button" class="select-opt ${t === app.draftType ? "active" : ""}" onclick="pickMaterialType('${t}')"><span style="width:14px;display:inline-block">${t === app.draftType ? "&#10003;" : ""}</span>${esc(t)}</button>`
  ).join("");
}

function openMaterialModal(idx) {
  app.editSlot = idx;
  const slot = (idx === -1 ? app.externalSpool : app.slots[idx]) || { type: "PETG", color: "#28302A" };
  app.draftType = slot.type || "PETG";
  app.draftColor = slot.color || "#28302A";
  renderMaterialTypeMenu();
  q("mat-swatches").innerHTML = SWATCHES.map(hex =>
    `<button class="swatch ${hex === app.draftColor ? "active" : ""}" style="background:${hex}" onclick="pickSwatch('${hex}')"></button>`
  ).join("");
  updateMaterialDraft();
  q("material-modal").classList.add("open");
}

function closeMaterialModal() {
  q("mat-type-menu").classList.remove("open");
  q("material-modal").classList.remove("open");
}

function pickSwatch(hex) {
  app.draftColor = hex;
  q("mat-swatches").querySelectorAll(".swatch").forEach(el => {
    el.classList.toggle("active", el.getAttribute("onclick").includes(hex));
  });
  updateMaterialDraft();
}

function updateMaterialDraft() {
  const type = app.draftType || "Empty";
  const empty = type === "Empty";
  const drum = q("mat-preview-drum");
  drum.classList.toggle("empty", empty);
  drum.style.setProperty("--spool-color", app.draftColor || "#28302A");
  q("mat-preview-type").textContent = type;
  q("mat-preview-hex").textContent = empty ? "-" : app.draftColor;
}

function saveMaterialSlot() {
  const type = app.draftType || "Empty";
  const next = { type, color: type === "Empty" ? "" : app.draftColor };
  if (app.editSlot === -1) {
    app.externalSpool = next;
  } else {
    app.slots[app.editSlot] = next;
  }
  closeMaterialModal();
  renderMaterials();
  showBanner("Updated " + (app.editSlot === -1 ? "external spool" : "slot " + (app.editSlot + 1)) + " preview (" + type + ").", "ok");
}

function toggleDrying() {
  showBanner("ACE Pro drying control via Cloud API is not supported yet.", "error");
}

function openDryingModal() {
  q("dry-presets").innerHTML = DRY_PRESETS.map((p, idx) =>
    `<button class="preset-chip ${p.name === app.drying.preset ? "active" : ""}" onclick="selectDryPreset(${idx})">${esc(p.name)}</button>`
  ).join("");
  q("dry-modal-temp-input").value = String(Math.min(55, Number(app.drying.target) || 55));
  q("dry-modal-hours-input").value = String(Math.max(1, Math.min(24, Math.round(Number(app.drying.hours) || 8))));
  q("drying-modal").classList.add("open");
}

function closeDryingModal() { q("drying-modal").classList.remove("open"); }

function selectDryPreset(idx) {
  const p = DRY_PRESETS[idx];
  if (!p) return;
  app.drying.preset = p.name;
  app.drying.target = Math.min(55, p.temp);
  app.drying.hours = p.hours;
  openDryingModal();
}

function saveDryingSettings() {
  const temp = Math.max(25, Math.min(55, Math.round(Number(q("dry-modal-temp-input").value) || 55)));
  const hours = Math.max(1, Math.min(24, Math.round(Number(q("dry-modal-hours-input").value) || 8)));
  app.drying.target = temp;
  app.drying.hours = hours;
  closeDryingModal();
  renderMaterials();
  showBanner("ACE Pro drying control via Cloud API is not supported yet (max 55°C).", "error");
}

function openControlModal() {
  const chosen = app.printers.find(p => Number(p.id) === Number(app.selected));
  if (!chosen || !chosen.online) return;
  const s = app.lastStatus || {};
  q("cm-nozzle").value = app.targets.nozzle;
  q("cm-bed").value = app.targets.bed;
  q("cm-chamber").value = app.targets.chamber;
  q("cm-fan-model").value = app.targets.fan_model;
  q("cm-fan-aux").value = app.targets.fan_aux;
  q("cm-fan-exhaust").value = app.targets.fan_exhaust;
  q("cm-nozzle-hint").textContent = (s.nozzle != null ? "Now " + s.nozzle + "°C / " : "") + "Max 320°C";
  q("cm-bed-hint").textContent = (s.bed != null ? "Now " + s.bed + "°C / " : "") + "Max 120°C";
  q("control-modal").classList.add("open");
}

function closeControlModal() { q("control-modal").classList.remove("open"); }

function setText(id, value) {
  const el = q(id);
  if (el) el.textContent = value;
}

function applyTargetValue(key, val) {
  const limits = { nozzle: [0, 320], bed: [0, 120], chamber: [0, 65], fan_model: [0, 100], fan_aux: [0, 100], fan_exhaust: [0, 100] };
  const [lo, hi] = limits[key] || [0, 100];
  const num = Math.max(lo, Math.min(hi, Math.round(Number(val) || 0)));
  app.targets[key] = num;
  if (key === "nozzle") setText("temp-nozzle-target", "/" + num + "°C");
  else if (key === "bed") setText("temp-bed-target", "/" + num + "°C");
  else if (key === "chamber") setText("temp-chamber-target", "/" + num + "°C");
  else if (key === "fan_model") setText("fan-model", num + "%");
  else if (key === "fan_aux") setText("fan-aux", num + "%");
  else if (key === "fan_exhaust") setText("fan-exhaust", num + "%");
  return num;
}

function saveControlModal() {
  applyTargetValue("nozzle", q("cm-nozzle").value);
  applyTargetValue("bed", q("cm-bed").value);
  applyTargetValue("chamber", q("cm-chamber").value);
  applyTargetValue("fan_model", q("cm-fan-model").value);
  applyTargetValue("fan_aux", q("cm-fan-aux").value);
  applyTargetValue("fan_exhaust", q("cm-fan-exhaust").value);
  closeControlModal();
  showBanner("Control targets updated in UI (Cloud API temp/fan write pending).", "ok");
}

function editInlineControl(ev, key) {
  ev.stopPropagation();
  const chosen = app.printers.find(p => Number(p.id) === Number(app.selected));
  if (!chosen || !chosen.online) return;
  const host = ev.currentTarget;
  if (host.querySelector("input")) return;
  const prevHtml = host.innerHTML;
  const unit = key.startsWith("fan_") ? "%" : "°C";
  const input = document.createElement("input");
  input.type = "number";
  input.className = "inline-num-input";
  input.value = String(app.targets[key] || 0);
  const suffix = document.createElement("span");
  suffix.className = "metric-sub";
  suffix.textContent = unit;
  host.innerHTML = "";
  host.appendChild(input);
  host.appendChild(suffix);
  app.editingInline = true;
  input.focus();
  input.select();
  let done = false;
  function commit(save) {
    if (done) return;
    done = true;
    app.editingInline = false;
    const nextVal = input.value;
    host.innerHTML = prevHtml;
    if (save) {
      const n = applyTargetValue(key, nextVal);
      showBanner("Set " + key.replace("_", " ") + " target to " + n + unit + " (preview).", "ok");
    }
  }
  input.addEventListener("click", e => e.stopPropagation());
  input.addEventListener("keydown", e => {
    if (e.key === "Enter") commit(true);
    else if (e.key === "Escape") commit(false);
  });
  input.addEventListener("blur", () => commit(true));
}

function setAxisStep(btn) {
  btn.parentElement.querySelectorAll(".step-btn").forEach(el => el.classList.remove("active"));
  btn.classList.add("active");
}

function logoutAccount() {
  closeAccountModal();
  orca.postMessage({ action: "logout" });
}

function renderAuth() {
  const dot = q("auth-dot");
  dot.className = "dot " + (app.auth ? "online" : "offline");
  q("auth-label").textContent = app.auth ? (app.email || "Connected") : "Not connected";
}

function renderPrinters() {
  const list = q("printer-list");
  if (!app.printers.length) {
    list.innerHTML = app.auth
      ? '<div class="empty-box">No printers found in this account.</div>'
      : '<div class="empty-box">Connect your account to load printers.</div>';
  } else {
    list.innerHTML = app.printers.map(p => {
      const id = Number(p.id) || 0;
      const selected = id === Number(app.selected);
      const online = !!p.online;
      return `<button class="printer-item ${selected ? "selected" : ""} ${online ? "" : "is-offline"}" onclick="selectPrinter(${id})">
        <span class="printer-left">
          <span class="printer-icon"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M6 9V2h12v7"/><path d="M6 18H4a2 2 0 0 1-2-2v-5a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v5a2 2 0 0 1-2 2h-2"/><rect x="6" y="14" width="12" height="8"/></svg></span>
          <span class="printer-meta">
            <div class="printer-name">${esc(p.name || "Anycubic printer")}</div>
            <div class="printer-model">${esc(p.model || "Cloud device")}</div>
          </span>
        </span>
        <span class="pill"><span class="dot ${online ? "online" : "offline"}"></span>${online ? "Online" : "Offline"}</span>
      </button>`;
    }).join("");
  }

  const chosen = app.printers.find(p => Number(p.id) === Number(app.selected));
  const hasPrinter = !!chosen;
  const isOnline = !!(chosen && chosen.online);
  if (!isOnline) {
    q("job-controls").style.display = "none";
  }
  q("btn-pause").disabled = !isOnline;
  q("btn-resume").disabled = !isOnline;
  q("btn-stop").disabled = !isOnline;

  document.querySelectorAll("#card-camera button, #card-axis button, #card-materials button").forEach(btn => {
    btn.disabled = !isOnline;
  });
  ["card-camera", "card-materials", "card-axis"].forEach(id => {
    const el = q(id);
    if (el) el.classList.toggle("is-offline", hasPrinter && !isOnline);
  });
  q("camera-msg").textContent = !hasPrinter
    ? "Select a printer"
    : isOnline
      ? "Press Play to request camera"
      : "Printer is offline";

  if (chosen) {
    q("printer-title").textContent = chosen.name || "Anycubic printer";
    q("printer-subtitle").textContent = chosen.model || "Anycubic Cloud printer";
    q("info-name").textContent = chosen.name || "-";
    q("info-model").textContent = chosen.model || "-";
    q("info-id").textContent = chosen.cn || chosen.id || "-";
    q("info-fw").textContent = chosen.firmware || "-";
    q("ace-name").textContent = chosen.ace_name || "ACE Pro";
    q("ace-fw").textContent = chosen.has_ace === false ? "Not connected" : (chosen.ace_firmware || "-");
    q("ace-status").textContent = chosen.has_ace === false ? "Not connected" : "Connected";
    q("ace-badge").className = "badge " + (chosen.has_ace === false ? "danger" : "ok");
    q("det-name").textContent = chosen.name || "-";
    q("det-cn").textContent = chosen.cn || chosen.id || "-";
    q("det-fw").textContent = chosen.firmware || "-";
    q("det-model").textContent = chosen.model || "-";
    q("det-mac").textContent = chosen.mac || "-";
    q("det-bind").textContent = chosen.bind_time || "-";
    q("det-time").textContent = chosen.print_time || "-";
    q("det-filament").textContent = chosen.filament || "-";
    q("det-count").textContent = chosen.print_count || "-";
    q("fw-printer-name").textContent = chosen.name || "-";
    q("fw-printer-model").textContent = chosen.model || "-";
    q("fw-printer-ver").textContent = chosen.firmware || "-";
    q("fw-ace-name").textContent = chosen.ace_name || "ACE Pro";
    q("fw-ace-ver").textContent = chosen.ace_firmware || "Not detected";
    q("info-online").textContent = isOnline ? "Online" : "Offline";
    q("info-online-badge").className = "badge " + (isOnline ? "ok" : "danger");
    q("info-online-dot").className = "dot " + (isOnline ? "online" : "offline");
    if (!isOnline) {
      q("mqtt-dot").className = "dot offline";
      q("mqtt-label").textContent = "Printer offline";
      q("info-telemetry").textContent = "Offline";
    }
  } else {
    q("printer-title").textContent = "No printer selected";
    q("printer-subtitle").textContent = app.auth
      ? "Select a printer from the sidebar"
      : "Connect your Anycubic Cloud account";
    ["info-name", "info-model", "info-id", "info-fw", "det-name", "det-cn", "det-fw", "det-model", "det-mac", "det-bind", "det-time", "det-filament", "det-count", "fw-printer-name", "fw-printer-model", "fw-printer-ver"].forEach(id => {
      q(id).textContent = "-";
    });
    q("ace-name").textContent = "ACE Pro";
    q("ace-fw").textContent = "-";
    q("fw-ace-name").textContent = "ACE Pro";
    q("fw-ace-ver").textContent = "-";
    q("info-online").textContent = "-";
    q("info-online-badge").className = "badge";
    q("info-online-dot").className = "dot";
  }
}

function tempRatio(cur, target) {
  if (cur == null) return 0;
  const max = target && target > 0 ? target : 100;
  return Math.max(0, Math.min(100, Math.round((Number(cur) / Number(max)) * 100)));
}

function renderStatus(s, isMqtt) {
  if (!s) return;
  app.lastStatus = s;
  if (s.nozzle_target != null) app.targets.nozzle = Number(s.nozzle_target) || 0;
  if (s.bed_target != null) app.targets.bed = Number(s.bed_target) || 0;
  if (s.chamber_target != null) app.targets.chamber = Number(s.chamber_target) || 0;
  const chosen = app.printers.find(p => Number(p.id) === Number(app.selected));
  const isOnline = !chosen || !!chosen.online;
  const progress = Math.max(0, Math.min(100, Number(s.progress) || 0));
  const rawState = String(s.state || "Idle");
  const stateText = isOnline ? rawState : "Printer Offline";
  const lower = stateText.toLowerCase();
  const tone = !isOnline || lower.includes("offline") || lower.includes("err") || lower.includes("fail")
    ? "danger"
    : lower.includes("pause") || lower.includes("wait")
      ? "warn"
      : lower.includes("print") || lower.includes("ready") || lower.includes("online")
        ? "ok"
        : "";
  const isPaused = isOnline && lower.includes("pause");
  const isPrinting = isOnline && !isPaused && (lower.includes("print") || lower.includes("heat") || lower.includes("run") || progress > 0);
  const isActiveJob = isPrinting || isPaused;
  q("job-controls").style.display = isActiveJob ? "grid" : "none";
  q("btn-pause").disabled = !isPrinting;
  q("btn-resume").disabled = !isPaused;
  q("btn-stop").disabled = !isActiveJob;
  q("progress-ring").style.setProperty("--p", isOnline ? progress : 0);
  q("progress-text").textContent = (isOnline ? progress : 0) + "%";
  q("job-state").textContent = stateText;
  q("job-badge").className = "badge " + tone;
  q("job-badge-dot").className = "dot " + (tone === "ok" ? "online" : tone === "danger" ? "offline" : tone);
  q("job-badge-text").textContent = isOnline ? rawState : "Disconnected";
  q("job-file").textContent = isOnline ? (s.file || "No active print") : "Printer is offline";
  if (!app.editingInline) {
    setText("temp-nozzle", isOnline && s.nozzle != null ? s.nozzle + "°C" : "--°C");
    setText("temp-nozzle-target", "/" + (isOnline && s.nozzle_target != null ? s.nozzle_target + "°C" : "--"));
    q("bar-nozzle").style.width = isOnline ? tempRatio(s.nozzle, s.nozzle_target) + "%" : "0%";
    setText("temp-bed", isOnline && s.bed != null ? s.bed + "°C" : "--°C");
    setText("temp-bed-target", "/" + (isOnline && s.bed_target != null ? s.bed_target + "°C" : "--"));
    q("bar-bed").style.width = isOnline ? tempRatio(s.bed, s.bed_target) + "%" : "0%";
    setText("temp-chamber", isOnline && s.chamber != null ? s.chamber + "°C" : "--°C");
    setText("temp-chamber-target", "/" + (isOnline && s.chamber_target != null ? s.chamber_target + "°C" : "--"));
    q("bar-chamber").style.width = isOnline ? tempRatio(s.chamber, s.chamber_target) + "%" : "0%";
    setText("fan-model", isOnline ? "0%" : "--");
    setText("fan-aux", isOnline ? "0%" : "--");
    setText("fan-exhaust", isOnline ? "0%" : "--");
  }
  if (Array.isArray(s.slots) && s.slots.length) {
    app.slots = s.slots;
    renderMaterials();
  }
  if (s.drying && typeof s.drying === "object") {
    app.drying = Object.assign({}, app.drying, s.drying);
    renderMaterials();
  }
  if (s.external_spool && typeof s.external_spool === "object") {
    app.externalSpool = s.external_spool;
    renderMaterials();
  }
  q("last-update").textContent = "Updated " + new Date().toLocaleTimeString();
  if (isOnline && isMqtt) {
    q("mqtt-dot").className = "dot online";
    q("mqtt-label").textContent = "MQTT live";
    q("info-telemetry").textContent = "MQTT live";
  } else if (isOnline) {
    q("mqtt-dot").className = "dot online";
    q("mqtt-label").textContent = "Cloud live";
    q("info-telemetry").textContent = "Cloud live";
  }
}

orca.onMessage(d => {
  if (!d || typeof d !== "object") return;
  if (window.__anysharikAuthGate) window.__anysharikAuthGate(d);
  if (d.auth !== undefined) app.auth = !!d.auth;
  if (d.email !== undefined) app.email = d.email || "";
  if (d.selected !== undefined) app.selected = Number(d.selected) || 0;
  if (d.printers !== undefined) app.printers = Array.isArray(d.printers) ? d.printers : [];
  renderAuth();
  renderPrinters();
  renderMaterials();
  if (d.status) renderStatus(d.status, !!d.mqtt);
  const chosen = app.printers.find(p => Number(p.id) === Number(app.selected));
  if (!d.status && d.mqtt === false && chosen && chosen.online) {
    q("mqtt-dot").className = "dot warn";
    q("mqtt-label").textContent = "MQTT connecting";
    q("info-telemetry").textContent = "Connecting";
  }
  if (d.message !== undefined) {
    showBanner(d.message, d.error ? "error" : "ok");
  }
});

orca.postMessage({ action: "load" });
setInterval(() => {
  if (app.auth && app.selected) orca.postMessage({ action: "poll_status" });
}, 5000);
</script>
<div id="auth-gate" style="position:fixed;inset:0;background:rgba(15,15,15,.96);display:grid;place-items:center;z-index:1000">
  <div style="width:min(420px,calc(100vw - 40px));background:var(--bg);border:1px solid var(--border);border-radius:10px;padding:24px;text-align:center">
    <h2 style="margin:0 0 12px;font-size:17px">Sign in to Anycubic Cloud</h2>
    <p id="auth-gate-text" style="color:var(--muted);line-height:1.5;margin:0 0 20px">Sign in is required before you can use printer controls.</p>
    <button id="auth-gate-button" class="primary">Sign in</button>
  </div>
</div>
<script>
(function(){
  const gate=document.getElementById("auth-gate"),button=document.getElementById("auth-gate-button"),text=document.getElementById("auth-gate-text");
  function show(error){gate.style.display="grid";button.disabled=false;text.textContent=error||"Sign in is required before you can use printer controls."}
  button.onclick=function(){button.disabled=true;text.textContent="Waiting for the official Anycubic sign-in window...";orca.postMessage({action:"login"})};
  window.__anysharikAuthGate=function(data){if(data.auth===true){gate.style.display="none"}else if(data.auth===false){show(data.error||data.message)}};
  show();
})();
</script>
</body>
</html>"""


class CloudPage(orca.pages.PagesPluginCapabilityBase):
    def get_name(self):
        return "AnySharik"

    def get_ui(self):
        return PAGE

    def on_message(self, data):
        global _agent
        if not isinstance(data, dict) or not _agent:
            return
        action = data.get("action") or ""
        if action == "login":
            threading.Thread(target=_login_worker, args=(self,), daemon=True).start()
            self.post_message({"message": "Waiting for Anycubic Cloud sign-in..."})
        elif action == "logout":
            save_state({"token": "", "email": "", "printer_id": 0})
            _agent.disconnect_printer()
            _agent.printers = []
            _agent.selected = 0
            _agent.refresh_page(self, banner="Disconnected from Anycubic Cloud.")
        elif action in ("load", "refresh"):
            _agent.refresh_page(self)
        elif action == "poll_status":
            _agent.poll_status_for_page(self)
        elif action == "select":
            _agent.select(int(data.get("id") or 0))
            _agent.refresh_page(self)
        elif action in ("pause", "resume", "stop"):
            _agent.control(action, page=self)


class CloudAgent(orca.printer_agent.PrinterAgentBase):
    def __init__(self):
        global _agent
        super().__init__()
        _agent = self
        self.callbacks = {}
        self.printers = []
        self.selected = load_state().get("printer_id", 0)
        self.mqtt = None
        self._page = None

    def get_name(self):
        return "AnySharik printer agent"

    def get_agent_info(self):
        return orca.printer_agent.AgentInfo(AGENT_ID, "AnySharik", "0.3.26", "Anycubic Cloud")

    def _cb(self, name, fn):
        self.callbacks[name] = fn
        return 0

    def set_on_ssdp_msg_fn(self, fn): return self._cb("ssdp", fn)
    def set_on_local_connect_fn(self, fn): return self._cb("connect", fn)
    def set_on_local_message_fn(self, fn): return self._cb("message", fn)
    def set_on_message_fn(self, fn): return self._cb("message", fn)
    def set_on_printer_connected_fn(self, fn): return self._cb("connected", fn)
    def set_on_subscribe_failure_fn(self, fn): return self._cb("failure", fn)
    def set_on_user_message_fn(self, fn): return self._cb("user", fn)
    def set_server_callback(self, fn): return self._cb("server", fn)
    def set_queue_on_main_fn(self, fn): return self._cb("queue", fn)

    def start_discovery(self, start, sending):
        if not start:
            return True
        try:
            self.refresh()
        except CloudError:
            pass
        return True

    def bind_detect(self, *args): return -1

    def connect_printer(self, params):
        try:
            self.refresh()
        except CloudError:
            return -1
        try:
            if getattr(params, "dev_id", ""):
                self.select(int(params.dev_id))
        except (TypeError, ValueError):
            pass
        return 0 if self.printers else -1

    def disconnect_printer(self):
        if self.mqtt:
            self.mqtt.stop()
            self.mqtt = None
        return 0

    def get_user_selected_machine(self):
        return str(self.selected)

    def set_user_selected_machine(self, dev_id):
        try:
            self.selected = int(dev_id or 0)
        except (TypeError, ValueError):
            self.selected = 0
        state = load_state()
        state["printer_id"] = self.selected
        save_state(state)
        return 0

    def check_cert(self): return 0
    def request_bind_ticket(self): return (-1, "")
    def bind(self, *args): return -1
    def unbind(self, *args): return -1
    def ping_bind(self, *args): return -1

    def refresh(self):
        state = load_state()
        if not state.get("token"):
            self.printers = []
            return []
        self.printers = CloudApi(state["token"]).printers()
        fn = self.callbacks.get("ssdp")
        if fn:
            for p in self.printers:
                fn(json.dumps({
                    "dev_name": p.get("name", "Anycubic"),
                    "dev_id": str(p.get("id", 0)),
                    "dev_ip": "",
                    "dev_type": str(p.get("model") or p.get("machine_type") or ""),
                    "dev_signal": "-50",
                    "connect_type": "lan",
                    "bind_state": "free",
                }))
        return self.printers

    def select(self, pid):
        self.selected = int(pid or 0)
        state = load_state()
        state["printer_id"] = self.selected
        save_state(state)

    def _start_mqtt(self, printer):
        if self.mqtt:
            self.mqtt.stop()
            self.mqtt = None
        state = load_state()
        machine = str(printer.get("machine_type") or printer.get("machineType") or "printer")
        key = str(printer.get("key") or printer.get("printer_key") or printer.get("id") or "")
        if state.get("token") and state.get("email") and key:
            self.mqtt = MqttTelemetry(state["token"], state["email"], machine, key, self._mqtt_state)
            self.mqtt.start()
            return True
        return False

    def _mqtt_state(self, payload):
        fn = self.callbacks.get("message")
        if fn:
            try:
                fn(str(self.selected), json.dumps({"print": {"command": "push_status", "data": payload}}))
            except Exception:
                pass
        if self._page is not None:
            try:
                self._page.post_message({"status": _normalize_status(payload), "mqtt": True})
            except Exception:
                pass

    def refresh_page(self, page, banner=None):
        self._page = page
        state = load_state()
        token = state.get("token", "")
        email = state.get("email", "")
        error_msg = None
        authenticated = False
        if token:
            try:
                CloudApi(token).profile()
                authenticated = True
            except CloudError as exc:
                error_msg = str(exc)
                state.update(token="", email="")
                save_state(state)
                token = ""
                email = ""
        try:
            ps = self.refresh() if authenticated else []
        except CloudError as exc:
            ps = []
            error_msg = str(exc)
            authenticated = False
            state.update(token="", email="")
            save_state(state)
            token = ""
            email = ""

        selected_id = int(state.get("printer_id") or self.selected or 0)
        if not selected_id and ps:
            selected_id = int(ps[0].get("id") or 0)
            self.select(selected_id)

        payload = {
            "auth": authenticated,
            "email": email,
            "selected": selected_id,
            "printers": [],
        }
        chosen = next((p for p in ps if int(p.get("id") or 0) == selected_id), None)
        raw_status = None
        if chosen and authenticated and token:
            if self._start_mqtt(chosen):
                payload["mqtt"] = False
            try:
                raw_status = CloudApi(token).status(selected_id)
                payload["status"] = _normalize_status(raw_status)
            except CloudError:
                pass
        else:
            self.disconnect_printer()

        payload["printers"] = [
            _extract_device_info(p, raw_status if chosen and int(p.get("id") or 0) == selected_id else None)
            for p in ps
        ]

        page.post_message(payload)

    def poll_status_for_page(self, page):
        state = load_state()
        token = state.get("token", "")
        pid = int(state.get("printer_id") or self.selected or 0)
        if not token or not pid:
            return
        try:
            raw_status = CloudApi(token).status(pid)
            page.post_message({"status": _normalize_status(raw_status)})
        except CloudError:
            pass

    def control(self, action, page=None):
        state = load_state()
        token = state.get("token", "")
        pid = int(state.get("printer_id") or self.selected or 0)
        if not token or not pid:
            if page:
                page.post_message({"message": "Connect an account and select a printer first.", "error": True})
            return
        try:
            CloudApi(token).control(pid, action)
            if page:
                page.post_message({"message": f"Command '{action}' sent.", "error": False})
        except CloudError as exc:
            if page:
                page.post_message({"message": str(exc), "error": True})

    def _send_print(self, params, update_fn, cancel_fn, start=True):
        state = load_state()
        if not state.get("token"):
            return -7002
        try:
            printer_id = int(getattr(params, "dev_id", "") or 0)
        except (TypeError, ValueError):
            printer_id = 0
        if not printer_id:
            printer_id = int(state.get("printer_id") or self.selected or 0)
        if not printer_id:
            return -7002
        if printer_id != self.selected:
            self.select(printer_id)
        path, tmp = extract_gcode(params.filename, getattr(params, "plate_index", 0))
        try:
            CloudApi(state["token"]).upload_and_print(
                printer_id,
                path,
                start,
                lambda p, m: update_fn(1, p, m) if update_fn else None,
            )
            return 0
        except CloudError:
            return -1
        finally:
            if tmp:
                try:
                    tmp.unlink()
                except OSError:
                    pass

    def start_local_print(self, params, update_fn, cancel_fn):
        return self._send_print(params, update_fn, cancel_fn)

    def start_local_print_with_record(self, params, update_fn, cancel_fn, wait_fn):
        # Force OrcaSlicer onto its cloud-print path; otherwise it may make a
        # speculative LAN attempt and ask for the target printer twice.
        return -7010

    def start_send_gcode_to_sdcard(self, params, update_fn, cancel_fn, wait_fn):
        return self._send_print(params, update_fn, cancel_fn, start=False)

    def start_print(self, params, update_fn, cancel_fn, wait_fn):
        return self._send_print(params, update_fn, cancel_fn)

    def start_sdcard_print(self, params, update_fn, cancel_fn):
        return self._send_print(params, update_fn, cancel_fn)

    def send_message(self, *args): return 0
    def send_message_to_printer(self, *args): return 0


@orca.plugin
class AnySharikPlugin(orca.base):
    def register_capabilities(self):
        browser_paths = [shutil.which(name) for name in ("msedge.exe", "chrome.exe")]
        if sys.platform == "win32":
            browser_paths.extend(
                str(path)
                for root in (os.environ.get("PROGRAMFILES(X86)", ""), os.environ.get("PROGRAMFILES", ""))
                for path in (
                    Path(root) / "Microsoft/Edge/Application/msedge.exe",
                    Path(root) / "Google/Chrome/Application/chrome.exe",
                )
                if root and path.is_file()
            )
        browser_paths = list(dict.fromkeys(path for path in browser_paths if path))
        profile = LOGIN_PROFILE_DIR
        format_cmd = subprocess.list2cmdline if sys.platform == "win32" else shlex.join
        process_commands = [format_cmd(_login_browser_command(path, profile)) for path in browser_paths]
        orca.request_permissions(
            network_http=["https://cloud-universe.anycubic.com", "https://*.amazonaws.com"],
            network_socket=["mqtt-universe.anycubic.com", "('127.0.0.1', 19223)"],
            process=process_commands,
            fs_readwrite=list(dict.fromkeys([str(ROOT / "*"), str(DATA_DIR / "*")])),
            threading=True,
        )
        orca.register_capability(CloudAgent)
        orca.register_capability(CloudPage)
