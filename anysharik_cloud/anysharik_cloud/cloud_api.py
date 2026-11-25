"""Small Anycubic Cloud REST client used by the AnySharik Orca plugin."""
from __future__ import annotations

import hashlib
import json
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path

ROOT = "https://cloud-universe.anycubic.com/p/p/workbench/api"
APP_ID = "f9b3528877c94d5c9c5af32245db46ef"
APP_SECRET = "0cf75926606049a3937f56b0373b99fb"


class CloudError(RuntimeError):
    pass


def _ssl_context():
    return ssl.create_default_context()


class CloudApi:
    def __init__(self, token: str = ""):
        self.token = token.strip()

    def _headers(self):
        now = str(int(time.time() * 1000))
        nonce = str(uuid.uuid4())
        sig = hashlib.md5((APP_ID + now + "1.0.0" + APP_SECRET + nonce + APP_ID).encode()).hexdigest()
        headers = {
            "User-Agent": "Mozilla/5.0 AnySharik",
            "Origin": "https://cloud-universe.anycubic.com",
            "Content-Type": "application/json",
            "XX-Device-Type": "web",
            "XX-Is-Cn": "2",
            "XX-Nonce": nonce,
            "XX-Signature": sig,
            "XX-Timestamp": now,
            "XX-Version": "1.0.0",
            "XX-LANGUAGE": "US",
        }
        if self.token:
            headers["XX-Token"] = self.token
        return headers

    def request(self, method: str, path: str, body=None, query=None):
        url = ROOT + path
        if query:
            url += "?" + urllib.parse.urlencode(query)
        data = None if body is None else json.dumps(body).encode()
        req = urllib.request.Request(url, data=data, headers=self._headers(), method=method)
        try:
            with urllib.request.urlopen(req, timeout=30, context=_ssl_context()) as response:
                result = json.loads(response.read().decode("utf-8", "replace"))
        except (OSError, ValueError) as exc:
            raise CloudError(f"Cloud request failed: {exc}") from exc
        if not isinstance(result, dict):
            raise CloudError("Cloud returned an invalid response")
        code = result.get("code")
        if code not in (None, 0, 1):
            raise CloudError(str(result.get("msg") or result.get("message") or f"Cloud error {code}"))
        return result

    def profile(self):
        return self.request("GET", "/user/profile/userInfo").get("data") or {}

    @classmethod
    def login_with_oauth_code(cls, code: str):
        """Exchange the official Anycubic User Center callback code for a Cloud token."""
        code = code.strip()
        if not code or len(code) > 2048:
            raise CloudError("Invalid Anycubic authorization code")
        client = cls()
        oauth = client.request("GET", "/v3/public/getoauthToken", query={"code": code}).get("data") or {}
        access_token = oauth.get("access_token")
        if not access_token:
            raise CloudError("Anycubic did not return an access token")
        result = client.request("POST", "/v3/public/loginWithAccessToken", {
            "access_token": access_token,
            "device_type": "web",
        }).get("data") or {}
        token = result.get("token")
        if not token:
            raise CloudError("Anycubic did not return a Cloud token")
        user = result.get("user") or {}
        return token, str(user.get("user_email") or user.get("user_nickname") or "")

    def printers(self):
        data = self.request("GET", "/work/printer/getPrinters").get("data") or []
        return [p for p in data if isinstance(p, dict)]

    def status(self, printer_id):
        return self.request("GET", "/v2/printer/info", query={"id": str(printer_id)}).get("data") or {}

    def project_id(self, printer_id):
        data = self.status(printer_id)
        project = data.get("project") if isinstance(data.get("project"), dict) else data
        return int(project.get("id") or project.get("project_id") or 0)

    def order(self, order_id, printer_id, project_id=0, settings=None):
        return self.request("POST", "/work/operation/sendOrder", {
            "order_id": order_id, "printer_id": int(printer_id), "project_id": int(project_id),
            "data": None, "ams_info": None, "settings": settings,
        })

    def upload_and_print(self, printer_id, path: Path, start=True, progress=None):
        size = path.stat().st_size
        lock = self.request("POST", "/v2/cloud_storage/lockStorageSpace", {
            "size": size, "name": path.name, "is_temp_file": int(start),
        }).get("data") or {}
        lock_id, upload_url = lock.get("id"), lock.get("preSignUrl")
        if not lock_id or not upload_url:
            raise CloudError("Cloud did not provide an upload URL")
        try:
            if progress: progress(10, "Uploading to Anycubic Cloud")
            data = path.read_bytes()
            req = urllib.request.Request(upload_url, data=data, method="PUT", headers={"Content-Length": str(len(data))})
            with urllib.request.urlopen(req, timeout=180, context=_ssl_context()):
                pass
            if progress: progress(85, "Registering file")
            file_data = self.request("POST", "/v2/profile/newUploadFile", {"user_lock_space_id": int(lock_id)}).get("data") or {}
            file_id = file_data.get("id")
            if not file_id:
                raise CloudError("Cloud did not register the uploaded file")
            if start:
                if progress: progress(95, "Starting print")
                self.request("POST", "/work/operation/sendOrder", {
                    "order_id": 1, "printer_id": int(printer_id), "project_id": 0,
                    "data": {"filetype": 0, "file_id": int(file_id), "is_delete_file": 1,
                             "project_type": 1, "task_settings": {"ai_detect": 0, "camera_timelapse": 0}},
                    "ams_info": None, "settings": None,
                })
            if progress: progress(100, "Done")
        except Exception:
            try:
                self.request("POST", "/v2/cloud_storage/unlockStorageSpace", {"id": int(lock_id), "is_delete_cos": 1})
            except Exception:
                pass
            raise

    def control(self, printer_id, action):
        ids = {"pause": 2, "resume": 3, "stop": 4}
        if action not in ids:
            raise CloudError("Unsupported printer action")
        return self.order(ids[action], printer_id, self.project_id(printer_id))
