"""Minimal MQTT 3.1.1 client for Anycubic Cloud telemetry."""
from __future__ import annotations
import base64, hashlib, json, os, socket, ssl, struct, threading

BROKER = "mqtt-universe.anycubic.com"
_BROKER_KEY_TEXT = (
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAn2Kpx1AzT2Df1kf1MImT"
    "dqCgq5JDGdFTMw/Mx4TN6+oYUQyVUcSs8j+EPFlaCja7t9nXoNLrfS26PwdDzJEt"
    "+wVDCdoWvNxuie+0w2Zk8lpRHn76z+waTON3OLaneWe0xINNMtAqmuV0w2HSoNm"
    "vrLqJ7iO8moNeUO92fHUAnwkrNCtKeWpB80DLdVJBZRUeiL7KKH+7ud343KcfWLp"
    "C5cj9RyZYVCEShwY9/tPN40Jg+jk43JiFbu5ruAMPuUWn5Iy/6ENnyBKk21uYxED"
    "3y/OKNVJyl8+fZMgZriCzIP2YsU52O7nbr2iWytA1a1ZTIyiUPpGYQSYY8PSV7vw"
    "xwIDAQAB"
)
_BROKER_KEY = base64.b64decode(_BROKER_KEY_TEXT + "=" * (-len(_BROKER_KEY_TEXT) % 4))

_MODULUS_MARKER = b"\x02\x82\x01\x01\x00"

def _rsa_encrypt(message):
    # The embedded key is the public broker key; no private material is stored.
    marker = _BROKER_KEY.find(_MODULUS_MARKER)
    if marker < 0:
        raise ValueError("Invalid broker public key")
    n = int.from_bytes(_BROKER_KEY[marker + len(_MODULUS_MARKER):marker + len(_MODULUS_MARKER) + 256], "big")
    e = 65537
    ps_length = 256 - len(message) - 3
    if ps_length < 8:
        raise ValueError("MQTT credential payload is too large")
    block = b"\x00\x02"
    while len(block) < ps_length + 2:
        block += os.urandom(1).replace(b"\x00", b"\x01")
    encoded = block + b"\x00" + message
    return pow(int.from_bytes(encoded, "big"), e, n).to_bytes(256, "big")

def _s(value):
    raw = value.encode(); return struct.pack("!H", len(raw)) + raw

def _remaining(n):
    out = bytearray()
    while True:
        d, n = n % 128, n // 128
        out.append(d | (128 if n else 0))
        if not n: return bytes(out)

def _packet(sock):
    head = sock.recv(1)
    if not head:
        raise ConnectionError("MQTT connection closed")
    multiplier = 1
    length = 0
    while True:
        raw = sock.recv(1)
        if not raw:
            raise ConnectionError("MQTT connection closed")
        byte = raw[0]
        length += (byte & 127) * multiplier
        if not byte & 128:
            break
        multiplier *= 128
    data = b""
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            raise ConnectionError("MQTT connection closed")
        data += chunk
    return head[0] >> 4, data

def _connect(client_id, user, password):
    body = _s("MQTT") + bytes([4, 0xC2]) + struct.pack("!H", 45) + _s(client_id) + _s(user) + _s(password)
    return b"\x10" + _remaining(len(body)) + body

class MqttTelemetry:
    def __init__(self, token, email, machine_type, printer_key, on_state):
        self.token, self.email = token, email
        self.machine_type, self.printer_key, self.on_state = machine_type, printer_key, on_state
        self.stop_event = threading.Event(); self.thread = None

    def start(self):
        if self.thread and self.thread.is_alive(): return
        self.stop_event.clear(); self.thread = threading.Thread(target=self._run, daemon=True); self.thread.start()

    def stop(self): self.stop_event.set()

    def _run(self):
        while not self.stop_event.is_set():
            sock = None
            try:
                raw = self.token.encode()
                encrypted = base64.b64encode(_rsa_encrypt(raw)).decode()
                client = "web_" + hashlib.md5(raw).hexdigest()
                user = "user|web|" + self.email + "|" + hashlib.md5((client + encrypted + client).encode()).hexdigest()
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                sock = ctx.wrap_socket(socket.create_connection((BROKER, 8883), timeout=10), server_hostname=BROKER)
                sock.sendall(_connect(client, user, encrypted))
                kind, connack = _packet(sock)
                if kind != 2 or len(connack) < 2 or connack[1] != 0:
                    raise ConnectionError("MQTT broker rejected the connection")
                topic = f"anycubic/anycubicCloud/v1/+/public/{self.machine_type}/{self.printer_key}/#"
                body = struct.pack("!H", 1) + _s(topic) + b"\0"
                sock.sendall(b"\x82" + _remaining(len(body)) + body)
                sock.settimeout(5)
                while not self.stop_event.is_set():
                    try:
                        kind, data = _packet(sock)
                    except socket.timeout:
                        sock.sendall(b"\xc0\0")
                        continue
                    if kind != 3:
                        continue
                    length = struct.unpack("!H", data[:2])[0]
                    payload = data[2 + length:]
                    try:
                        self.on_state(json.loads(payload.decode()))
                    except (ValueError, UnicodeError):
                        pass
            except (OSError, ConnectionError):
                self.stop_event.wait(5)
            finally:
                if sock is not None:
                    try:
                        sock.close()
                    except OSError:
                        pass
