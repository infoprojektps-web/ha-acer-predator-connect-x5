"""Serialized local X5 client, used only from Home Assistant's executor."""

from __future__ import annotations

from dataclasses import dataclass
from http.cookiejar import CookieJar
import ipaddress
import json
import re
import secrets
import string
import threading
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPCookieProcessor, HTTPRedirectHandler, Request, build_opener

from .protocol import ProtocolError, decode_response, encode_request, load_public_key, make_access_token, make_local_time


class RouterError(Exception):
    """Sanitized router error."""


class AuthenticationError(RouterError):
    """Credentials require user attention."""


class SessionError(RouterError):
    """Session was invalidated; never replay a write automatically."""


class SafetyError(RouterError):
    """A command would violate the configured device boundary."""


def normalize_url(value: str) -> str:
    try:
        parsed = urlsplit(value.strip() if "://" in value else "http://" + value.strip())
        if parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.username or parsed.password or parsed.path not in ("", "/") or parsed.query or parsed.fragment:
            raise ValueError
        port = parsed.port
        host = parsed.hostname.lower()
        if ":" in host:
            host = f"[{host}]"
        if port is not None:
            host += f":{port}"
        return f"{parsed.scheme}://{host}"
    except ValueError:
        raise ValueError("Enter only the router HTTP(S) address and port") from None


def normalize_mac(value: str) -> str:
    compact = re.sub(r"[:-]", "", value.strip()).lower()
    if not re.fullmatch(r"[0-9a-f]{12}", compact) or compact in ("000000000000", "ffffffffffff") or int(compact[:2], 16) & 1:
        raise ValueError("Invalid unicast MAC address")
    return ":".join(compact[i:i + 2] for i in range(0, 12, 2))


def _same_ip(left: str, right: str) -> bool:
    try:
        return ipaddress.ip_address(left) == ipaddress.ip_address(right)
    except ValueError:
        return False


@dataclass(frozen=True)
class Device:
    mac: str
    name: str
    blocked: bool
    ip: str = ""
    ipv6: str = ""


@dataclass(frozen=True)
class Snapshot:
    devices: dict[str, Device]
    client_ip: str

    @property
    def protected_macs(self) -> set[str]:
        addresses = self.client_ip.split("|")
        return {mac for mac, device in self.devices.items() if any(
            _same_ip(address, caller) for address in (device.ip, device.ipv6) for caller in addresses
        )}


def parse_snapshot(data: dict) -> Snapshot:
    try:
        connected = data["ConnectedDevicesList"]
        blocked = data["BlockedDevicesList"]
        client_ip = data["clientIpAddress"]
        if not isinstance(connected, list) or not isinstance(blocked, list) or not isinstance(client_ip, str):
            raise ValueError
        for address in client_ip.split("|"):
            if address:
                ipaddress.ip_address(address)
        if not client_ip.strip("|"):
            raise ValueError
        devices = {}
        for rows, is_blocked in ((connected, False), (blocked, True)):
            for row in rows:
                mac = normalize_mac(row["Mac"])
                old = devices.get(mac)
                # Firmware uses Ip in connected-device rows. Accept known aliases
                # defensively, but never invent the management client's address.
                ip = row.get("Ip", row.get("IP", row.get("IpAddress", old.ip if old else "")))
                name = row.get("Name") or (old.name if old else mac)
                ipv6 = row.get("Ipv6", old.ipv6 if old else "") or ""
                if not isinstance(ip, str) or not isinstance(name, str) or not isinstance(ipv6, str):
                    raise ValueError
                devices[mac] = Device(mac, name, is_blocked, ip, ipv6)
        return Snapshot(devices, client_ip)
    except (KeyError, TypeError, ValueError):
        raise ProtocolError("Invalid connected-device response") from None


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise RouterError("Router redirects are not allowed")


class RouterClient:
    """One in-memory session; no credentials are logged or exported."""

    def __init__(self, url: str, password: str, allowed_macs=(), protected_macs=(), *, transport=None, public_key=None):
        self.url = normalize_url(url)
        self._password = password
        self.allowed_macs = frozenset(normalize_mac(mac) for mac in allowed_macs)
        self.protected_macs = frozenset(normalize_mac(mac) for mac in protected_macs)
        self._key = public_key if public_key is not None else load_public_key()
        self._token = ""
        self._session_key = ""
        self._login_after = 0.0
        self._auth_failed = False
        self._lock = threading.RLock()
        self._opener = build_opener(_NoRedirect(), HTTPCookieProcessor(CookieJar()))
        self._transport = transport or self._http_post

    def _http_post(self, payload: dict, headers: dict) -> bytes:
        request = Request(self.url + "/cgi-bin/web_cgi", data=json.dumps(payload, separators=(",", ":")).encode(), headers={"Content-Type": "application/json", "Cache-Control": "no-store", **headers}, method="POST")
        try:
            with self._opener.open(request, timeout=20) as response:
                data = response.read(2_000_001)
                if len(data) > 2_000_000:
                    raise RouterError("Router response exceeds limit")
                return data
        except HTTPError as err:
            # Retain only the numeric status, never the response or headers.
            raise RouterError(f"Router HTTP error {err.code}") from None
        except (TimeoutError, OSError, URLError):
            raise RouterError("Router connection failed") from None

    def close(self) -> None:
        with self._lock:
            self._token = self._session_key = self._password = ""
            for handler in self._opener.handlers:
                if isinstance(handler, HTTPCookieProcessor):
                    handler.cookiejar.clear()

    def _call(self, action: str, data: dict | None = None) -> dict:
        payload = dict(data or {})
        payload["action"] = action
        headers = {}
        if self._token:
            payload["accesstoken"] = make_access_token(self._token, int(time.time() * 1000))
            headers["Authorization"] = make_access_token(self._token, int(time.time() * 1000))
        if action != "login_web":
            payload["localSystemTime"] = make_local_time(int(time.time() * 1000), self._session_key)
        response = decode_response(self._transport({"enData": encode_request(payload, self._key)}, headers), self._key)
        code = response["result"]
        if code == 0:
            # Firmware replies are flat: the web interceptor copies the whole
            # response to response.data. Do not assume a nested data envelope.
            return response
        if code in (22, 55):
            self._auth_failed = True
            self._token = self._session_key = ""
            raise AuthenticationError("Router rejected authentication; reconfigure credentials")
        if code in (33, 44, 66, 77):
            self._token = self._session_key = ""
            self._login_after = max(self._login_after, time.monotonic() + (300 if code == 33 else 60))
            reason = {33: "another login conflicts with this session", 44: "access token rejected", 66: "session expired", 77: "router could not decrypt the request"}[code]
            raise SessionError(f"Router result {code}: {reason}; waiting before login, command was not retried")
        raise RouterError(f"Router returned result code {code}")

    def _ensure_session(self):
        if self._auth_failed:
            raise AuthenticationError("Reconfigure router credentials before retrying")
        if self._token:
            return
        if time.monotonic() < self._login_after:
            raise SessionError("Router login cooldown is active")
        self._login_after = time.monotonic() + 60
        session_key = "".join(secrets.choice(string.ascii_lowercase + string.digits) for _ in range(64))
        response = self._call("login_web", {"loginpwd": self._password, "aesLocalRandomKey": session_key})
        token = response.get("accesstoken")
        if not isinstance(token, str) or not token:
            raise ProtocolError("Router login did not return an access token")
        self._token, self._session_key = token, session_key

    def get_devices(self) -> Snapshot:
        with self._lock:
            self._ensure_session()
            return parse_snapshot(self._call("get_connecteddevices"))

    def set_blocked(self, mac: str, blocked: bool) -> Snapshot:
        with self._lock:
            mac = normalize_mac(mac)
            if type(blocked) is not bool or mac not in self.allowed_macs or mac in self.protected_macs:
                raise SafetyError("Device is outside the configured control list")
            before = self.get_devices()
            # Without the caller's identified row, blocking cannot be proven safe.
            if blocked and (not before.protected_macs or mac in before.protected_macs):
                raise SafetyError("Cannot block the management client or an unidentified management connection")
            device = before.devices.get(mac)
            if device is None:
                raise SafetyError("Device is absent from the router lists; command was not sent")
            if device.blocked == blocked:
                return before
            self._call("set_block_device", {"device_name": device.name, "mac": mac, "enable": blocked})
            after = self.get_devices()
            # An unblocked device may disappear while it reconnects.
            actual_blocked = mac in after.devices and after.devices[mac].blocked
            if actual_blocked != blocked:
                raise RouterError("Router did not confirm the requested block-list state")
            return after
