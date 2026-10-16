"""Offline regression tests. All keys, addresses and credentials are synthetic."""

import base64
import importlib
import json
from pathlib import Path
import sys
import types
import unittest

from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = "acer_test_package"
package = types.ModuleType(PACKAGE)
package.__path__ = [str(ROOT / "custom_components" / "acer_predator_connect")]
sys.modules[PACKAGE] = package
protocol = importlib.import_module(PACKAGE + ".protocol")
client = importlib.import_module(PACKAGE + ".client")

MANAGER = "02:00:00:00:00:01"
TARGET = "02:00:00:00:00:02"
OTHER = "02:00:00:00:00:03"
PRIVATE = rsa.generate_private_key(public_exponent=65537, key_size=1024)
PUBLIC = PRIVATE.public_key()


def private_reply(data):
    raw = json.dumps(data, separators=(",", ":")).encode()
    size = (PUBLIC.key_size + 7) // 8
    numbers = PRIVATE.private_numbers()
    blocks = []
    for offset in range(0, len(raw), size - 11):
        chunk = raw[offset:offset + size - 11]
        block = b"\x00\x01" + b"\xff" * (size - len(chunk) - 3) + b"\x00" + chunk
        blocks.append(pow(int.from_bytes(block, "big"), numbers.d, numbers.public_numbers.n).to_bytes(size, "big"))
    return base64.b64encode(b"".join(blocks))


class Firmware:
    def __init__(self):
        self.calls = []
        self.blocked = False
        self.next_error = None
        self.manager_present = True
        self.target_present = True
        self.accept_write = True
        self.disconnect_write = False
        self.disappear_on_unblock = False

    def __call__(self, body, headers):
        cipher = base64.b64decode(body["enData"])
        size = PUBLIC.key_size // 8
        raw = b"".join(PRIVATE.decrypt(cipher[i:i + size], padding.PKCS1v15()) for i in range(0, len(cipher), size))
        data = json.loads(raw)
        self.calls.append((data, dict(headers)))
        if self.next_error is not None:
            result, self.next_error = self.next_error, None
            return private_reply({"result": result})
        action = data["action"]
        if action == "login_web":
            self.assert_login(data, headers)
            return private_reply({"result": 0, "accesstoken": "test-session-token"})
        if action == "set_block_device":
            if self.disconnect_write:
                raise client.RouterError("Simulated connection loss")
            if self.accept_write:
                self.blocked = data["enable"]
                if not self.blocked and self.disappear_on_unblock:
                    self.target_present = False
            return private_reply({"result": 0})
        rows = [{"Name": "Test management host", "Mac": MANAGER, "Ip": "192.0.2.10"}] if self.manager_present else []
        blocked = []
        if self.target_present:
            (blocked if self.blocked else rows).append({"Name": "Test tablet", "Mac": TARGET, "Ip": "192.0.2.20"})
        return private_reply({"result": 0, "ConnectedDevicesList": rows, "BlockedDevicesList": blocked, "clientIpAddress": "192.0.2.10|2001:db8::10"})

    @staticmethod
    def assert_login(data, headers):
        assert len(data["aesLocalRandomKey"]) == 64
        assert "localSystemTime" not in data
        assert "Authorization" not in headers


class ProtocolTests(unittest.TestCase):
    def test_router_public_key_is_valid(self):
        self.assertEqual(protocol.load_public_key().key_size, 512)
        self.assertTrue(protocol.encode_request({"action": "test"}, protocol.load_public_key()))

    def test_cryptojs_reference_vectors(self):
        vectors = json.loads((ROOT / "tests/cryptojs_vectors.json").read_text())
        self.assertIn(64, {len(v["key"]) for v in vectors})
        for vector in vectors:
            with self.subTest(key_size=len(vector["key"]), text=vector["text"]):
                result = protocol.cryptojs_cbc_encrypt(vector["text"].encode(), vector["key"].encode())
                self.assertEqual(base64.b64encode(result).decode(), vector["cipher"])

    def test_standard_aes_matches_openssl(self):
        for size in (16, 24, 32):
            key = bytes(range(size))
            text = b"independent standard AES verification"
            pad = 16 - len(text) % 16
            encryptor = Cipher(algorithms.AES(key), modes.CBC(key[:16])).encryptor()
            reference = encryptor.update(text + bytes([pad]) * pad) + encryptor.finalize()
            self.assertEqual(protocol.cryptojs_cbc_encrypt(text, key), reference)

    def test_rsa_request_multiblock_unicode_roundtrip(self):
        original = {"name": "Test żółć", "value": "x" * 500}
        cipher = base64.b64decode(protocol.encode_request(original, PUBLIC))
        size = PUBLIC.key_size // 8
        plain = b"".join(PRIVATE.decrypt(cipher[i:i + size], padding.PKCS1v15()) for i in range(0, len(cipher), size))
        self.assertEqual(json.loads(plain), original)

    def test_response_recovers_multiple_blocks(self):
        original = {"result": 0, "long": "x" * 500}
        self.assertEqual(protocol.decode_response(private_reply(original), PUBLIC), original)

    def test_invalid_response_rejected_without_payload_in_exception(self):
        for raw in (b"secret-not-base64", b"", base64.b64encode(b"a" * 128), private_reply({"result": True})):
            with self.assertRaises(protocol.ProtocolError) as error:
                protocol.decode_response(raw, PUBLIC)
            self.assertNotIn("secret", str(error.exception))

    def test_timestamp_token_matches_browser_transform(self):
        token, stamp = "test-session-token", 1792134000123
        combined = token + str(stamp)
        half = len(combined) // 2
        rotated = combined[half:] + combined[:half]
        result = protocol.make_access_token(token, stamp)
        self.assertEqual(result[0:10:2] + result[10:], rotated)
        self.assertTrue(result[1:10:2].endswith(str(len(token))))

    def test_timestamp_aes_is_base64(self):
        encoded = protocol.make_local_time(1792134000123, "a" * 64)
        self.assertEqual(len(base64.b64decode(encoded)), 16)


class ClientTests(unittest.TestCase):
    def setUp(self):
        self.firmware = Firmware()
        self.router = client.RouterClient("http://192.0.2.1:8080", "synthetic-password", [TARGET], transport=self.firmware, public_key=PUBLIC)

    def actions(self):
        return [call[0]["action"] for call in self.firmware.calls]

    def test_login_and_request_authentication(self):
        snapshot = self.router.get_devices()
        self.assertEqual(snapshot.protected_macs, {MANAGER})
        self.assertFalse(snapshot.devices[TARGET].blocked)
        request, headers = self.firmware.calls[-1]
        self.assertIn("accesstoken", request)
        self.assertIn("localSystemTime", request)
        self.assertIn("Authorization", headers)
        self.assertNotEqual(headers["Authorization"], "test-session-token")
        self.assertNotIn("loginpwd", request)

    def test_block_then_unblock_are_verified(self):
        self.assertTrue(self.router.set_blocked(TARGET, True).devices[TARGET].blocked)
        self.assertFalse(self.router.set_blocked(TARGET, False).devices[TARGET].blocked)
        writes = [call[0] for call in self.firmware.calls if call[0]["action"] == "set_block_device"]
        self.assertEqual([write["enable"] for write in writes], [True, False])
        self.assertEqual([write["mac"] for write in writes], [TARGET, TARGET])
        self.assertEqual(writes[0]["device_name"], "Test tablet")

    def test_no_write_when_already_in_desired_state(self):
        self.router.set_blocked(TARGET, False)
        self.assertNotIn("set_block_device", self.actions())

    def test_device_outside_allowlist_never_contacts_router(self):
        with self.assertRaises(client.SafetyError):
            self.router.set_blocked(OTHER, True)
        self.assertEqual(self.firmware.calls, [])

    def test_management_client_cannot_be_blocked_even_if_selected(self):
        self.router.allowed_macs = frozenset([MANAGER])
        with self.assertRaises(client.SafetyError):
            self.router.set_blocked(MANAGER, True)
        self.assertNotIn("set_block_device", self.actions())

    def test_unknown_management_row_prevents_blocking(self):
        self.firmware.manager_present = False
        with self.assertRaises(client.SafetyError):
            self.router.set_blocked(TARGET, True)
        self.assertNotIn("set_block_device", self.actions())

    def test_protected_mac_never_contacts_router(self):
        self.router.protected_macs = frozenset([TARGET])
        with self.assertRaises(client.SafetyError):
            self.router.set_blocked(TARGET, True)
        self.assertEqual(self.firmware.calls, [])

    def test_missing_device_is_not_assumed_unblocked(self):
        self.firmware.target_present = False
        with self.assertRaises(client.SafetyError):
            self.router.set_blocked(TARGET, True)
        self.assertNotIn("set_block_device", self.actions())

    def test_timeout_does_not_replay_write(self):
        self.firmware.disconnect_write = True
        with self.assertRaises(client.RouterError):
            self.router.set_blocked(TARGET, True)
        self.assertEqual(self.actions().count("set_block_device"), 1)

    def test_false_success_is_detected(self):
        self.firmware.accept_write = False
        with self.assertRaises(client.RouterError):
            self.router.set_blocked(TARGET, True)

    def test_device_can_disappear_after_verified_unblock(self):
        self.firmware.blocked = True
        self.firmware.disappear_on_unblock = True
        self.assertNotIn(TARGET, self.router.set_blocked(TARGET, False).devices)

    def test_bad_password_stops_poll_login_attempts(self):
        self.firmware.next_error = 55
        for _ in range(3):
            with self.assertRaises(client.AuthenticationError):
                self.router.get_devices()
        self.assertEqual(self.actions(), ["login_web"])

    def test_expired_session_invalidates_and_does_not_replay(self):
        self.router.get_devices()
        self.firmware.next_error = 66
        with self.assertRaises(client.SessionError):
            self.router.set_blocked(TARGET, True)
        with self.assertRaises(client.SessionError):
            self.router.get_devices()
        self.assertEqual(self.actions().count("login_web"), 1)
        self.assertNotIn("set_block_device", self.actions())

    def test_snapshot_missing_lists_is_error(self):
        with self.assertRaises(protocol.ProtocolError):
            client.parse_snapshot({"result": 0})

    def test_close_discards_credentials_and_session(self):
        self.router.get_devices()
        self.router.close()
        self.assertEqual((self.router._token, self.router._password, self.router._session_key), ("", "", ""))

    def test_ipv6_management_client_is_protected(self):
        snapshot = client.parse_snapshot({"ConnectedDevicesList": [{"Mac": MANAGER, "Name": "Test", "Ip": "", "Ipv6": "2001:db8::10"}], "BlockedDevicesList": [], "clientIpAddress": "2001:db8::10|"})
        self.assertEqual(snapshot.protected_macs, {MANAGER})

    def test_url_rejects_credentials_redirect_paths_and_invalid_port(self):
        for url in ("http://user:pass@example.test", "ftp://example.test", "http://example.test/a", "http://example.test?token=x", "http://example.test:99999"):
            with self.assertRaises(ValueError):
                client.normalize_url(url)

    def test_mac_normalization_and_rejection(self):
        self.assertEqual(client.normalize_mac("02-00-00-00-00-02"), TARGET)
        for value in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00", "01:00:00:00:00:01", "bad"):
            with self.assertRaises(ValueError):
                client.normalize_mac(value)


if __name__ == "__main__":
    unittest.main()
