"""X5 firmware wire format. No live credentials or captured session data."""

from __future__ import annotations

import base64
import json
import secrets
import string

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

# Public encryption key shipped by the X5 web application (not a credential).
PUBLIC_KEY = b"""-----BEGIN PUBLIC KEY-----
MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBALqkaC1tYKsRcUdmz607MG6HNOhVNyPB
hFPAez2bJJJtaZxA3PWJnohwBJCMth+PRq33OJoebBpD2rJGRyW1hJUCAwEAAQ==
-----END PUBLIC KEY-----
"""


class ProtocolError(Exception):
    """Unexpected data; messages must never contain wire payloads."""


def load_public_key(pem: bytes = PUBLIC_KEY) -> rsa.RSAPublicKey:
    key = serialization.load_pem_public_key(pem)
    if not isinstance(key, rsa.RSAPublicKey):
        raise ProtocolError("Unsupported router public key")
    return key


def encode_request(data: dict, key: rsa.RSAPublicKey) -> str:
    """NodeRSA-compatible PKCS#1 v1.5 chunked encryption."""
    raw = json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode()
    chunk_size = (key.key_size + 7) // 8 - 11
    return base64.b64encode(b"".join(
        key.encrypt(raw[i:i + chunk_size], padding.PKCS1v15())
        for i in range(0, len(raw), chunk_size)
    )).decode("ascii")


def decode_response(raw: bytes, key: rsa.RSAPublicKey) -> dict:
    """Recover the firmware's private-encrypt/public-decrypt response blocks.

    This is the vendor protocol, not confidential encryption of the response.
    Validate the block-type-1 padding before accepting any decoded JSON.
    """
    try:
        text = raw.decode("ascii").strip()
        if text.startswith('"'):
            text = json.loads(text)
        cipher = base64.b64decode(text, validate=True)
        size = (key.key_size + 7) // 8
        if not cipher or len(cipher) % size:
            raise ValueError
        numbers = key.public_numbers()
        plain = bytearray()
        for offset in range(0, len(cipher), size):
            value = int.from_bytes(cipher[offset:offset + size], "big")
            if value >= numbers.n:
                raise ValueError
            block = pow(value, numbers.e, numbers.n).to_bytes(size, "big")
            end = block.find(b"\0", 2)
            if block[:2] != b"\0\1" or end < 10 or block[2:end] != b"\xff" * (end - 2):
                raise ValueError
            plain.extend(block[end + 1:])
        result = json.loads(plain.decode("utf-8"))
        if not isinstance(result, dict) or type(result.get("result")) is not int:
            raise ValueError
        return result
    except (ValueError, TypeError, UnicodeError, OverflowError):
        raise ProtocolError("Invalid encrypted router response") from None


def make_access_token(token: str, timestamp_ms: int) -> str:
    """Firmware 95ab.h: rotate token+time and interleave length marker."""
    combined = token + str(timestamp_ms)
    half = len(combined) // 2
    rotated = combined[half:] + combined[:half]
    length = str(len(token))
    marker = "".join(secrets.choice(string.ascii_lowercase) for _ in range(max(0, 5 - len(length)))) + length
    return "".join(
        (rotated[i] if i < len(rotated) else "") + (marker[i] if i < len(marker) else "")
        for i in range(max(len(rotated), len(marker)))
    )


def _mul(a: int, b: int) -> int:
    out = 0
    while b:
        if b & 1:
            out ^= a
        a = ((a << 1) ^ (0x11B if a & 0x80 else 0)) & 255
        b >>= 1
    return out


def _sbox_value(value: int) -> int:
    inverse = 0
    if value:
        inverse, base, exponent = 1, value, 254
        while exponent:
            if exponent & 1:
                inverse = _mul(inverse, base)
            base = _mul(base, base)
            exponent >>= 1
    return inverse ^ ((inverse << 1 | inverse >> 7) & 255) ^ ((inverse << 2 | inverse >> 6) & 255) ^ ((inverse << 3 | inverse >> 5) & 255) ^ ((inverse << 4 | inverse >> 4) & 255) ^ 0x63


_SBOX = tuple(_sbox_value(i) for i in range(256))


def cryptojs_cbc_encrypt(plain: bytes, key: bytes) -> bytes:
    """Reproduce CryptoJS AES-CBC, including its nonstandard 64-byte key.

    X5 passes a 64-character UTF-8 key directly to CryptoJS (Nk=16,
    rounds=22), with that same WordArray as IV. Standard AES libraries
    reject this key length. The wire-compatible expansion is isolated here;
    it must not be used to design any new cryptographic protocol.
    """
    if len(key) not in (16, 24, 32, 64):
        raise ProtocolError("Unsupported session key length")
    nk = len(key) // 4
    rounds = nk + 6
    words = [list(key[i:i + 4]) for i in range(0, len(key), 4)]
    rcon = 1
    for i in range(nk, 4 * (rounds + 1)):
        temp = words[i - 1].copy()
        if i % nk == 0:
            temp = [_SBOX[v] for v in temp[1:] + temp[:1]]
            temp[0] ^= rcon
            rcon = _mul(rcon, 2)
        elif nk > 6 and i % nk == 4:
            temp = [_SBOX[v] for v in temp]
        words.append([a ^ b for a, b in zip(words[i - nk], temp)])
    round_keys = [sum(words[i:i + 4], []) for i in range(0, len(words), 4)]
    pad_size = 16 - len(plain) % 16
    plain += bytes([pad_size]) * pad_size
    previous = key[:16]
    output = bytearray()
    for offset in range(0, len(plain), 16):
        state = [a ^ b ^ c for a, b, c in zip(plain[offset:offset + 16], previous, round_keys[0])]
        for round_number in range(1, rounds + 1):
            state = [_SBOX[v] for v in state]
            state = [state[4 * ((column + row) % 4) + row] for column in range(4) for row in range(4)]
            if round_number != rounds:
                mixed = []
                for column in range(4):
                    a, b, c, d = state[4 * column:4 * column + 4]
                    mixed.extend((
                        _mul(a, 2) ^ _mul(b, 3) ^ c ^ d,
                        a ^ _mul(b, 2) ^ _mul(c, 3) ^ d,
                        a ^ b ^ _mul(c, 2) ^ _mul(d, 3),
                        _mul(a, 3) ^ b ^ c ^ _mul(d, 2),
                    ))
                state = mixed
            state = [a ^ b for a, b in zip(state, round_keys[round_number])]
        previous = bytes(state)
        output.extend(previous)
    return bytes(output)


def make_local_time(timestamp_ms: int, session_key: str) -> str:
    return base64.b64encode(cryptojs_cbc_encrypt(str(timestamp_ms).encode(), session_key.encode())).decode("ascii")
