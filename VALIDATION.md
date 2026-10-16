# Validation scope — 0.1.1

## Completed locally

- 29 offline unit tests for the client and cryptographic wire format, including safe error reporting and session recovery after cooldown.
- CryptoJS 4.2.0 reference vectors, including the vendor's nonstandard 64-byte key behavior.
- An independent OpenSSL-backed AES check for all three standard AES key sizes.
- Multi-block RSA request round trips, Unicode payloads, private-encrypt/public-decrypt responses and malformed-response rejection.
- Simulated firmware verifies block/unblock direction, fresh-state checks, read-after-write verification and no automatic write replay.
- Safety tests cover allowlist, explicit protected MACs, the management connection (IPv4 and IPv6), absent devices and unidentified management connections.
- Wrong-password suppression, session-expiry cooldown and in-memory credential cleanup.
- Python source compilation.

## Not yet established

- A full block/unblock cycle from this integration on a physical X5.
- Whether cookies or additional request headers are required by a particular firmware.
- Router firmware coverage beyond the inspected UI build.

Live browser work during protocol research confirmed that the vendor panel could remove a test device from the block list and report an empty block list afterward. That does not validate this Python implementation end to end.

A user-provided Home Assistant 2026.10.1 snapshot confirms version 0.1.0 was installed, its config entry was loaded, and devices had been selected. All four configured switches were unavailable at capture time and the coordinator had logged read errors. The generic 0.1.0 error message does not establish the underlying cause. Version 0.1.1 removes the second login when opening options and preserves sanitized error details; recovery on the user's router still needs confirmation. The HA smoke script also checks active-session reuse and refusal of stale options data.

GitHub Actions runs offline tests and a Home Assistant import/schema/entity smoke check. Consult the actual Actions result before treating that check as passed. A green CI run does not replace the physical-router test.
