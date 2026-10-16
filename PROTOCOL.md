# X5 wire protocol

This document contains no captured credentials, tokens or cookies. It records a static-code derivation, not a packet capture or a guarantee of compatibility with other firmware.

## Endpoint

All documented actions use `POST <router origin>/cgi-bin/web_cgi`. The web application internally names requests `/web_cgi/<action>`, moves the final path element into `action`, then uses its `/cgi-bin` base URL.

On-wire JSON contains one field, `enData`. Its value is base64 of concatenated RSA PKCS#1 v1.5 encrypted blocks. The public key in protocol.py is public material shipped in the vendor UI, not a credential. The module uses NodeRSA with `encryptionScheme: "pkcs1"`.

## Session

Login plaintext JSON contains `action: "login_web"`, `loginpwd` and a client-generated 64-character `aesLocalRandomKey`. It has no `localSystemTime` and no token on a fresh session. A successful reply contains `result: 0` and `accesstoken`.

The web response interceptor uses NodeRSA `decryptPublic`, then parses JSON. These are private-key-encrypted/type-1-padded RSA blocks, not confidential responses. The interceptor copies the entire decoded object into its `.data` property. The wire object itself is flat; the client must not require a nested `data` envelope.

For subsequent requests, the web app transforms the session token with the current epoch time in milliseconds. It concatenates token+timestamp, rotates the two halves, and interleaves a five-character token-length marker into the beginning (the marker is padded with random lowercase letters). The transformed value appears in `Authorization` and in the plaintext `accesstoken` field. Separate calls may produce different padding characters. There is no Bearer prefix.

`localSystemTime` is CryptoJS AES-CBC/PKCS7 of the timestamp string. The app passes `Utf8.parse(aesLocalRandomKey)` as both key and IV. With a 64-byte key CryptoJS expands 16 key words into 22 rounds; this is not standard AES-128/192/256. Only the first four IV words participate in CBC. The isolated compatibility routine in protocol.py reproduces this; it is verified against independent CryptoJS 4.2.0 vectors for 16, 24, 32 and 64-byte keys. It is not a recommended cipher for new designs.

Cookies, if sent by the router, are retained in a private in-memory CookieJar. Whether the tested firmware additionally requires them has not been established by a login test of this implementation.

## Block-list actions

Plaintext write fields, before encryption and without real secret values:

```json
{
  "action": "set_block_device",
  "device_name": "Test device",
  "mac": "02:00:00:00:00:02",
  "enable": true,
  "accesstoken": "<per-request transformation>",
  "localSystemTime": "<encrypted timestamp>"
}
```

`true` adds the MAC to the block list; `false` removes it. Read action `get_connecteddevices` returns `ConnectedDevicesList`, `BlockedDevicesList` and `clientIpAddress`. The latter can contain multiple IPs separated by `|`. The UI protects its own management connection by comparing these addresses against both `Ip` and `Ipv6`.

## Result codes observed in source

| Code | Meaning |
| --- | --- |
| 0 | success |
| 1 | action timeout |
| 22 | brute-force/login lockout |
| 33 | single-user/session conflict |
| 44 | token error |
| 55 | password error |
| 66 | token expired |
| 77 | decryption error |

The existence of code 33 alone does not establish how multiple sessions behave in practice. No timeout, lifetime or concurrent-session guarantee is inferred.
