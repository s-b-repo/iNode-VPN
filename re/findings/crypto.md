# H3C iNode SSL VPN Linux Client — Credential & Challenge Crypto / Encoding

Component KEY: **crypto**
Libraries analysed:
- `libs/libiNodeSslvpnPt.so` (SSL VPN auth state machine, login/challenge packet builders, SPA/zeroTrust)
- `libs/libInodeUtility.so` and `libs/libutility.so` (crypto primitives: AES, base64, MD5, TEA, CRC32, adler32)
- `libs/libskf_wrapper.so` + `libs/libskf_engine.so` (GM / SM2/SM3/SM4 via SKF UKey, OpenSSL engine)

---

## TL;DR — how the password is protected on the wire

**The SSL VPN password is NOT pre-encrypted, hashed, AES-encrypted, or base64-obfuscated by the client. It is sent essentially in cleartext (only URL-encoded / XML-escaped) inside the TLS tunnel.** Confidentiality relies entirely on TLS (and, for GM gateways, on TLCP/GMTLS with SM2/SM3/SM4 negotiated by the SKF engine at the TLS layer).

There is no client-side challenge-response (no HMAC/MD5/SM3 of `challenge+password`). The "challenge" flow is a **server-driven SMS / OTP** flow: the server sends a challenge, the user types the SMS/OTP code, and that code is sent back as cleartext XML fields over the same TLS tunnel.

The AES / TEA / fixed-key crypto found in the binaries is used for **local config/credential storage on disk** and for the optional **SPA "zeroTrust" knock packet**, *not* for protecting the login password on the wire.

---

## 1. Standard login — password is cleartext inside TLS

### 1a. Legacy V3 form login (`CHttpsAuth::buildSslAuthPacketV3`, HttpsAuth.cpp ~1700)
`x-www-form-urlencoded` POST, password URL-encoded only:

```
POST /svpn/vpnuser/login_submit.cgi HTTP/1.1\r\n
Accept: application/x-shockwave-flash, image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, */*\r\n
Referer: https://<host>:<port>/svpn/index.cgi\r\n
Accept-Language: zh-cn\r\n
Content-Type: application/x-www-form-urlencoded\r\n
UA-CPU: x86\r\n
Accept-Encoding: gzip, deflate\r\n
User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.2; SV1; .NET CLR 1.1.4322; .NET CLR 2.0.50727)\r\n
Host: <host>\r\n
Content-Length: <len>\r\n
Connection: Keep-Alive\r\n
Cache-Control: no-cache\r\n
Cookie: vldID=<vldID>\r\n        (or "Cookie: domainId=<id>; authId=<authId>")
\r\n
txtMacAddr=<mac>&svpnlang=<lang>&txtUsrName=<user>&txtPassword=<password>&selDomain=<domain>&vldCode=<code>&showOption=0&saveFlag=0&UserName=<user>&vldID=<vldID>
```

Field names (real, from rodata):
`txtMacAddr=`, `&svpnlang=`, `&txtUsrName=`, `&txtPassword=`, `&selDomain=`, `&vldCode=`, `&showOption=0&saveFlag=0&UserName=`, `&vldID=`.
Cookies referenced: `vldID`, `domainId`, `authId`.
`txtPassword` is the raw password URL-encoded. No hashing.

### 1b. Current V7 XML login (`CHttpsAuth::buildSslAuthPacketV7`, HttpsAuth.cpp ~2050; XML built by `CSSLVpnXmlParser::FormatLoginXML`, SslVpnXmlParser.cpp:27-57)
The login is an XML document placed (URL-encoded) into a `request=` body and POSTed:

```
POST <path> HTTP/1.1\r\n
Host: <host>\r\n
... headers ...
\r\n
request=<URL-encoded XML>
```

XML template (root `<data>`, child elements set as text — SslVpnXmlParser.cpp:29 emits `"<data></data>"` then fills children):

```xml
<data>
  <username>USER</username>
  <password>PASSWORD</password>          <!-- SslVpnXmlParser.cpp:39, struct off +0x20 -->
  <vldCode>CAPTCHA</vldCode>             <!-- :40 -->
  <language>CN|EN</language>             <!-- :41 -->
  <OS>Linux</OS>                          <!-- :42 -->
  <macAddress>AA:BB:..</macAddress>       <!-- :43 -->
  <supportChallengePwd>0|1</supportChallengePwd>  <!-- :44 -->
  <private>BASE64(client-info blob)</private>     <!-- :45 -->
</data>
```

Real element tag literals (SslVpnXmlParser.cpp): `username` (0x85198), `password` (0x851a1), `vldCode` (0x851b6), `language` (0x851be), `OS` (0x851c7), `macAddress` (0x851ca), `supportChallengePwd` (0x85213), `private` (0x85190), wrapper `data` (0x850e8), `<data></data>` (0x85227).

**`<password>` content is the raw user password** (struct `_VPNLogInPacketInfoV7` field at offset +0x20). In `buildSslAuthPacketV7` the password is copied from the `_SslvpnUser` struct (offset +0xb6) into the packet's password field. The only transform applied before the XML is **URLEncoder::Encode** of the whole `request=` body. The literal `"<password>"`/`"</password>"` strings (0x80ec7 / 0x80ed2) and `"******"` (0x80dd6) that appear in the function are used **only to mask the password in debug logs** (`svpn.HttpsAuth.buildAuthPktV7:` 0x80ee0), not to wrap it on the wire.

#### Special "challenge password" concatenation (HttpsAuth.cpp:2057-2061)
When the `_SslvpnUser` byte flag at +0xb6 is set, the password field is built by concatenating with a **non-ASCII separator byte `0xA1`** (`std::string::operator+=((char)0xA1)`), i.e. `<sep 0xA1> + <oldpwd/newpwd parts>`. This is the change-password / dual-password (old@new) encoding, still cleartext, still only inside TLS. The username is taken from `_SslvpnUser+0x14`, the password material from `_SslvpnUser+0xb6` and `+0x95`.

---

## 2. Challenge / 2nd-factor flow — server-driven SMS/OTP, no crypto

`CHttpsAuth::buildSslChallengeAuthPacketV7` (HttpsAuth.cpp:3652) and `CSSLVpnXmlParser::FormatChallengeAuthXML` (SslVpnXmlParser.cpp:216-257).

The challenge **type** is read from config (`cfg+0xc4`) and logged as one of:
- `challenge type SMS` (HttpsAuth.cpp:3668)
- `challenge type SMS-GW` (:3674)
- `challenge type SMS-IMC` (:3680)

Challenge XML (`<data>` root, SslVpnXmlParser.cpp:216-251):

```xml
<data>
  <username>USER</username>          <!-- :227 -->
  <type>CHALLENGE_TYPE</type>        <!-- :228 -->
  <code>SMS_OR_OTP_CODE</code>       <!-- :229  the value the user typed -->
  <language>CN|EN</language>         <!-- :230 -->
  ...                                <!-- "SMS-IMC" (0x85393), "CHANGEPWD" (0x8539b) branches -->
  <password>NEW_PASSWORD</password>  <!-- :237 only on CHANGEPWD branch, raw -->
  <vldCode>...</vldCode>             <!-- :241 -->
  <language>...</language>           <!-- :242 -->
  <OS>Linux</OS>                     <!-- :243 -->
  <macAddress>..</macAddress>        <!-- :244 -->
  <private>BASE64(...)</private>     <!-- :245 -->
</data>
```

Real tags: `username`, `type` (0x851dc), `code` (0x851e1), `language`, `OS`, `macAddress`, `private`, plus the branch markers `SMS-IMC` (0x85393) and `CHANGEPWD` (0x8539b).

**There is no MD5/SHA/SM3/HMAC computed over `challenge + password + salt`.** The `<code>` is the literal SMS/OTP code the user entered. Everything is transported cleartext inside TLS, URL-encoded in a `request=` POST body, same envelope as login. The response is parsed by `SendChallengeAuthResult` / `prsAuthRspMsgV3`.

---

## 3. The `<private>` field — base64 of a binary client-info blob

`CHttpsAuth::makePrivateContent` (HttpsAuth.cpp:2491-2514) builds a small fixed binary struct (flags + lengths + client/OS info, zero-initialised then filled) and calls `utl_base64_encode` (HttpsAuth.cpp:2512) on it. Output is placed in `<private>`. **This is NOT the password** — it is host/OS/endpoint metadata. Standard base64 alphabet (see §6).

---

## 4. Local-storage AES (fixed key/IV) — `utlCrypt.cpp`, NOT on the wire

In `libInodeUtility.so` / `libutility.so`, the wrappers `utl_AESCBC_Encryption` / `utl_AESCBC_Decryption` (utlCrypt.cpp:436-479) use **hard-coded global key and IV** (data symbols, statically initialised, no runtime writers) to encrypt local config/credential files:

- **Algorithm:** AES-128-CBC (key bits = `0x10 << 3` = 128; data length fixed 0x20 = 32 bytes per call), OpenSSL `AES_set_encrypt_key` + `AES_cbc_encrypt(..., enc=1)`.
- **Key (16 bytes)** = global `rkey1[0:8] || rkey2[0:8]`:
  - `rkey1` @0x3b9138 = `EC D4 4F 7B C6 DD 7D DE`
  - `rkey2` @0x3b9088 = `2B 7B 51 AB 4A 6F 5A 22`
  - => key = `EC D4 4F 7B C6 DD 7D DE 2B 7B 51 AB 4A 6F 5A 22`
- **IV (16 bytes)** = global `iv1[0:8] || iv2[0:8]`:
  - `iv1` @0x3b9140 = `61 40 34 64 65 25 23 31`  (ASCII `a@4de%#1`)
  - `iv2` @0x3b9080 = `61 73 64 66 73 64 32 34`  (ASCII `asdfsd24`)
  - => IV = ASCII **`a@4de%#1asdfsd24`** (`61 40 34 64 65 25 23 31 61 73 64 66 73 64 32 34`)

The `_New` variants (`utl_AESCBC_Encryption_New`, utlCrypt.cpp:564-586) keep the **same fixed IV (`a@4de%#1asdfsd24`)** but take the **16-byte key and length from the caller** (still AES-128-CBC). Generic helper `utl_Encrpt_Aes`/`utl_decrpt_Aes` (utlCrypt.cpp:627+) take caller key + key-bits.

GOT/relocation names confirm: `rkey1@@Base`, `rkey2@@Base`, `iv1@@Base`, `iv2@@Base`.

> Reimplement: `AES-128-CBC(key=EC D44F7B C6DD7DDE 2B7B51AB 4A6F5A22, IV="a@4de%#1asdfsd24")` for the legacy fixed-key local store; for `_New`, same IV, caller key.

---

## 5. SPA / "zeroTrust" knock packet — AES-256-CBC, hex output

`buildMinusOnePacket(SpaRegisterParams*)` (SslClient.cpp:143-334) builds the Single-Packet-Authorization "minus one" / zeroTrust packet:

1. Collects local IPv4/IPv6 addresses (`getifaddrs`, `inet_ntop`), an AID and a content blob.
2. **AES key** = `SpaRegisterParams + 0x230` (a provisioned/registered key string, `c_str()`); content + lengths from struct.
3. Encrypts content with **`utl_AES256CBC_encrypt`** (SslClient.cpp:311) → **AES-256-CBC** (`AES_set_encrypt_key` with bits = `0x100` = 256; confirmed at utlCrypt.cpp:522-527).
4. Encrypted bytes are **hex-encoded** with `sprintf("%02X", b)` (SslClient.cpp:307/318), space-separated then packed.
5. Debug format string (rodata 0x830d0):
   `[buildMinusOnePacket] contentLenth<%d>,content<%s>; keyLength<%d>,key<%s>; encryptContentLength<%d>,encryptContent<%s>; strSrcIP<%s>,strAID<%s>`
   Log tag `zeroTrust` (0x83045).

`utl_AES256CBC_encrypt` (utlCrypt.cpp:506-553) internals:
- copies 0x48 bytes of key material, `AES_set_encrypt_key(key, 256, &rk)`, `AES_cbc_encrypt(..., enc=1)`,
- emits ciphertext as uppercase hex (`%02X`) via ostringstream, and also hex-dumps the key for logging.
- The IV/key are caller-supplied (the SPA path supplies the registered key).

`makePrivateContent` also uses `utl_base64_encode`; `doCamsNotify` / `spaDoCamsNotify` use `utl_base64_decode` for CAMS notifications.

---

## 6. Encoding primitives

- **Base64** (`base64_encode`/`utl_base64_encode`, libInodeUtility.so 0xb615d / 0xc0c42): **standard RFC4648 alphabet**
  `ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/` (decode table confirms `+`→62, `/`→63, padding `=`). No custom alphabet.
- **Hex** (`%02X`, uppercase) for SPA ciphertext and for logging keys/IVs.
- **URL-encoding** `URLEncoder::Encode` wraps the entire `request=<xml>` body and the `txtPassword=` form value.

## 7. Hash / integrity

- **MD5** (`MD5Init/Update/Final/MD5Calc`, libInodeUtility.so 0xb088d…; `getMD5Value`/`setMD5Value`, `CalcMD5FromFile`, `GetMd5CharFromFile`) — used for **file/update integrity** (e.g. `pre_version_md5_file.txt`), not for password hashing.
- **CRC32 / adler32** (`crc32`, `crc32_combine`, `adler32`, `adler32_combine` — exact zlib API) — zlib/deflate stream checksums; not credential-related.
- **DES/3DES** (`des_*`, `des3_*`) present but used for legacy/other (not the SSL VPN login path observed).

## 8. TEA / hash-key obfuscation (`utlTeaCipher.cpp`)

- `utl_EncryptTeaKey` / `utl_DecryptTeaKey` (libInodeUtility.so 0xcaa78 / 0xcab2e): classic **TEA/XTEA** on 8-byte blocks (length must be multiple of 8 — `and eax,7; test` check at utlTeaCipher.cpp:95), **128-bit key (4×uint32) supplied by caller** (`unsigned int const* key`).
- `utl_EncryptHashKey` / `utl_DecryptHashKey` / `utl_DecryptHashKeyS` wrap TEA over a char buffer with a caller key.
These protect locally-stored keys/secrets, not wire traffic.

---

## 9. GM / SM2-SM3-SM4 (Chinese national crypto) — TLS-layer only, via SKF

GM is used to authenticate the **TLS (TLCP/GMTLS) handshake with a client certificate**, when the gateway is a GM gateway. It does **not** transform the application password.

State string: `INODE_GMTLS_1_1`. Cert type dispatched in `buildSslCtx`; error string `svpn.HttpsAuth.buildCtx Not support certificate type %d for GMSSL.`

Two GM cert sources:
- **`CHttpsAuth::loadGMFileCert(SSL_CTX*)`** (HttpsAuth.cpp:4292-area): file-based **double certificate** — separate **signing cert** and **encryption cert** (`SSL_CTX_use_enc_certificate_file`, error tags `ER_GM_LOAD_ENC_CERT`, `ER_GM_CONVERT_ENC_CERT`, `ER_GM_GET_EC_SIG_PKEY`, `ER_GM_GET_EC_ENC_PKEY`, `H3C_GM_SIGN_CERT`).
- **`CHttpsAuth::loadGMSKFCert(SSL_CTX*)`** (HttpsAuth.cpp:3553-3634): hardware **SKF UKey**:
  - `SKF_Library_init()` → open UKey ctx → `SKF_UKEY_CTX_Verify_PIN()` (PIN check, `remain_attempts`) → `SKF_UKEY_CTX_set_SSL_CTX_cert()` → `SKF_ENGINE_init()` → `SKF_ENGINE_CTX_set_SSL_CTX_private_key()` (binds the SM2 private key in the token as the TLS client key via the OpenSSL engine). Error tags `ER_GM_GET_SKF_ENGINE`, `ER_GM_EXPORT_SKF_ENC_CERT`.

SKF engine (`libskf_engine.so`, OpenSSL ENGINE `skf_engine_id` / `skf_engine_name`):
- Registers `EVP_PKEY` methods for SM2: `EVP_PKEY_meth_set_sign/verify/encrypt`, alias type, `digest_custom` over `EVP_sm3()`.
- Uses OpenSSL 1.1.1k GM helpers: `sm2_encrypt`, `sm2_verify`, `sm2_compute_z_digest`, `sm2_ciphertext_size`.
- `get_pkey_from_skf_container()`, `set_skf_engine_data_on_key()`, `get_inode_skf_engine()`.

SKF wrapper (`libskf_wrapper.so`, GM/T 0016 SKF API): full SM2/SM3/SM4 token API — `SKF_ECCSignData`, `SKF_ECCVerify`, `SKF_ECCDecrypt`, `SKF_ECCExportSessionKey`, `SKF_Encrypt/Decrypt` (SM4), `SKF_Digest*` (SM3), `SKF_ExportPublicKey`, `SKF_ExportCertificate`, `SKF_DevAuth`, `SKF_VerifyPIN`. Data symbol `skf_app_password` holds the default app password for the token.
Helper export: `SKF_Wrapper_ECCSignData(void*, char* tbs, uint len, char** sig, uint* siglen)`.

So for a GM gateway: the SM2/SM3/SM4 work happens entirely inside the TLS/TLCP handshake (mutual cert auth). The password/SMS-code in the XML body remains cleartext **inside** that GM-TLS tunnel.

---

## 10. RSA references (different component — note only)

Strings `H3C_USER_RSAKEY`, `H3C_RSA`, `ER_RSA_ENCRYPT`, `szUserRsaKey`, `useRSA` appear in `.debug_str`/rodata of `libiNodeSslvpnPt.so` and `libInodeSecurityAuth.so`. In `libInodeSecurityAuth.so` (`useRSA`, `H3C_USER_RSAKEY`) these belong to the **802.1X / portal (EAD) authentication** path (a different component), where the portal password is RSA-encrypted with a server public key before posting. This is out of scope for the SSL VPN login path documented above, but flagged for the portal/802.1X analyst.

---

## Reimplementation cheat-sheet (SSL VPN client)

| What | How |
|---|---|
| Login password on wire | **cleartext**, URL-encoded, inside `<password>` of `request=<xml>` (V7) or `txtPassword=` form (V3); TLS only |
| Challenge / 2FA | server SMS/OTP; user code echoed in `<code>`/`<vldCode>`, cleartext over TLS; no client hash |
| Captcha | `<vldCode>` / `vldCode=`; cookie `vldID` |
| `<private>` | base64(binary client/OS info blob), NOT password |
| Local config AES | AES-128-CBC, key `EC D44F7B C6DD7DDE 2B7B51AB 4A6F5A22`, IV `"a@4de%#1asdfsd24"` |
| SPA/zeroTrust knock | AES-256-CBC with provisioned key (`SpaRegisterParams+0x230`), ciphertext uppercase-hex |
| base64 | standard `A-Za-z0-9+/`, pad `=` |
| Hash | MD5 only for file integrity; CRC32/adler32 = zlib stream checksums |
| Local key obfuscation | TEA/XTEA (128-bit caller key, 8-byte blocks) |
| GM gateway | TLCP/GMTLS double-cert (sign+enc) or SKF UKey; SM2 sign/enc, SM3 digest, SM4 cipher via OpenSSL `skf_engine`; TLS-layer auth only |

## Open questions
- Exact byte layout of the `_SslvpnUser` and `_VPNLogInPacketInfoV7` structs (offsets +0x14 user, +0x95, +0xb6 password parts) — partially recovered; full field map would need the struct DWARF.
- Whether any deployment toggles a non-TLS password obfuscation server-side (none found in the client).
- Exact contents of the `<private>` binary blob (HttpsAuth.cpp:2491) — field-by-field layout not fully decoded.
