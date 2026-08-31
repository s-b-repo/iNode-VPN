# H3C iNode SSL VPN — Clean-Room Protocol Specification

Reconstructed from reverse engineering of the H3C iNode 7.3 (PC `V7R3B05D151`,
Linux package `E0651`) SSL VPN client against an H3C SecPath F1000 (Comware "V7"
SSL VPN) gateway. Target binaries: `libiNodeSslvpnPt.so`, `libvnic.so`,
`libZeroTrust.so`, `libInodeUtility.so`/`libutility.so`, `libpipc.so`,
`AuthenMngService`. All binaries shipped unstripped with DWARF; tag names, CGI
paths, cookie names, struct offsets, enum values and byte layouts below are
recovered exactly unless explicitly marked **[UNCERTAIN]** / **[VALIDATE]**.

This document is implementation-grade: a competent engineer can build an
interoperable client from it alone. Citations are `file.cpp:line` (source name
from DWARF) and/or `@0xADDR` (offset in `libiNodeSslvpnPt.so`).

---

## 1. Overview & Architecture

### 1.1 Components

| Component | Binary | Role |
|---|---|---|
| GUI front-end | `iNodeClient` | User UI. Talks only to the daemon over local IPC. |
| Orchestration daemon | `AuthenMngService` (`AuthMngSvc 1.8.2`) | Owns connection lifecycle; loads `*.icnf` profiles; drives the protocol engine. |
| SSL VPN protocol engine | `libiNodeSslvpnPt.so` | The actual TLS/HTTP wire protocol: auth (`CHttpsAuth`), HTTP helpers (`CSslHttpOper`), tunnel (`CSslClient`), XML (`CSSLVpnXmlParser`), manager (`CSslVpnMgr`). |
| Virtual NIC / routing | `libvnic.so` | TUN device, address/route/DNS programming. |
| Zero-Trust / SPA | `libZeroTrust.so` | UDP single-packet-authorization knock + SDP controller JSON. |
| Crypto/util | `libInodeUtility.so`, `libutility.so` | AES/base64/MD5/TEA/HMAC, TLV packet codec. |
| GM crypto | `libskf_engine.so`, `libskf_wrapper.so` | SM2/SM3/SM4 SKF UKey + GMTLS (optional). |

An interoperable **standalone** client only needs the protocol engine behaviour
(Sections 2–8). The IPC layer (Section 7.4) is internal and not on the wire.

### 1.2 Transport & ports

- **Control plane + data plane**: HTTP/1.1 over **TLS**, default **TCP 443**
  (`iVpnServerPort`, config-driven), to `https://<gateway>/svpn/*`.
  The data tunnel reuses an HTTP-like verb (`NET_EXTEND`) on a **fresh** TLS
  socket and then switches to raw 4-byte-framed binary. **TCP-over-TLS only on
  Linux — no DTLS/UDP data channel** (DTLS config frames are recognized and
  ignored, `SslClient.cpp:746-749`).
- **SPA knock (Zero-Trust mode only)**: **UDP**. Gateway handshake port **8000**
  (`Spa_Knock_Port_GW=0x1f40`), device register **19006** (`Spa_Register_Port`),
  generic **59993** (`Spa_Knock_Port`). SDP controller HTTPS auth **443**
  (`Spa_Auth_Port`); ZT controller auth alt port **4433** (`CONTROLLERAUTHPORT`).
- **Two protocol generations**: **V3** (legacy HTML-form CGI, `User-Agent:
  SSLVPN-Client/3.0`) and **V7** (XML-in-`request=`, `User-Agent:
  SSLVPN-Client/7.0`, `svpnginfo` cookie). Version is detected from the response
  header **`Server: SSLVPN-Gateway/7.0`** → V7, else V3
  (`getVpnVersionFromResp @0x52122`). **V7 is the modern path and the primary
  target of this spec.**

### 1.3 TLS context (`buildSslCtx @0x45a36`)

- Standard: `TLS_client_method`. GM/national: `CNTLS_client_method` (selected by
  cert type; state string `INODE_GMTLS_1_1`). TLS version negotiable:
  `INODE_TLS_1_0 / _1_2 / _AUTO` (`TLS_VERSION=0` = auto).
- Server cert verification: `SSL_CTX_set_verify` + `set_verify_depth` +
  `load_verify_locations` + `SSL_get_verify_result`; hostname check via
  `ACE_SSL_Context::check_host`. (SNI is emitted inside `libACE_SSL`, not this
  lib — **[VALIDATE]** exact SNI bytes if needed.)
- Optional **mutual TLS** client cert: PEM/CRT direct; PFX/P12 converted to a
  passwordless PEM by shelling
  `LD_LIBRARY_PATH=./libs ./openssl pkcs12 -in <f> -nodes -password pass:<pw>`.
- Optional **GM** client auth: file double-cert (sign + enc cert) via
  `loadGMFileCert`, or **SKF USB-Key** via `loadGMSKFCert` (PIN-gated;
  `SKF_Library_init`→`SKF_UKEY_CTX_Verify_PIN`→bind SM2 key as TLS client key).

---

## 2. Full Connection Sequence

```
[0] (Zero-Trust only) SPA UDP KNOCK  ── UDP/8000 ─▶  open firewall pinhole for src IP
                                                     (§5.4; skip entirely in classic mode)

[1] TLS CONNECT  host:443                            buildSslCtx + verify peer + check_host

[2] GET /svpn/index.cgi  (UA SSLVPN-Client/7.0)
        ◀── 30x Location:  (getHttpAuthStatFromLocStr)
              "getinfo"        -> state AUTHSTAT_WAIT_REDIRECT_RESP(1)
              "getdomainlist"  -> state AUTHSTAT_WAIT_DOMAINLIST_RESP(2)
        Detect version from "Server: SSLVPN-Gateway/7.0".
        Follow redirects (300..307, Location:) until 200 OK.

[3] PARSE gatewayinfo capabilities (GetVpnConnInfo):
        supportPassword/supportCert/supportDKey/supportvldimg,
        vldimg@url, <login>, <logout>, <challenge> URLs.

[4] GET <domainlist-url>  (Cookie: domainId=...; authId=-1; showOption=1; saveFlag=0; UserName=)
        ◀── 200 OK  <data><domainlist><domain><name><url></domain>...</domainlist></data>
        Pick a <domain>; its <url> is the V7 login URL (e.g. /svpn/vpnuser/check.cgi).

[5] (if supportvldimg) GET <vldimg url e.g. /svpn/image.cgi>
        ◀── image bytes; Set-Cookie: vldID / svpnvldid / svpnginfo
        User solves CAPTCHA -> vldCode.

[6] POST <loginURL>  body: request=<urlencoded login XML>  (Cookie: svpnginfo=...)
        XML = FormatLoginXML(username,password,vldCode,language,OS,macAddress,
                             supportChallengePwd,private)
        ◀── Set-Cookie: ...svpnginfo=<token>;
            <data><result>Success|Challenge</result>...</data>   (parseAuthRespMsgV7)

[7] CHALLENGE / 2FA LOOP  (while result == Challenge):
        type ∈ {SMS, SMS-GW, SMS-IMC, PROMPTPWD, CHANGEPWD}
        User supplies code / new password.
        POST <challengeURL e.g. /svpn/vpnuser/check_return.cgi>
            Referer: https://<host>/svpn/vpnuser/check.cgi
            body: request=<urlencoded FormatChallengeAuthXML>
        ◀── result: Success | (NewChallenge -> loop) | Failed

[8] (optional) KICK OLD SESSION:
        GET /svpn/olduser_info.cgi?svpnlang=cn        -> old user id
        GET /svpn/vpnuser/kickolduser.cgi?OldUserID=&NewUserID=&IsKick=1&svpnlang=cn

[9] (optional, EAD/posture) POST /svpn/vpnuser/check_return.cgi  body: hostcheckresult=&ActXisIns=1

[10] TUNNEL SETUP — NEW TLS socket, send:
        NET_EXTEND / HTTP/1.1\r\nHost:..\r\nUser-Agent: SSLVPN-Client/7.0\r\nCookie: svpnginfo=..\r\n\r\n
        ◀── gateway pushes a NETWORK-CONFIG frame (type=3/sub=2) carrying the
            plaintext param block: IPADDRESS/SUBNETMASK/GATEWAY/PREFIXLENGTH/
            DNS/ROUTES/EXCLUDE ROUTES/RESTRICT/KEEPALIVETIME/IPV6*.

[11] VIRTUAL IP / ROUTE / DNS programming (libvnic):
        open /dev/net/tun (IFF_TUN|IFF_NO_PI), SIOCSIFADDR/SIOCSIFNETMASK, IFF_UP,
        rtnetlink RTM_NEWROUTE (v4) / `ip -6 route add` (v6), rewrite /etc/resolv.conf.

[12] DATA FLOW (raw 4-byte framing over the TLS socket):
        TUN read  -> frame  01 00 htons(len) <ip pkt>  -> SSL_write
        SSL_read  -> frame  type=1 -> write payload to TUN

[13] KEEPALIVE:  every 1 s send  02 01 00 00 ; reset no-resp counter on any
        inbound frame (esp. type=2 ack). After N unanswered -> offline.

[14] TEARDOWN:  GET /svpn/logout.cgi  (Cookie: svpnginfo=...)
        or gateway pushes type=4 force-logoff frame.
```

State enums driving steps [2]–[4]: `EHttpAuthStat` =
`AUTHSTAT_WAIT_CONN_RESP(0)` / `AUTHSTAT_WAIT_REDIRECT_RESP(1)` /
`AUTHSTAT_WAIT_DOMAINLIST_RESP(2)` (`@0x2618f`).

---

## 3. HTTP Requests & Responses (exact)

All requests are HTTP/1.1 over TLS. Line terminator `\r\n`, blank line ends
headers. `<host>` is the gateway host the caller configured. Default port 443.

### 3.1 GET gateway/param query — V7 (`buildHttpConReqV7 @0x524ca`)
```
GET /svpn/index.cgi HTTP/1.1
Host: <host>
Connection: Keep-Alive
User-Agent: SSLVPN-Client/7.0

```
**Response**: 30x redirect (`Location:` classified by `getHttpAuthStatFromLocStr`)
or 200 OK with gatewayinfo XML (§4.1). Version header `Server: SSLVPN-Gateway/7.0`.

### 3.1b GET — V3 legacy (`buildHttpConReqV3 @0x522ee`)
```
GET /svpn/index.cgi HTTP/1.1
Accept: application/x-shockwave-flash, image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, */*
UA-CPU: x86
Accept-Encoding: gzip, deflate
User-Agent: SSLVPN-Client/3.0
Host: <host>
Connection: Keep-Alive
Accept-Language: zh-cn

```
(Some V3 requests use the spoof UA: `Mozilla/4.0 (compatible; MSIE 6.0; Windows
NT 5.2; SV1; .NET CLR 1.1.4322; .NET CLR 2.0.50727)`.)

### 3.2 GET domain list (`getDomainParams @0x48440`)
```
GET <domainlist-url> HTTP/1.1
Host: <host>
User-Agent: SSLVPN-Client/7.0   (V3: MSIE spoof UA + Accept-Language: zh-cn)
Cookie: domainId=<id>; authId=-1; showOption=1; saveFlag=0; UserName=
Connection: Keep-Alive

```
**Response**: 200 OK, domain-list XML (§4.2).

### 3.3 GET CAPTCHA image (`getVerifyPic @0x492a4`, `buildVldImgReqV7 @0x50cac`)
```
GET <vldimg-url e.g. /svpn/image.cgi> HTTP/1.1
Accept: */*
Host: <host>
User-Agent: SSLVPN-Client/7.0
Cookie: svpnginfo=<svpnginfo>          (V7)
        svpnvldid=<n>; svpnuid=<hex>   (V3, e.g. svpnvldid=178; svpnuid=a48eafca8822d45b88f10a2118ec8400)
Connection: Keep-Alive

```
**Response**: image bytes; `Set-Cookie:` provides `vldID` / `svpnvldid` /
`svpnginfo`. Parser scans `Set-Cookie:` for those three tokens.

### 3.4 POST V7 login (`buildSslAuthPacketV7 @0x4dfee`)
```
POST <loginURL> HTTP/1.1
Host: <host>
Connection: Keep-Alive
User-Agent: SSLVPN-Client/7.0
Cookie: svpnginfo=<svpnginfo>
Content-Type: application/x-www-form-urlencoded
Content-Length: <len>

request=<URL-ENCODED login XML (§4.3)>
```
Body is literally `request=` + `URLEncoder::Encode(<data>...</data>)` (whole doc
percent-encoded; `<password>`→`%3Cpassword%3E`). **Response**: `Set-Cookie:
...svpnginfo=<token>` + login-result XML (§4.5). Result ∈ `Success` | `Challenge`
| `CHANGEPWD` | `PROMPTPWD` | `SSLVPN_NotSupportAuthPkt`.

### 3.5 POST V7 challenge / 2FA (`buildSslChallengeAuthPacketV7 @0x54bf0`, `buildSsl2ndAuthPacketV7 @0x4ec7e`)
```
POST <challengeURL e.g. /svpn/vpnuser/check_return.cgi> HTTP/1.1
Referer: https://<host>/svpn/vpnuser/check.cgi
Host: <host>
User-Agent: SSLVPN-Client/7.0
Cookie: svpnginfo=<svpnginfo>
Content-Type: application/x-www-form-urlencoded
Content-Length: <len>

request=<URL-ENCODED challenge XML (§4.4)>
```
**Response**: same login-result XML; loop until `Success` or `Failed`.

### 3.6 POST V3 legacy login (`buildSslAuthPacketV3 @0x4fb76`)
```
POST /svpn/vpnuser/login_submit.cgi HTTP/1.1
Accept: application/x-shockwave-flash, ... , */*
Referer: https://<host>:<port>/svpn/index.cgi
Accept-Language: zh-cn
Content-Type: application/x-www-form-urlencoded
UA-CPU: x86
Accept-Encoding: gzip, deflate
User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.2; SV1; .NET CLR 1.1.4322; .NET CLR 2.0.50727)
Host: <host>
Content-Length: <len>
Connection: Keep-Alive
Cache-Control: no-cache
Cookie: vldID=<v>; domainId=<id>; authId=...; showOption=0; saveFlag=0; UserName=...

txtMacAddr=<mac>&svpnlang=<cn|EN>&txtUsrName=<user>&txtPassword=<pass>&vldCode=<captcha>&selDomain=<domain>&selIdentity=1
```
(Some builds append `&showOption=0&saveFlag=0&UserName=<user>&vldID=<vldID>`.)

### 3.7 EAD / host-check result (`sendCheckResult @0x4ca02`)
```
POST /svpn/vpnuser/check_return.cgi HTTP/1.1
Referer: https://<host>:<port>/svpn/vpnuser/check.cgi
Content-Type: application/x-www-form-urlencoded
Cookie: domainId=<id>; authId=...; showOption=0; saveFlag=0; UserName=; svpnlang=1;
Host: <host>
Content-Length: <len>
Cache-Control: no-cache

hostcheckresult=&ActXisIns=1
```

### 3.8 Kick old session (`kickOldLogin @0x5348a`)
```
GET /svpn/olduser_info.cgi?svpnlang=cn HTTP/1.1     -> body: var arrOldUserInfo=new Array(...)
GET /svpn/vpnuser/kickolduser.cgi?OldUserID=<old>&NewUserID=<new>&IsKick=1&svpnlang=cn HTTP/1.1
   Cookie: svpnvldid=<v>; svpnuid=<u>
   Referer: https://<host>:<port>/...
```

### 3.9 Logout (`buildLogOutReqV7 @0x50646` / `buildLogOutReqV3 @0x50368`)
```
GET /svpn/logout.cgi HTTP/1.1
Host: <host>
User-Agent: SSLVPN-Client/7.0
Cookie: svpnginfo=<svpnginfo>        (V3: Cookie: domainId=<id>; authId=...; showOption=0; saveFlag=0; UserName=; svpnlang=1;)
Connection: Keep-Alive

```

### 3.10 Tunnel handshake (`buildIPHandshakeReq`, SslClient.cpp:1177)
```
NET_EXTEND / HTTP/1.1
Host: <host>
User-Agent: SSLVPN-Client/7.0
Cookie: svpnginfo=<svpnginfo>

```
On a **separate** TLS socket. `svpnginfo` is `utf82gbk`-encoded. Legacy variant:
single-line `NET_EXTEND / HTTP/1.1\r\nCookie:<cookie>\r\n\r\n`. Response = the
plaintext param block (§6.3) followed by raw frames.

### 3.11 HTTP framing rules (`CSslHttpOper`, HttpsTool.cpp)
- Success = status line contains `200 OK` (`isRespSuccess @0x5d62e`).
- Redirect = code in **300..307** (`299 < code < 308`); new URL from `Location:`
  (`needRedirection @0x5d72a`).
- Body framing: `Content-Length:` or `chunked` Transfer-Encoding
  (`hasHttpHeader @0x5e3a8`; `praseChunkedData` for chunked).

---

## 4. XML Message Schemas

Root element of **every** body/response is `<data>`. Built with a vendored
TinyXML ("inodexml"); `AddItem(tag,value)` appends a child of `<data>`. **Element
order below is the exact binary emission order.** Request bodies are entirely
URL-percent-encoded and prefixed with `request=`.

### 4.1 GatewayInfo (server→client, `GetVpnConnInfo`, SslVpnXmlParser.cpp:145)
Path `<data><gatewayinfo><auth>...`. Into `_VPNAuthUrlV7`:
| tag | field | meaning |
|---|---|---|
| `supportPassword` | strSupportPwdState | "1"/"0" password auth allowed |
| `supportCert` | strSupportCertState | cert auth allowed |
| `supportDKey` | strSupportDKeyState | hardware-key auth allowed |
| `supportvldimg` | strSupportVldimgState | CAPTCHA required |
| `vldimg` (attr `url`) | strVldImgURL | CAPTCHA image URL |
| `login` | strLoginURL | login POST URL |
| `logout` | strLogoutURL | logout URL |
| `challenge` | CheckonlineURL | challenge/2FA POST URL |
```xml
<data><gatewayinfo><auth>
  <supportPassword>1</supportPassword><supportCert>0</supportCert>
  <supportDKey>0</supportDKey><supportvldimg>1</supportvldimg>
  <vldimg url="/svpn/image.cgi"/>
  <login>/svpn/vpnuser/check.cgi</login>
  <logout>/svpn/logout.cgi</logout>
  <challenge>/svpn/vpnuser/check_return.cgi</challenge>
</auth></gatewayinfo></data>
```

### 4.2 DomainList (server→client, `GetDomainListInfo`, SslVpnXmlParser.cpp:106)
```xml
<data><domainlist>
  <domain><name>RADIUS</name><url>/svpn/vpnuser/check.cgi</url></domain>
  ...
</domainlist></data>
```
Each `<domain>` → `_DomainUrlInfo{strDomainName@0x00, strDomainUrl@0x20}`.

### 4.3 LoginXML (client→server, `FormatLoginXML`, SslVpnXmlParser.cpp:27, struct `_VPNLogInPacketInfoV7`)
Emission order: `username, password, vldCode, language, OS, macAddress,
supportChallengePwd, private`.
```xml
<data>
  <username>USER</username>
  <password>PASS</password>
  <vldCode>CAPTCHA</vldCode>
  <language>cn</language>            <!-- "cn"/"CN" or "en"/"EN" or "1"; from isLangCn() -->
  <OS>Linux</OS>
  <macAddress>AA-BB-CC-DD-EE-FF</macAddress>   <!-- some builds prefix "H;" -->
  <supportChallengePwd>1</supportChallengePwd>
  <private>BASE64_CLIENT_INFO</private>
</data>
```
Field meanings: `username`=login name; `password`=credential (§5);
`vldCode`=CAPTCHA text (empty if none); `language` UI lang; `OS`="Linux";
`macAddress`=primary NIC MAC; `supportChallengePwd`="1" advertises 2FA/change-pwd
support; `private`=base64 host/OS telemetry blob (§5.5).

### 4.4 ChallengeAuthXML (client→server, `FormatChallengeAuthXML`, SslVpnXmlParser.cpp:216, struct `_VPNCahllengeAuthPacketInfo`)
Always: `username, type, code, language`. Then **branch on `type`**:
- `type == "SMS-IMC"` → add `password`.
- `type == "CHANGEPWD"` → add `password` (OLD) then `newPassword` (NEW).
All paths then append: `vldCode, OS, macAddress, private`.
```xml
<data>
  <username>USER</username>
  <type>SMS|SMS-GW|SMS-IMC|PROMPTPWD|CHANGEPWD</type>
  <code>CHALLENGE_CODE</code>        <!-- SMS/OTP code the user typed -->
  <language>cn</language>
  <password>OLDPW</password>         <!-- when SMS-IMC or CHANGEPWD -->
  <newPassword>NEWPW</newPassword>   <!-- only CHANGEPWD -->
  <vldCode>V</vldCode>
  <OS>Linux</OS>
  <macAddress>MAC</macAddress>
  <private>BLOB</private>
</data>
```

### 4.5 LoginInfo result (server→client, `GetLogInInfo`, SslVpnXmlParser.cpp:183 / `parseAuthRespMsgV7 @0x49c3c`)
```xml
<data>
  <result>Success|Challenge</result>     <!-- strcmp; also CHANGEPWD/PROMPTPWD seen as result tokens -->
  <replyMessage>...</replyMessage>        <!-- server text -->
  <EMOServer>...</EMOServer>              <!-- EMO server address (optional) -->
  <private>...</private>                  <!-- opaque blob, size up to 0x820 -->
  <type>SMS|SMS-GW|SMS-IMC|PROMPTPWD|CHANGEPWD</type>
  <message>...</message>                  <!-- display message -->
  <smsDynamicPwdd>1</smsDynamicPwdd>      <!-- SMS dynamic-pwd flag -->
  <waitTime>120</waitTime>                <!-- int: wait before retry (s) -->
  <intervaltime>60</intervaltime>         <!-- int: resend interval (s) -->
</data>
```
Unknown `type` → fail with `SSLVPN_NotSupportAuthPkt`.

### 4.6 Format2ndLoginXML (`Format2ndLoginXML`, SslVpnXmlParser.cpp:61, arg `EnumSmsVender`)
Variant of 4.4 used by the 2nd-auth path. Always `username, type, code,
language`; **if `EnumSmsVender == SSLVPN_SMS_IMC(1)`** also append `password,
vldCode, OS, macAddress, private`.

### 4.7 V3 form bodies (not XML)
- Login (`login_submit.cgi`):
  `txtMacAddr=<mac>&svpnlang=<cn|EN>&txtUsrName=<user>&txtPassword=<pass>&vldCode=<captcha>&selDomain=<domain>&selIdentity=1`
- Host-check (`check_return.cgi`): `hostcheckresult=&ActXisIns=1`

---

## 5. Credential & Challenge Crypto / Encoding

### 5.1 Wire encoding (always)
- The full `<data>` document is **URL-percent-encoded** (`URLEncoder::Encode`),
  then sent as `request=<encoded>` with `Content-Type:
  application/x-www-form-urlencoded`. V3 form values are likewise URL-encoded.
- Confidentiality is **TLS only** (GMTLS for GM gateways). The `<password>` and
  `******` literals in the binary are **debug-log masking**, not wire framing.

### 5.2 Login password — PRIMARY recovered behavior: cleartext inside TLS
Direct decompilation of `buildSslAuthPacketV7` (HttpsAuth.cpp:2050-2066) and
`FormatLoginXML` shows the raw user password is copied into `<password>` with
**no hashing/RSA/AES** at this layer — only URL-encoding. Same for the V3
`txtPassword=` field. (crypto agent, high confidence, direct code read.)

> **[UNCERTAIN — KEY ITEM TO VALIDATE LIVE]** The *docs* agent reports the
> password is **RSA-public-key-encrypted then base64** before `<password>`
> (symbols `H3C_USER_RSAKEY`/`szUserRsaKey`, `szPasswordBase64`,
> `szNewPasswordBase64`, `ER_RSA_ENCRYPT`). The crypto agent attributes those
> RSA symbols to the 802.1X/Portal (EAD) component, not the SSL VPN login path.
> **Resolution:** implement cleartext-in-TLS first (matches the traced SSL VPN
> code path); if the gateway rejects it, the gateway likely advertises an RSA
> public key and expects `base64(RSA_encrypt(pubkey, password))`. A live capture
> against the target gateway MUST settle this. Treat RSA as a configurable /
> gateway-version variant. The `<private>` blob is base64 telemetry, NOT the
> password (settled).

### 5.3 Change-password / dual-password encoding
When the `_SslvpnUser` flag at `+0xb6` is set, the password field is built by
concatenating parts with a **separator byte `0xA1`** (non-ASCII), i.e.
`0xA1 + part1 + 0xA1 + part2` (old@new), still cleartext, still TLS-only
(HttpsAuth.cpp:2057-2061). For `CHANGEPWD` the explicit XML form (separate
`<password>`/`<newPassword>`) per §4.4 is the documented path.

### 5.4 Challenge / 2FA
Server-driven SMS/OTP. **No client-side HMAC/MD5/SM3 over challenge+password.**
The user-entered code is echoed cleartext in `<code>` (and `<vldCode>` for
CAPTCHA). Types: `SMS`, `SMS-GW`, `SMS-IMC`, `PROMPTPWD`, `CHANGEPWD`.

### 5.5 `<private>` blob (`makePrivateContent`, HttpsAuth.cpp:2491-2514)
A small fixed binary struct (flags + lengths + client/OS info), zero-initialized
then filled, **base64-encoded** (`utl_base64_encode`, standard RFC4648 alphabet
`A-Za-z0-9+/`, pad `=`). Exact byte layout **[UNCERTAIN]** — needs a live capture.
An empty/placeholder `<private>` is a safe first attempt.

### 5.6 SPA knock HOTP (Zero-Trust only) — RFC 4226 HMAC-SHA1
`generateOTP(key, counter, digits, addChecksum, mode) @0x1bd70`:
```
msg     = counter as 8-byte BIG-ENDIAN
mac     = HMAC_SHA1(key=clientKey, msg)                  # 20 bytes
off     = mac[19] & 0x0f
bin     = ((mac[off]&0x7f)<<24)|(mac[off+1]<<16)|(mac[off+2]<<8)|mac[off+3]
otp     = bin % DIGITS_POWER[digits]                     # decimal string, sprintf("%d")
```
- `key` = per-client `clientKey` (from SDP registration; persisted `SdpKey-<ip>`).
- `counter` = the random uint32 `pktID` sent in clear in the packet.
- Call passes `digits=5, addChecksum=1, mode=8`; the packet copies **6 bytes**
  into the password field. **[VALIDATE]** effective digit count (5 vs 6) against
  a live knock.

### 5.7 Not used on the SSL VPN login wire (for reference)
- **Local config AES-128-CBC** (fixed): key `EC D4 4F 7B C6 DD 7D DE 2B 7B 51 AB
  4A 6F 5A 22`, IV ASCII `a@4de%#1asdfsd24` (`utl_AESCBC_Encryption`,
  utlCrypt.cpp:436). `_New` variant: same IV, caller key. On-disk only.
- **SPA "minus-one" packet AES-256-CBC**: key = `SpaRegisterParams+0x230`,
  ciphertext uppercase-hex (`utl_AES256CBC_encrypt`, utlCrypt.cpp:506).
- **TEA/XTEA** (`utl_EncryptTeaKey`): local secret obfuscation, 128-bit key,
  8-byte blocks.
- **MD5**: file-integrity; **CRC32/adler32**: zlib stream checksums.
- **GM SM2/SM3/SM4**: TLS/TLCP handshake auth only (SKF UKey / double cert);
  never transforms the app password.

---

## 6. Data-Plane Tunnel Framing

### 6.1 Upgrade
After auth, open a **new** TLS socket and send the `NET_EXTEND` request (§3.10).
The gateway replies HTTP-style, then the socket becomes a raw bidirectional
frame stream and immediately receives a type=3/sub=2 network-config frame.

### 6.2 Frame layout (both directions)
```
 offset  size  field
   0      1    type      (uint8)
   1      1    subtype   (uint8)
   2      2    length    (uint16, BIG-ENDIAN / network order) = payload byte count
   4   length  payload
```
Total frame = `length + 4`. Length read as `ntohs`. Receive buffer is `0x14000`
(81920) bytes; partial frames retained across reads, cursor advanced by
`length+4`.

| type | sub | direction | meaning | action |
|---|---|---|---|---|
| 1 | 0 | both | IP data packet | payload = raw IP packet → write to TUN (`CVirNIC::Data_Input`) |
| 2 | 1 | both | heartbeat / keepalive ack | reset no-response counter |
| 3 | 1 | gw→cl | network-config EMPTY (error) | log/ignore |
| 3 | 2 | gw→cl | network-config UPDATE | `changeVirNetWork` → reprogram IP/mask/gw/DNS/routes |
| 3 | 3 | gw→cl | network-config is DTLS | **ignored on Linux** |
| 4 | * | gw→cl | force client logoff | shutdown tunnel |

Client only **emits** type=1 (data, sub=0) and type=2 (heartbeat, sub=1).

### 6.3 Examples
```
IP data egress :  01 00 <htons(iplen)> <raw IP packet>
heartbeat      :  02 01 00 00            (4 bytes, no payload, every 1 s)
```
Egress aggregation: framed buffers are queued (`pushEntunnelQ`, cap 255), drained
into an `0x14000` big-buffer (`fillSendBigBuf`), then a single `SSL_write`.

### 6.4 Keepalive / offline (`heartBeat`, SslClient.cpp:560)
- Dedicated thread, `usleep(1_000_000)` = **1 s** loop (`SslvpnHeartBeatTimer`).
- Each tick: if `noRespCount >= maxThreshold` → user offline (notify, `usleep
  50000`, drop); else `noRespCount++` and send `02 01 00 00`.
- Any inbound frame (esp. type=2) clears the no-response state.
- `maxThreshold` is gateway-supplied (struct `+0x48`). `KEEPALIVETIME:` from the
  param block informs timing.

### 6.5 Network-config param block (`getVpnParamFromResp @0x65a88`)
Plaintext `KEY:value` lines (newline-separated). Recognized prefixes:
```
IPADDRESS:        SUBNETMASK:      GATEWAY:         PREFIXLENGTH:
DNS:              ROUTES:          EXCLUDE ROUTES:  RESTRICT:
KEEPALIVETIME:    IPV6ADDRESS:     IPV6GATEWAY:     IPV6DNS:
IPV6ROUTES:       EXCLUDE IPV6ROUTES:               IPV6RESTRICT:
```
Missing IP or GATEWAY → error. Parsed into `_tagNICInfo` (§7.2). `bDefaultGateway`
true ⇒ redirect-all; otherwise split-tunnel per `ROUTES`. **[UNCERTAIN]** whether
this block is delivered identically inside the type=3/sub=2 frame and in the
`NET_EXTEND` HTTP response (same parser is used for both) — verify on-wire
serialization (key:value text vs binary TLV) with a live capture.

### 6.6 TUN / route / DNS programming (libvnic)
```
fd = open("/dev/net/tun", O_RDWR)
ifr.ifr_flags = 0x1001                       // IFF_TUN | IFF_NO_PI
strncpy(ifr.ifr_name, "inode%d", 16)
ioctl(fd, 0x400454ca /*TUNSETIFF*/, &ifr)
// address (AF_INET ioctl socket "iocfd"):
ioctl(iocfd, 0x8916 /*SIOCSIFADDR*/,    &ifr)   // virtual IP
ioctl(iocfd, 0x891a /*SIOCSIFNETMASK*/, &ifr)   // mask
ioctl(iocfd, 0x8918 /*SIOCSIFDSTADDR*/, &ifr)   // P-t-P dst (if provided)
ioctl(iocfd, 0x891c /*SIOCSIFBRDADDR*/, &ifr)   // broadcast
ioctl(iocfd, 0x8913 /*SIOCGIFFLAGS*/,   &ifr); ifr.ifr_flags|=IFF_UP; ioctl(iocfd, 0x8914 /*SIOCSIFFLAGS*/, &ifr)
// IPv4 routes: rtnetlink — socket(AF_NETLINK=16, SOCK_RAW, NETLINK_ROUTE),
//   bind sockaddr_nl; RTM_NEWROUTE/RTM_DELROUTE with RTA_GATEWAY/RTA_METRICS.
// IPv6 routes: shell  ip -6 route add <pfx>/<len> dev <if> metric <m>
// DNS: append `nameserver <ip>` lines to /etc/resolv.conf followed by marker
//      `#Line Generated by iNode SSL VPN Client`  (v4 dns0/dns1 + IPv6 DNS)
```
No `SIOCSIFMTU` observed; MTU (if any) carried via route entry (`rt_mtu`)
**[UNCERTAIN]**.

---

## 7. Constants, Structs, State Machine

### 7.1 Constants
```
DEFAULT_PORT            = 443
HTTP_VERSION            = HTTP/1.1
UA_V7                   = SSLVPN-Client/7.0
UA_V3                   = SSLVPN-Client/3.0
UA_SPOOF                = Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.2; SV1; .NET CLR 1.1.4322; .NET CLR 2.0.50727)
VERSION_SENTINEL        = Server: SSLVPN-Gateway/7.0          (-> V7)
SUCCESS_STATUS          = "200 OK"
REDIRECT_RANGE          = 300..307
FORM_CONTENT_TYPE       = application/x-www-form-urlencoded
V7_FORM_KEY             = request=
XML_ROOT                = <data></data>
SESSION_COOKIE          = svpnginfo
CAPTCHA_COOKIES         = svpnvldid, svpnuid ; verify-code = vldID
DOMAIN_COOKIE           = domainId=<id>; authId=-1; showOption=1; saveFlag=0; UserName=
OS_FIELD                = Linux
TUNNEL_VERB             = NET_EXTEND / HTTP/1.1
PATH_INDEX              = /svpn/index.cgi
PATH_IMAGE             = /svpn/image.cgi
PATH_LOGIN_V7          = /svpn/vpnuser/check.cgi        (discovered, not hardcoded)
PATH_CHALLENGE_V7      = /svpn/vpnuser/check_return.cgi
PATH_LOGIN_V3          = /svpn/vpnuser/login_submit.cgi
PATH_OLDUSER          = /svpn/olduser_info.cgi?svpnlang=cn
PATH_KICK             = /svpn/vpnuser/kickolduser.cgi?OldUserID=<o>&NewUserID=<n>&IsKick=1&svpnlang=cn
PATH_LOGOUT          = /svpn/logout.cgi
FRAME_HEADER_LEN       = 4 ;  BIG_BUF_SIZE = 0x14000 (81920) ; ENTUNNEL_Q_MAX = 255
HEARTBEAT_FRAME        = 02 01 00 00 ; HEARTBEAT_INTERVAL = 1 s
TUN_DEVICE             = /dev/net/tun ; IFR_FLAGS = 0x1001 (IFF_TUN|IFF_NO_PI) ; TUNSETIFF = 0x400454ca
RESOLV_CONF            = /etc/resolv.conf  (marker "#Line Generated by iNode SSL VPN Client")
SPA_KNOCK_PORT_GW = 8000 ; SPA_REGISTER_PORT = 19006 ; SPA_KNOCK_PORT = 59993 ; SPA_AUTH_PORT = 443
SPA_DECLARED_LEN  = 0x0110 ; SPA_HEADER_LEN = 0x2f (47 bytes) ; SPA_AID_LEN = 32
Service-IDs: SSLVPN=7000/7001, Portal=5020, 802.1X=8021, L2TP/IPsec=2401, Wireless=1100, EAD=9019, ZeroTrust=19006
AUTHTYPE bitmask: Local=1, AD=2, LDAP=4, RADIUS=8 (15=all); shipped authMode=7
```

### 7.2 Enums
```
EHttpAuthStat:        AUTHSTAT_WAIT_CONN_RESP=0, _WAIT_REDIRECT_RESP=1, _WAIT_DOMAINLIST_RESP=2
getHttpAuthStatFromLocStr: "getinfo"->1, "getdomainlist"->2, else 0
ESvpnChallegeType:    NONE=0, SMS=1, SMS_IMC=2, PROMPTPWD=3, CHANGEPWD=4, SMS_GW=5
ESvpnChallegeResult:  SUCCESS=0, NEWCHLLENGE=1, FAILED=2
EnumSmsVender:        NO=0, IMC=1, YAXIN=2, GW=3
Wire result tokens:   Success | Challenge | CHANGEPWD | PROMPTPWD | SSLVPN_NotSupportAuthPkt
Wire type tokens:     SMS | SMS-GW | SMS-IMC | PROMPTPWD | CHANGEPWD
Frame types:          1=data, 2=heartbeat, 3=netconfig(sub1=empty,2=update,3=DTLS), 4=force-logoff
```

### 7.3 Structs (std::string = 32 bytes each)
```
_VPNLogInPacketInfoV7 (256B):  strUserName@00 strPassword@20 strVldCode@40
   strLanguage@60 strOS@80 strMacAddr@A0 strPrivate@C0 strSupportChallengePwd@E0
_VPNCahllengeAuthPacketInfo (320B): strUserName@00 strPwd@20 strType@40 strCode@60
   strVldCode@80 strLanguage@A0 strOS@C0 strMacAddr@E0 strPrivate@100 strNewPwd@120
_VPN2ndLogInPacketInfoV7 (288B): strUserName@00 strPwd@20 strType@40 strCode@60
   strVldCode@80 strLanguage@A0 strOS@C0 strMacAddr@E0 strPrivate@100
_VPNAuthUrlV7 (568B): strSupportPwdState@00 strSupportCertState@20 strSupportDKeyState@40
   strSupportVldimgState@60 strVldImgURL@80 strLoginURL@A0 strLogoutURL@C0
   CheckonlineURL@E0 str2ndLoginURL@100 str2ndChallengeType@120 str2ndChallengeMsg@140
_DomainUrlInfo (64B): strDomainName@00 strDomainUrl@20
_tagNICInfo: iLocalGatewayIP, iPhyGateway, iGateway, iSubnetMask, iSubnetMaskLen,
   virtualIP, ulDnsAddr0, ulDnsAddr1, oDnsAddrs[v4], oDnsIPv6, m_routes(vector<rte>),
   m_fallBackRoutes, ulMTU, bDefaultGateway, bChangeDns, bChangeRoute, bRouteLimit(IPv6)
NS_ROUTE::rte: dst, mask/prefixlen, gateway/nexthop, metric, rt_mtu
SpaKnockPacket: declaredLen@00(u16 BE=0x0110) clientAid[32]@02 pktID@22(u32 BE=bswap(rand))
   password[6]@26(HOTP) portCount@2c((n/2)+1) port0@2d(htons) portN[]@2f(htons)
```

### 7.4 Internal IPC (not on the network wire; for a full client clone)
- GUI ↔ daemon: FIFO bus under `/tmp/iNode/` (`iNodeCmn`/`iNodeClient`, 48-byte
  `npmsghdr{type,seq,path[32],subMod,datalen}`; subMod 5 = SSL VPN) **and** a
  local UDP command socket `127.0.0.1:50001` carrying `CPacketItem` TLV (12-byte
  big-endian header `ProtocolType/ConnectId/MsgType/MsgValue` + TLV attrs;
  ValueType 6 = integer).
- Relevant `H3C_*` MsgType codes: `MSG_FRONT_START=113`,
  `SSLVPN_QUERY_AUTH_PARAM=200`, `QUERY_DOMAIN_PARAM=201`, `QUERY_VERTIFY_PIC=202`,
  `SSLVPN_SHUTDOWN=203`, `MSG_GET_AUTH_INFO=204`, `AUTH_REQUEST=1`,
  `LOGOFF_REQ=3`, `CHALLENGE_AUTH_INFO=302`, `CHALLENGE_AUTH_RESULT=307`.
- `*.icnf` profile keys: `CONNECT_NAME, USER_NAME, PASSWORD(utl_encrpt'd),
  SAVE_PASSWORD, AUTO_AUTHEN, REMOTEIP, DOMAINID, AUTHMODE, AUTHTYPE(=15),
  AUTHNAME(=RADIUS), TLS_VERSION, CERT_TYPE, MSGAUTH, RSA, REAUTHTIMES(=3),
  REAUTHINTERVAL(=5), ROOTFILE, CLIENTFILE, CLIENTCERTPWD`.

---

## 8. Language-Agnostic Client Algorithm (end to end)

```
function sslvpn_connect(host, port=443, user, pass, domain_hint, opts):
    # --- 0. Zero-Trust SPA (only if opts.zeroTrust) ---
    if opts.zeroTrust:
        (aid, key) = sdp_register_or_load(host)         # HTTPS /api/terminal/.../register
        send_spa_knock(host, 8000, aid, key)            # §5.6 + §8.knock
        # also knock before each subsequent gateway/controller call

    # --- 1. TLS connect (auth channel) ---
    sock = tls_connect(host, port, build_ssl_ctx(opts.certs))   # verify peer + hostname

    # --- 2. discover capabilities + domains ---
    resp = http_get(sock, "/svpn/index.cgi", ua="SSLVPN-Client/7.0")
    version = "V7" if "Server: SSLVPN-Gateway/7.0" in resp else "V3"
    while status(resp) in 300..307:
        loc = header(resp,"Location"); st = classify(loc)  # getinfo/getdomainlist
        resp = http_get(sock, loc)
    assert "200 OK" in status_line(resp)
    cfg = parse_gatewayinfo(resp)        # supportPassword/Cert/DKey/vldimg + login/logout/challenge URLs
    if redirect saw "getdomainlist":
        domains = parse_domainlist(http_get(sock, domainlist_url,
                     cookie="domainId=0; authId=-1; showOption=1; saveFlag=0; UserName="))
        loginURL = pick(domains, domain_hint).url
    else:
        loginURL = cfg.login

    # --- 3. CAPTCHA ---
    vldCode = ""
    if cfg.supportvldimg == "1":
        img = http_get(sock, cfg.vldimg_url, cookie=cookies)    # Set-Cookie: vldID/svpnvldid/svpnginfo
        update_cookies(img); vldCode = solve_captcha(img.body)

    # --- 4. login ---
    xml = "<data>" +
          tag("username",user) + tag("password", encode_password(pass, cfg)) +   # §5.2 (cleartext-in-TLS; RSA variant if gateway demands)
          tag("vldCode",vldCode) + tag("language","cn") + tag("OS","Linux") +
          tag("macAddress", primary_mac()) + tag("supportChallengePwd","1") +
          tag("private", base64(make_private_blob())) + "</data>"
    body = "request=" + urlencode(xml)
    resp = http_post(sock, loginURL, body, ct="application/x-www-form-urlencoded",
                     ua="SSLVPN-Client/7.0", cookie="svpnginfo="+svpnginfo)
    svpnginfo = setcookie(resp,"svpnginfo")
    info = parse_login_result(resp)            # result/type/code/message/waitTime/intervaltime

    # --- 5. challenge / 2FA loop ---
    while info.result == "Challenge":
        prompt_user(info.type, info.message, info.waitTime)
        cx = "<data>" + tag("username",user) + tag("type",info.type) +
             tag("code", ask_code()) + tag("language","cn")
        if info.type == "SMS-IMC":   cx += tag("password", encode_password(pass,cfg))
        if info.type == "CHANGEPWD": cx += tag("password", encode_password(oldpw,cfg)) +
                                            tag("newPassword", encode_password(newpw,cfg))
        cx += tag("vldCode",vldCode)+tag("OS","Linux")+tag("macAddress",mac())+
              tag("private",base64(make_private_blob())) + "</data>"
        resp = http_post(sock, cfg.challenge,
                     "request="+urlencode(cx),
                     headers={Referer:"https://"+host+"/svpn/vpnuser/check.cgi",
                              Cookie:"svpnginfo="+svpnginfo})
        info = parse_login_result(resp)
        if info.challengeResult == FAILED(2): fail("auth failed")
        # NEWCHLLENGE(1) -> loop ; SUCCESS(0) -> info.result becomes Success
    assert info.result == "Success"

    # --- 6. optional kick-old + EAD ---
    if old_user_online():
        old = get(http_get(sock,"/svpn/olduser_info.cgi?svpnlang=cn"))
        http_get(sock,"/svpn/vpnuser/kickolduser.cgi?OldUserID="+old+"&NewUserID="+old+"&IsKick=1&svpnlang=cn")
    if opts.ead:
        http_post(sock,"/svpn/vpnuser/check_return.cgi","hostcheckresult=&ActXisIns=1")

    # --- 7. tunnel up (NEW TLS socket) ---
    if opts.zeroTrust: send_spa_knock(host, 8000, aid, key)
    tsock = tls_connect(host, port, build_ssl_ctx(opts.certs))
    send(tsock, "NET_EXTEND / HTTP/1.1\r\nHost: "+host+
                "\r\nUser-Agent: SSLVPN-Client/7.0\r\nCookie: svpnginfo="+svpnginfo+"\r\n\r\n")
    read_http_response(tsock)                  # then raw framing
    params = await_netconfig_frame(tsock)      # type=3/sub=2 -> §6.5 key:value block
    assert params.IPADDRESS and params.GATEWAY

    # --- 8. program virtual NIC ---
    tun = tun_open("inode0", IFF_TUN|IFF_NO_PI)
    set_addr(tun, params.IPADDRESS, params.SUBNETMASK); if_up(tun)
    for r in params.ROUTES:  rtnetlink_add(r)              # exclude EXCLUDE ROUTES
    if params.bDefaultGateway: add_default_via_tun()
    write_resolv_conf(params.DNS, params.IPV6DNS)

    # --- 9. data + keepalive loops ---
    spawn: every 1 s -> send_frame(tsock, type=2,sub=1,payload=())   # 02 01 00 00
    loop select(tsock, tun):
        on tsock frame (type,sub,len,payload):
            if type==1: write(tun, payload)
            elif type==2: noResp = 0
            elif type==3 and sub==2: reprogram_net(parse_block(payload))
            elif type==4: break                                   # force logoff
        on tun packet pkt:
            send_frame(tsock, type=1,sub=0,payload=pkt)           # 01 00 htons(len) pkt
        if noResp >= maxThreshold: go_offline()

    # --- 10. teardown ---
    http_get(sock, "/svpn/logout.cgi", cookie="svpnginfo="+svpnginfo)

# helper: SPA knock (Zero-Trust)
function send_spa_knock(ip, port, aid, key):
    r = random_u32()
    otp = hotp_sha1(key, counter=r, digits=6)                     # §5.6
    pkt = u16be(0x0110) + aid_padded_32(aid) + u32be(r) + otp[0:6] +
          u8((nports/2)+1) + u16be(port) [+ u16be(extra_ports)...]
    udp_sendto(ip, port, pkt)

# helper: send_frame
function send_frame(sock, type, sub, payload):
    ssl_write(sock, u8(type)+u8(sub)+u16be(len(payload))+payload)
```

---

## 9. Open Questions / Unknowns & Interop Test Plan

### 9.1 Open questions (priority order)
1. **[CRITICAL] Login password encoding.** Cleartext-in-TLS (traced SSL VPN code)
   vs RSA-pubkey+base64 (docs/strings). Resolve by capturing one real login. If
   the gatewayinfo or a separate response carries an RSA public key
   (`H3C_USER_RSAKEY`/`szUserRsaKey`), implement `base64(RSA_encrypt(pubkey,pw))`;
   else send cleartext. (crypto vs docs conflict — flagged.)
2. **`<private>` blob byte layout** (`makePrivateContent`). Likely accepted empty;
   confirm whether the gateway requires specific OS/host fields. Capture and diff.
3. **`svpnginfo` value composition** — server-issued opaque token; client just
   echoes it. Confirm it is opaque (no client derivation).
4. **Network-config serialization** inside type=3/sub=2 frame vs `NET_EXTEND`
   HTTP body — confirm both are the `KEY:value` text block parsed by the same
   `getVpnParamFromResp`, or whether the frame payload is binary/XML.
5. **V7 login URL/path** — `/svpn/vpnuser/check.cgi` is the observed value but is
   discovered from `<login>` in gatewayinfo / `<url>` in domainlist; always use
   the discovered value, not the constant.
6. **SPA HOTP digit count** (5 vs 6) and whether the gateway enforces pktID
   replay windows.
7. **macAddress format** — `AA-BB-CC-DD-EE-FF` vs `AA:BB:CC:DD:EE:FF` vs `H;`
   prefix differ between agents; try `AA-BB-CC-DD-EE-FF` first.
8. **`language` value** — `cn`/`CN`/`1` vs `en`/`EN` observed inconsistently;
   `cn` is safest default.
9. **SNI bytes** (handled in `libACE_SSL`) and exact GMTLS cipher suite list, if
   targeting a GM gateway.
10. **MTU application** path (no `SIOCSIFMTU` found).

### 9.2 Interop test plan
1. **Passive capture baseline.** Run the real iNode client against the target
   SecPath F1000 with TLS keylogging (`SSLKEYLOGFILE`) or an mitm with a trusted
   CA. Capture: index→domainlist→image→login→challenge→NET_EXTEND→frames→logout.
   This single capture resolves OQ #1, #2, #4, #7, #8 definitively.
2. **Capability probe.** `GET /svpn/index.cgi`; assert version sentinel and parse
   gatewayinfo. Verify `supportvldimg`/`supportPassword` gate the flow.
3. **Login round-trip.** Send cleartext-password login; on success proceed; on
   failure, look for an RSA key field and retry with RSA path. Compare your
   `request=` body byte-for-byte against the capture.
4. **Challenge matrix.** Test each `type`: `SMS`/`SMS-IMC` (code echo + password
   for SMS-IMC), `CHANGEPWD` (password+newPassword), `PROMPTPWD`. Verify the
   `NEWCHLLENGE`/`SUCCESS`/`FAILED` loop transitions.
5. **Tunnel bring-up.** Confirm a fresh TLS socket is required (reusing the auth
   socket should fail). Validate the first frame is type=3/sub=2 and the param
   block parses; bring up TUN and ping an intranet resource.
6. **Framing fuzz.** Verify `length` is big-endian by sending an undersized data
   frame and checking gateway behavior; confirm heartbeat `02 01 00 00` keeps the
   link alive and that stopping heartbeats triggers offline after N intervals.
7. **Route/DNS correctness.** With `bDefaultGateway=1` (full tunnel) and split
   tunnel, confirm rtnetlink routes and `/etc/resolv.conf` rewrite match the
   capture; confirm restore on logout.
8. **Zero-Trust path (if applicable).** Send the 47-byte knock to UDP/8000 and
   confirm 443 becomes reachable only after a valid HOTP; brute the digit count
   (5/6) if rejected.
9. **Negative tests.** Wrong password, expired captcha, kicked session, gateway
   force-logoff (type=4) — confirm graceful handling.

---

## 10. Confidence Summary

| Area | Confidence | Notes |
|---|---|---|
| HTTP endpoints, methods, headers, cookies | HIGH | Exact string literals, cross-agent agreement. |
| V7 XML tag names & ordering | HIGH | DWARF + decompiled `FormatLoginXML`/`FormatChallengeAuthXML`. |
| Result/type/challenge enums & state machine | HIGH | DWARF const values. |
| Tunnel framing (4-byte BE header, types 1/2/3/4) | HIGH | Both send & receive paths traced. |
| TUN/route/DNS programming | HIGH | ioctl/rtnetlink/resolv.conf literals. |
| SPA knock layout & HOTP | HIGH | `onKnockUDPMsg`+`generateOTP` traced; digit count VALIDATE. |
| **Login password = cleartext-in-TLS** | HIGH (RESOLVED) | OQ#1 settled — see Addendum A. `libiNodeSslvpnPt.so` imports **no** `RSA_public_encrypt`/`EVP_PKEY_encrypt`/`SM2_encrypt`/`EVP_EncryptInit`; `buildSslAuthPacketV7` only URL-encodes. RSA symbols are unreachable/other-module. |
| `<private>` blob contents | LOW | Layout not byte-decoded. |
| Param-block on-wire serialization (frame vs HTTP) | MEDIUM | Same parser, exact framing VALIDATE. |
```

---

## Addendum A — OQ#1 RESOLVED: login password is cleartext-in-TLS (HIGH)

Settled by adversarial re-verification of `libiNodeSslvpnPt.so`:

1. **No asymmetric/symmetric encryption is linked for the login path.** `nm -D`
   shows the lib imports **no** `RSA_public_encrypt`, `EVP_PKEY_encrypt`,
   `EVP_PKEY_CTX_*`, `SM2_encrypt`, `EVP_EncryptInit/Update`. The only crypto it
   imports is `utl_AES256CBC_encrypt` (used solely by `buildMinusOnePacket`, i.e.
   the Zero-Trust **SPA** packet — DWARF confirms `oStrEncryptContentPkt`/
   `EncryptContentLenth` are locals of `buildMinusOnePacket`), `utl_base64_*`
   (the `<private>` blob + SPA), and `EVP_PKEY_free` (TLS key mgmt).
2. **`buildSslAuthPacketV7` (HttpsAuth.cpp:2044–2147) only URL-encodes.** The
   decompiled body applies `URLEncoder::Encode` to the assembled `<data>` doc and
   `isLangCn()`/utf8 handling — no hashing/RSA/AES of `<password>`.
3. The DWARF variable names `szUserRsaKey`/`H3C_USER_RSAKEY`/`szPasswordBase64`/
   `szNewPasswordBase64` exist in `.debug_str` but their code is **not reachable
   with a linked asymmetric primitive** in this V7 Linux build (header-inlined
   from a shared `HttpsAuth` used by Portal/802.1X, or Windows/IMC-only).

**Implementation rule:** send the password **cleartext inside the TLS-protected
`<password>` element** (URL-encoded with the rest of the doc). Keep an optional
`base64(RSA_encrypt(pubkey, pw))` mode behind a flag for any future gateway that
advertises `H3C_USER_RSAKEY`, but it is **not** required for the standard V7 path.
The `<private>` element is base64 host telemetry, never the password.
