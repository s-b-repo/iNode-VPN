# H3C iNode SSL VPN — HTTPS Transport, Endpoints & Session/Cookies

Target library: `libs/libiNodeSslvpnPt.so` (ELF x86-64, **not stripped**, has DWARF).
Source files (from DWARF line info): `HttpsAuth.cpp`, `HttpsTool.cpp`, `SslClient.cpp`, plus `SslVpnXmlParser` (XML bodies).

Key classes:
- `CHttpsAuth` (singleton, `CHttpsAuth::instance()`) — builds & sends all the **auth-phase** HTTP/1.1 requests over a one-shot TLS socket (`ACE_SSL_SOCK_Stream`). Source: `HttpsAuth.cpp`.
- `CSslHttpOper` (singleton, `CSslHttpOper::instance()`) — low-level HTTP response helpers: status check, redirect detection, header parsing, chunked/Content-Length body receive. Source: `HttpsTool.cpp`.
- `CSslClient` (singleton, `CSslClient::instance()`) — builds the **tunnel handshake** (`NET_EXTEND`) and runs the persistent data tunnel + heartbeat. Source: `SslClient.cpp`.
- `CSSLVpnXmlParser` — formats/parses the V7 XML request/response bodies.

There are **two wire-protocol generations**, selected by the gateway's `Server:` response header:
- **V3 (legacy)** — form-urlencoded CGI endpoints (`login_submit.cgi`, etc.), `User-Agent: SSLVPN-Client/3.0` (or the MSIE 6.0 spoof UA).
- **V7 (modern)** — XML-in-`request=` POST bodies to URLs discovered from a domain-list XML, `User-Agent: SSLVPN-Client/7.0`, session carried in `Cookie: svpnginfo=...`.

Version is detected from the response: `getVpnVersionFromResp` looks for the literal header **`Server: SSLVPN-Gateway/7.0`** (`HttpsAuth.cpp` ~ `getVpnVersionFromResp` @ 0x52122). If present → V7, else V3.

---

## 1. TLS / transport layer

### Connection
- All auth requests go over TLS to `ACE_INET_Addr(host, port)`. Default VPN port is config-driven `iVpnServerPort`, **default 443**.
- Auth phase: `CHttpsAuth::sendAndRecvHttp(ACE_INET_Addr, request, &resp, ...)` (`HttpsAuth.cpp:2571+`) opens an `ACE_SSL_SOCK_Stream`, connects, sends the full request buffer, then calls `CSslHttpOper::recvRespData`.
- Tunnel phase: `CSslClient::conn2Remote` / `conn2RemoteReuseIP` (`SslClient.cpp:1761+` / `1851+`) establish the persistent reactor-driven SSL stream.

### SSL context — `CHttpsAuth::buildSslCtx(int authMode, const char* caCert, cert, key, encCert, encKey)` @ 0x45a36
- Standard TLS: `TLS_client_method` via `ACE_SSL_Context` / `SSL_CTX_new`.
- **GM / SM2 (ChinaTLS / GMSSL)**: uses `CNTLS_client_method`. Selected by cert type.
- Verification: `SSL_CTX_set_verify`, `SSL_CTX_set_verify_depth`, `SSL_CTX_load_verify_locations`, `SSL_get_verify_result`. Callbacks: `default_verify_callback`, `cert_verify_debug_callback` (logs Issuer/Subject/Verify/errcode/errmsg).
- **Host check**: `ACE_SSL_Context::check_host(const ACE_INET_Addr&, ssl_st*)` (DWARF symbol `_ZN15ACE_SSL_Context10check_hostERK13ACE_INET_AddrP6ssl_st`). No explicit `SSL_set_tlsext_host_name` SNI call was found in this lib (SNI handled inside ACE_SSL).
- Client certificate auth (mutual TLS):
  - File certs: `SSL_CTX_use_certificate_file` / `SSL_CTX_use_PrivateKey_file` / `SSL_CTX_check_private_key`. Supported cert containers: `.pem`, `.crt`, `.pfx`, `.p12`, `client.pem`.
  - `.pfx` / `.p12` are converted to a passwordless PEM by shelling out to the bundled openssl:
    `echo $PWD;LD_LIBRARY_PATH=./libs ./openssl pkcs12 -in "<file>" -nodes -password pass:<pw> ...` (via `system()`).
  - Cert/key paths set via `CHttpsAuth::SetCertPath / SetPrivateKeyPath / SetEncCertPath / SetEncPrivateKeyPath / SetRootCertPath / SetCertType / setTLSVersion`.

### GM SKF (USB-Key) cert — `CHttpsAuth::loadGMSKFCert(ssl_ctx_st*)` @ 0x548b8
Uses an SKF engine wrapper (`libskf_engine.so` / `libskf_wrapper.so`):
- `SKF_Library_init`, `SKF_ENGINE_init`, `SKF_UKEY_CTX_open`, `SKF_UKEY_CTX_set_PIN`, `SKF_UKEY_CTX_Verify_PIN`, `SKF_UKEY_CTX_remain_attempts`, `SKF_UKEY_CTX_set_SSL_CTX_cert`, `SKF_ENGINE_CTX_set_SSL_CTX_private_key`.
- PIN set via `CHttpsAuth::SetUSBkeyPIN(const char*)`; failure flag `m_bSKFVerifyPINFailed`, remaining-attempts `m_iSKFPINRemainCount`.
- Error-reason enum strings: `ER_GM_GET_SKF_ENGINE`, `ER_GM_LOAD_SKF_LIBRARY`, `ER_GM_OPEN_SKF_CONTAINER`, `ER_GM_VERIFY_SKF_PIN`, `ER_GM_SET_SIG_KEY_ENGINE`, `ER_GM_SET_ENC_KEY_ENGINE`, etc.
- File-based GM cert path: `CHttpsAuth::loadGMFileCert` (separate sig + enc cert/key).

---

## 2. HTTP response helpers (`CSslHttpOper`, HttpsTool.cpp)

- **`isRespSuccess(istringstream&)`** @ 0x5d62e (`HttpsTool.cpp:244`): reads the status line and checks it contains **`200 OK`**. No request line → error `svpn.httpOp.isRspSucc: http data is invalid, no request line.`
- **`needRedirection(istringstream&, std::string& newUrl)`** @ 0x5d72a (`HttpsTool.cpp:261`): parses status line after `"HTTP/1.1 "`; treats status code in **range 300..307** as a redirect (compares numeric code against `0x12b`=299 and `0x134`=308, i.e. `299 < code < 308`). Extracts the new URL from the **`Location:`** header. Errors: `svpn.httpOp.needRedirect: Location in http header is invalid.`
- **`hasHttpHeader(...)`** @ 0x5e3a8 (`HttpsTool.cpp:527`): detects body framing — looks for **`Content-Length:`** and **`chunked`** (Transfer-Encoding). Invalid length → `svpn.httpOp.hasHeader: Content-Length in http header is invalid.`
- **`recvRespData(ACE_SSL_SOCK_Stream&, std::string&, int)`** @ 0x5de3c (`HttpsTool.cpp`): receives until full body read, supports **chunked** (`praseChunkedData`) and Content-Length framing.
- **`getErrDescByID` / `getErrDescWhileCommFail`** @ 0x5eb68 / 0x5ebc6: map low-level comm failures to user-facing error descriptions.
- Cert-verify reason text: `getCertVerifyReasonText` maps `SSL_get_verify_result` codes to keys like `SSLVPN_CertVerify_Cert_Expired`, `SSLVPN_CertVerify_Untrusted_CA`, `SSLVPN_CertVerify_Signature_Invalid`, `SSLVPN_CertVerify_Cert_Chain_Not_Complete`, `SSLVPN_CertVerify_Failed`.

The redirect-target string is then classified by **`CHttpsAuth::getHttpAuthStatFromLocStr(const std::string&)`** @ 0x52262 (`HttpsAuth.cpp:2943`):
- contains `"getdomainlist"` → **1** (AUTHSTAT_WAIT_DOMAINLIST_RESP)
- contains `"getinfo"` → **2**
- otherwise → **0**

---

## 3. Cookie / session names

| Cookie name | Set by (response) | Echoed back in |
|---|---|---|
| `domainId` | selected domain id (client-chosen) | V3 GET/POST `Cookie: domainId=<id>; authId=...; showOption=...; saveFlag=0; UserName=...; svpnlang=1;` |
| `vldID` | verify-image response `Set-Cookie:` (`getVerifyPic`) | V3 login `Cookie: vldID=<v>` |
| `svpnvldid` | verify-image response `Set-Cookie:` (`getVerifyPic`) | older/kick `Cookie: svpnvldid=<v>; svpnuid=<u>` |
| `svpnuid` | verify-image / kick response | `Cookie: svpnvldid=...; svpnuid=...` |
| `svpnginfo` | **V7** login/parse response `Set-Cookie: ... svpnginfo=<info>` (parsed in `parseHttpRespV7`/`parseAuthRespMsgV7`/`getVerifyPic`) | **all V7** requests + `NET_EXTEND`: `Cookie: svpnginfo=<info>` |

The hard-coded sample cookie literal in the binary (a leftover/test value) is:
`Cookie: svpnvldid=178; svpnuid=a48eafca8822d45b88f10a2118ec8400`.

`svpnginfo` is the master V7 session token: parsed from `Set-Cookie:` (`parseHttpRespV7` @ 0x517a2, `HttpsAuth.cpp:2781`), then UTF-8/GBK converted and re-sent on every subsequent V7 HTTP request and on the tunnel `NET_EXTEND`.

`getVerifyPic` (`HttpsAuth.cpp:986`) explicitly extracts, from `Set-Cookie:`, the tokens `vldID=`, `svpnvldid=`, `svpnginfo=`; if none of `svpnvldid` is present it logs `svpn.HttpsAuth.getVerify: the response has no svpnvldid.`

---

## 4. Common HTTP request envelope literals

V3 / legacy headers (built in `buildHttpConReqV3` @ 0x522ee, `buildHttpRedirectV3` @ 0x525c4, etc.):
```
<METHOD> <path> HTTP/1.1\r\n
Accept: application/x-shockwave-flash, image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, */*\r\n
UA-CPU: x86\r\n
Accept-Encoding: gzip, deflate\r\n
User-Agent: SSLVPN-Client/3.0\r\n          (some requests use the MSIE 6.0 spoof UA below)
Host: <host>\r\n
Connection: Keep-Alive\r\n
Accept-Language: zh-cn\r\n\r\n
```
MSIE spoof UA literal: `User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.2; SV1; .NET CLR 1.1.4322; .NET CLR 2.0.50727)\r\n`

V7 headers (built in `buildHttpConReqV7` @ 0x524ca, `buildVldImgReqV7`, `buildSslAuthPacketV7`, etc.):
```
<METHOD> <path> HTTP/1.1\r\n
Host: <host>\r\n
Connection: Keep-Alive\r\n
User-Agent: SSLVPN-Client/7.0\r\n
Cookie: svpnginfo=<svpnginfo>\r\n        (when a session exists)
Content-Type: application/x-www-form-urlencoded   (POST only, implied; Content-Length always sent on POST)
Content-Length: <n>\r\n
\r\n
<body>
```
Note: `buildHttpConReqV3`'s default request path is `/svpn/index.cgi` (literal at 0x81671). The `Host:` value is the gateway host string the caller passes in.

---

## 5. Endpoint catalogue (exact literals)

### V3 (legacy CGI, application/x-www-form-urlencoded)

1. **Index / entry page** — `GET /svpn/index.cgi HTTP/1.1` (default path of `buildHttpConReqV3`). First request; gateway replies 30x → `Location` → drives state machine (`getdomainlist` / `getinfo`).

2. **Domain list** — `getDomainParams` @ 0x48440 (`HttpsAuth.cpp:827`):
   `GET <url> HTTP/1.1` with header
   `Cookie: domainId=<id>; authId=-1; showOption=1; saveFlag=0; UserName=\r\n\r\n`

3. **Verify (CAPTCHA) image** — `buildVldImgReqV3` @ 0x50b86:
   `GET /svpn/image.cgi HTTP/1.1` + `Referer: https://<host>:<port>/svpn/index.cgi`, `Accept: */*`, `Connection: Keep-Alive\r\n\r\n`.
   Response `Set-Cookie:` provides `vldID` / `svpnvldid` (parsed by `getVerifyPic`).

4. **Login** — `buildSslAuthPacketV3` @ 0x4fb76:
   ```
   POST /svpn/vpnuser/login_submit.cgi HTTP/1.1\r\n
   Accept: application/x-shockwave-flash, ...\r\n
   Referer: https://<host>:<port>/svpn/index.cgi\r\n
   Accept-Language: zh-cn\r\n
   Content-Type: application/x-www-form-urlencoded\r\n
   UA-CPU: x86\r\n
   Accept-Encoding: gzip, deflate\r\n
   User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; ...)\r\n
   Host: <host>\r\n
   Content-Length: <n>\r\n
   Connection: Keep-Alive\r\n
   Cache-Control: no-cache\r\n
   Cookie: vldID=<v>; domainId=<id>; authId=...; showOption=0; saveFlag=0; UserName=...; vldID=...\r\n\r\n
   ```
   Body (form-urlencoded): `txtMacAddr=<mac>&svpnlang=<cn|EN>&txtUsrName=<user>&txtPassword=<pass>&vldCode=<captcha>&selDomain=<domain>&selIdentity=1`
   (template literals: `txtMacAddr=`, `&svpnlang=`, `&txtUsrName=`, `&txtPassword=`, `&vldCode=`, `&selDomain=`, `&selIdentity=1`; guest fallback literal `&txtUsrName=guest&txtPassword=guest`).

5. **Security check / EAD result** — `sendCheckResult` @ 0x4ca02:
   `POST /svpn/vpnuser/check_return.cgi HTTP/1.1` with `Content-Type: application/x-www-form-urlencoded`,
   `Referer: https://<host>:<port>/svpn/vpnuser/check.cgi`,
   `Cookie: domainId=<id>; authId=...; showOption=0; saveFlag=0; UserName=; svpnlang=1; ...`
   Body literal: `hostcheckresult=&ActXisIns=1`.

6. **Kick old login** — `kickOldLogin` @ 0x5348a:
   - First `GET /svpn/olduser_info.cgi?svpnlang=cn HTTP/1.1` (parses `var arrOldUserInfo=new Array(...)` JS array + `Set-Cookie:`), then
   - `GET /svpn/vpnuser/kickolduser.cgi?OldUserID=<old>&NewUserID=<new>&IsKick=1&svpnlang=cn HTTP/1.1`
     with `Cookie: svpnvldid=...; svpnuid=...` and `Referer: https://...`.

7. **Logout** — `buildLogOutReqV3` @ 0x50368:
   `GET /svpn/logout.cgi HTTP/1.1` with `Cookie: domainId=<id>; authId=...; showOption=0; saveFlag=0; UserName=; svpnlang=1; ...`.

### V7 (XML in `request=` body)

1. **Index / domain list discovery** — `GET /svpn/index.cgi HTTP/1.1` (V7 envelope). 30x redirect (`getdomainlist`) → fetch domain-list XML. `getAuthParams` @ 0x47296 + `parseHttpRespV7` @ 0x517a2 extract the `<data>...</data>` XML; `CSSLVpnXmlParser::GetDomainListInfo` parses `<domainlist><data><domain><name>..</name><url>..</url></domain>...`. The selected domain's `<url>` is the **login URL** used for the POST.

2. **Verify image (V7)** — `buildVldImgReqV7` @ 0x50cac:
   `GET <imageUrl> HTTP/1.1` + `Host:`, `Connection: Keep-Alive`, `User-Agent: SSLVPN-Client/7.0`, `Cookie: svpnginfo=<info>`.

3. **Login (V7)** — `buildSslAuthPacketV7` @ 0x4dfee:
   ```
   POST <loginUrl> HTTP/1.1\r\n
   Host: <host>\r\n
   Connection: Keep-Alive\r\n
   User-Agent: SSLVPN-Client/7.0\r\n
   Cookie: svpnginfo=<info>\r\n
   Content-Length: <n>\r\n
   \r\n
   request=<URL-ENCODED-XML>
   ```
   The XML body (`CSSLVpnXmlParser::FormatLoginXML` @ 0x736e6) is:
   ```xml
   <data>
     <username>USER</username>
     <password>PASS</password>
     <vldCode>CAPTCHA</vldCode>
     <language>CN|EN</language>
     <OS>Linux</OS>
     <macAddress>H;AA-BB-CC-DD-EE-FF</macAddress>
     <supportChallengePwd>1</supportChallengePwd>
     <private>...</private>
   </data>
   ```
   It is **URL-encoded** before sending; e.g. `<password>` → `%3Cpassword%3E`, `</password>` → `%3C%2Fpassword%3E` (seen in `syncSendAuthReq`). `request=` is the form key.

4. **Challenge / 2FA (V7)** — login response may be `Challenge` (SMS dynamic password), `CHANGEPWD`, or `PROMPTPWD` (parsed in `parseAuthRespMsgV7` @ 0x49c3c). Reply POST built by `buildSslChallengeAuthPacketV7` @ 0x54bf0 / `buildSsl2ndAuthPacketV7` @ 0x4ec7e — same V7 envelope (`POST <url>`, `Cookie: svpnginfo=`, `request=<xml>`).
   Challenge XML (`FormatChallengeAuthXML` @ 0x74440):
   ```xml
   <data>
     <username>USER</username>
     <type>SMS|SMS-GW|SMS-IMC|CHANGEPWD|PROMPTPWD</type>
     <code>SMSCODE</code>
     <language>..</language>
     <password>OLD</password>      <!-- for CHANGEPWD -->
     <newPassword>NEW</newPassword> <!-- for CHANGEPWD -->
     <vldCode>..</vldCode>
     <OS>Linux</OS>
     <macAddress>H;..</macAddress>
     <private>..</private>
   </data>
   ```
   Second-factor XML (`Format2ndLoginXML` @ 0x7392e) is similar with `<username><type><code><language><password><vldCode><OS><macAddress><private>`. Passwords/codes are URL-encoded (`<code>`→`%3Ccode%3E`, etc).

5. **Logout (V7)** — `buildLogOutReqV7` @ 0x50646:
   `GET /svpn/logout.cgi HTTP/1.1` + `User-Agent: SSLVPN-Client/7.0`, `Cookie: svpnginfo=<info>`.

### Login response result tokens (V7, `parseAuthRespMsgV7`/`GetLogInInfo`)
Parsed XML `<data><result>..</result><replyMessage>..</replyMessage>...`. Result strings: **`Success`**, **`Challenge`**, **`CHANGEPWD`**, **`PROMPTPWD`**, `SSLVPN_NotSupportAuthPkt`. Challenge sub-types: `SMS`, `SMS-GW`, `SMS-IMC`. `GetLogInInfo` fields: `result`, `replyMessage`, `EMOServer`, `private`, `type`, `message`, `smsDynamicPwdd`, `waitTime`, `intervaltime`.

---

## 6. Tunnel establishment — `NET_EXTEND` (CSslClient, SslClient.cpp)

After auth success, `CSslClient::conn2Remote` (`SslClient.cpp:1761`) opens a **new** persistent SSL stream to the gateway and sends the tunnel handshake built by `CSslClient::buildIPHandshakeReq` @ 0x657e6 (`SslClient.cpp:1177`):

**V7 form:**
```
NET_EXTEND / HTTP/1.1\r\n
Host: <host>\r\n
User-Agent: SSLVPN-Client/7.0\r\n
Cookie: svpnginfo=<info>\r\n
\r\n
```

**Legacy form** (single-line cookie):
```
NET_EXTEND / HTTP/1.1\r\nCookie:<cookie>\r\n\r\n
```
(literal `NET_EXTEND / HTTP/1.1\r\nCookie:` at 0x841a0.)

The gateway response to `NET_EXTEND` is a **plaintext key:value param block** parsed by `CSslClient::getVpnParamFromResp` @ 0x65a88 (and `getVpnAllocParam` @ 0x6508e). Recognized line prefixes:
```
IPADDRESS:        SUBNETMASK:      GATEWAY:        PREFIXLENGTH:
DNS:              ROUTES:          EXCLUDE ROUTES: RESTRICT:
KEEPALIVETIME:    IPV6ADDRESS:     IPV6GATEWAY:    IPV6DNS:
IPV6ROUTES:       EXCLUDE IPV6ROUTES:   IPV6RESTRICT:
```
Missing IP/gateway → `CSslClient::getVpnParamFromResp the response has no ip or gateway.`
On success → `CSslClient::conn2Remote SSLVPN Tunnel Build SUCCESSFULLY.` A heartbeat timer (`startHeartBeat`/`heartBeat`) keeps the tunnel up (`KEEPALIVETIME:`), and `CSslClient::changeVirNetwork` configures the virtual NIC. `conn2RemoteReuseIP` re-establishes preserving the previous IP.

---

## 7. Auth state machine (ordered exchange, connect → tunnel-up)

State enums seen: `AUTHSTAT_WAIT_DOMAINLIST_RESP`, `AUTHSTAT_WAIT_REDIRECT_RESP`. Driver: `CHttpsAuth::doAuth` @ 0x4b860 (`HttpsAuth.cpp:1600+`) → `syncSendAuthReq` @ 0x4d038.

```
1. TLS connect to <host>:<port=443>  (buildSslCtx; verify peer cert + check_host)

2. GET /svpn/index.cgi HTTP/1.1
   -> 30x with Location:  --> getHttpAuthStatFromLocStr():
        "getdomainlist" => state 1
        "getinfo"       => state 2
   -> Server: SSLVPN-Gateway/7.0 header decides V7 vs V3 (getVpnVersionFromResp)

3. (follow redirects via needRedirection + buildHttpRedirectV3 until 200 OK)

4. getDomainParams: GET <domainlist-url>  (Cookie: domainId=...)
   -> 200 OK, XML <domainlist>; client picks a <domain> + its <url> (login URL)

5. [optional] GET /svpn/image.cgi (V3) or <imageUrl> (V7)  -- CAPTCHA
   -> Set-Cookie: vldID / svpnvldid / svpnginfo  (getVerifyPic)

6. LOGIN:
   V3: POST /svpn/vpnuser/login_submit.cgi  (form: txtUsrName/txtPassword/vldCode/selDomain/...)
   V7: POST <loginUrl>  body=request=<urlencoded login XML>  (Cookie: svpnginfo=)
   -> Set-Cookie: ... svpnginfo=<info>  (V7 session established; parseHttpRespV7/parseAuthRespMsgV7)
   -> result tokens: Success | Challenge | CHANGEPWD | PROMPTPWD

7. [if Challenge/CHANGEPWD/PROMPTPWD]:
   V7: POST <url> body=request=<challenge/2nd-auth XML>  (SMS code / new password)
   -> loop until Success

8. [optional] kickOldLogin:
   GET /svpn/olduser_info.cgi?svpnlang=cn  ->  GET /svpn/vpnuser/kickolduser.cgi?OldUserID=&NewUserID=&IsKick=1&svpnlang=cn

9. [optional] Security/EAD check:
   POST /svpn/vpnuser/check_return.cgi   body=hostcheckresult=&ActXisIns=1

10. TUNNEL UP (new SSL stream, CSslClient::conn2Remote):
    NET_EXTEND / HTTP/1.1  (Cookie: svpnginfo=<info>)
    -> plaintext param block: IPADDRESS:/SUBNETMASK:/GATEWAY:/DNS:/ROUTES:/KEEPALIVETIME:/...
    -> configure virtual NIC (changeVirNetwork), start heartBeat  => "SSLVPN Tunnel Build SUCCESSFULLY."

11. LOGOUT (teardown):
    V3: GET /svpn/logout.cgi (Cookie: domainId=...)
    V7: GET /svpn/logout.cgi (Cookie: svpnginfo=...)
```

SPA / port-knock (pre-connect) handled by `CSslClient::spaDoCamsNotify` / `CHttpsAuth::doCamsNotify` (UDP knock to `iSpaKnocksPort` / `iSpaAuthPort`) — out of scope for the HTTP layer but precedes step 1 when SPA is enabled.

---

## 8. Constants summary

| Constant | Value | Meaning |
|---|---|---|
| Default port | `443` | `iVpnServerPort` |
| HTTP version | `HTTP/1.1` | all requests |
| V3 UA | `SSLVPN-Client/3.0` | legacy |
| V7 UA | `SSLVPN-Client/7.0` | modern |
| Spoof UA | `Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.2; SV1; ...)` | V3 login/image/check/kick/logout |
| Success status | `200 OK` | isRespSuccess |
| Redirect range | `300..307` (`299 < code < 308`) | needRedirection |
| Version sentinel | `Server: SSLVPN-Gateway/7.0` | V7 detection |
| Form content type | `application/x-www-form-urlencoded` | POST bodies |
| V7 POST form key | `request=` | wraps URL-encoded XML |
| Session cookie | `svpnginfo` | V7 master token |
| Tunnel verb | `NET_EXTEND / HTTP/1.1` | data tunnel handshake |
