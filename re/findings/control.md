# H3C iNode SSL VPN — Control Plane & XML Protocol (KEY=control)

Target lib: `libs/libiNodeSslvpnPt.so` (ELF64, not stripped, DWARF present).
Primary source files: `SslVpnXmlParser.cpp`, `SslvpnMgr.cpp`, `HttpsAuth.cpp`.

The control plane is an HTTPS request/response protocol. All request bodies are
TinyXML documents whose **root element is `<data>`** ("inodexml" = vendored TinyXML).
The XML is **URL-encoded** (`URLEncoder::Encode`) and sent in an
`application/x-www-form-urlencoded` POST body as `request=<urlencoded-xml>`.

There are two protocol generations:
- **V3 (legacy)**: classic HTML-form POST with `txt*`/`sel*` fields.
- **V7 (current)**: `<data>` XML wrapped in `request=` + cookies. This is the focus.

---

## 1. HTTP Endpoints (CGI paths)

| Path | Method | Purpose |
|------|--------|---------|
| `/svpn/index.cgi` | GET | Initial gateway-info / param query (V7 ConReq); also redirect target base |
| `/svpn/vpnuser/check.cgi` | POST | V7 first-stage login (path taken from `strLoginURL` in gatewayinfo; Referer points here) |
| `/svpn/vpnuser/check_return.cgi` | POST | V7 second-stage / challenge auth (2FA, change-pwd) |
| `/svpn/vpnuser/login_submit.cgi` | POST | V3 legacy form login |
| `/svpn/image.cgi` | GET | Verify picture (captcha) image |
| `/svpn/olduser_info.cgi?svpnlang=cn` | GET | Query the already-logged-in (old) user before kick |
| `/svpn/vpnuser/kickolduser.cgi?OldUserID=<id>&NewUserID=<id>&IsKick=1&svpnlang=cn` | GET | Kick old session |
| `/svpn/logout.cgi` | GET | Logout |
| `NET_EXTEND / HTTP/1.1` | (custom) | Tunnel establishment after auth (data plane handoff) |

`svpnlang=cn` (Chinese) or `en` is appended via `isLangCn()`.

---

## 2. V7 HTTP request templates

### 2.1 GET gateway-param request (`buildHttpConReqV7`, HttpsAuth.cpp:2991)
```
GET <path> HTTP/1.1\r\n
Host: <host>\r\n
Connection: Keep-Alive\r\n
User-Agent: SSLVPN-Client/7.0\r\n
\r\n
```
`<path>` is `/svpn/index.cgi` for the initial param query.

### 2.2 V3 GET (`buildHttpConReqV3`, HttpsAuth.cpp:2961) — legacy
```
GET /svpn/index.cgi HTTP/1.1\r\n
Accept: application/x-shockwave-flash, image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, */*\r\n
UA-CPU: x86\r\n
Accept-Encoding: gzip, deflate\r\n
User-Agent: SSLVPN-Client/3.0\r\n
Host: <host>\r\n
Connection: Keep-Alive\r\n
Accept-Language: zh-cn\r\n
\r\n
```

### 2.3 V7 first-stage login POST (`buildSslAuthPacketV7`, HttpsAuth.cpp:2044)
```
POST <loginURL> HTTP/1.1\r\n
Host: <host>\r\n
... (Accept / UA etc.) ...
Cookie: svpnginfo=<svpnginfo>\r\n
Content-Type: application/x-www-form-urlencoded\r\n
Content-Length: <len>\r\n
\r\n
request=<URL-encoded login XML>
```
The body is exactly `request=` followed by `URLEncoder::Encode(<data>...</data>)`.
For logging, the `<password>...</password>` span (URL-encoded
`%3Cpassword%3E...%3C%2Fpassword%3E`) is replaced with `******`
(`svpn.HttpsAuth.buildAuthPktV7:` log line).

### 2.4 V7 challenge / 2nd-stage POST (`buildSslChallengeAuthPacketV7`/`buildSsl2ndAuthPacketV7`, HttpsAuth.cpp:3652/...)
```
POST /svpn/vpnuser/check_return.cgi HTTP/1.1\r\n
Referer: https://<host>/svpn/vpnuser/check.cgi\r\n
Host: <host>\r\n
Cookie: svpnginfo=<svpnginfo>\r\n
Content-Type: application/x-www-form-urlencoded\r\n
Content-Length: <len>\r\n
\r\n
request=<URL-encoded challenge XML>
```

### 2.5 V3 legacy login POST (`buildSslAuthPacketV3`, HttpsAuth.cpp:2290)
```
POST /svpn/vpnuser/login_submit.cgi HTTP/1.1\r\n
Accept: application/x-shockwave-flash, ... */*\r\n
Referer: https://<host>/svpn/index.cgi\r\n
Accept-Language: zh-cn\r\n
Content-Type: application/x-www-form-urlencoded\r\n
UA-CPU: x86\r\n
Accept-Encoding: gzip, deflate\r\n
User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.2; SV1; .NET CLR 1.1.4322; .NET CLR 2.0.50727)\r\n
Connection: Keep-Alive\r\n
Cache-Control: no-cache\r\n
...
\r\n
txtMacAddr=<mac>&txtUsrName=<user>&txtPassword=<pw>&selDomain=<dom>&selIdentity=1&svpnlang=cn
```
Legacy form field names: `txtMacAddr=`, `&txtUsrName=`, `&txtPassword=`,
`&selDomain=`, `&selIdentity=1`, `&svpnlang=cn`.

### 2.6 Captcha GET (`getVerifyPic`, HttpsAuth.cpp:986)
```
GET /svpn/image.cgi HTTP/1.1\r\n
Accept: */*\r\n
Cookie: svpnvldid=<id>; svpnuid=<uid>\r\n   (example: svpnvldid=178; svpnuid=a48eafca8822d45b88f10a2118ec8400)
Connection: Keep-Alive\r\n
\r\n
```

### 2.7 Domain-param cookie (`getDomainParams`, HttpsAuth.cpp)
```
Cookie: domainId=<id>; authId=-1; showOption=1; saveFlag=0; UserName=\r\n\r\n
```

---

## 3. Cookies / session

- **`svpnginfo=<value>`** — primary session/gateway cookie, sent on every authenticated POST.
- **`svpnvldid=<n>`, `svpnuid=<hex>`** — verify-image session (captcha) cookies.
- **`vldID=<n>`** — verify-code id cookie.
- **`domainId=<id>`** — selected domain (sent with `authId=-1; showOption=1; saveFlag=0; UserName=`).
- Responses carry `Set-Cookie:` headers. The parser scans `Set-Cookie:` lines and
  extracts `vldID=`, `svpnvldid=`, `svpnginfo=` tokens (HttpsAuth.cpp:1058+, 1077+, 1083+, 1089+).

---

## 4. XML request templates (root `<data>`)

`CBasedTXmlParser::AddItem(tag, value)` adds a child element of `<data>`; ordering below
is the exact emission order from the binary.

### 4.1 FormatLoginXML (`SslVpnXmlParser.cpp:27`, addr 0x736e6) — struct `_VPNLogInPacketInfoV7`
```xml
<data>
  <username>...</username>            <!-- strUserName  @0x00 -->
  <password>...</password>            <!-- strPassword  @0x20 -->
  <vldCode>...</vldCode>              <!-- strVldCode   @0x40 (captcha code) -->
  <language>...</language>            <!-- strLanguage  @0x60 -->
  <OS>...</OS>                        <!-- strOS        @0x80 (e.g. "Linux") -->
  <macAddress>...</macAddress>        <!-- strMacAddr   @0xA0 -->
  <supportChallengePwd>...</supportChallengePwd> <!-- strSupportChallengePwd @0xE0 -->
  <private>...</private>              <!-- strPrivate   @0xC0 -->
</data>
```
(Emission order in code: username, password, vldCode, language, OS, macAddress,
supportChallengePwd, private.)

### 4.2 Format2ndLoginXML (`SslVpnXmlParser.cpp:61`, addr 0x7392e) — struct `_VPN2ndLogInPacketInfoV7`, arg `EnumSmsVender`
```xml
<data>
  <username>...</username>     <!-- strUserName @0x00 -->
  <type>...</type>             <!-- strType     @0x40 (e.g. SMS-IMC / CHANGEPWD) -->
  <code>...</code>             <!-- strCode     @0x60 (challenge code/echo) -->
  <language>...</language>     <!-- strLanguage @0xA0 -->
  <!-- if EnumSmsVender == SSLVPN_SMS_IMC (1): extra branch -->
  <password>...</password>     <!-- strPwd      @0x20 -->
  <vldCode>...</vldCode>       <!-- strVldCode  @0x80 -->
  <OS>...</OS>                 <!-- strOS       @0xC0 -->
  <macAddress>...</macAddress> <!-- strMacAddr  @0xE0 -->
  <private>...</private>       <!-- strPrivate  @0x100 -->
</data>
```

### 4.3 FormatChallengeAuthXML (`SslVpnXmlParser.cpp:216`, addr 0x74440) — struct `_VPNCahllengeAuthPacketInfo`
Always emitted: `username`, `type`, `code`, `language`.
Then branches on the `type` value (`strType` @0x40):

- **type == "SMS-IMC"** (SslVpnXmlParser.cpp:233): add `password`(@0x20).
- **type == "CHANGEPWD"** (SslVpnXmlParser.cpp:235-238): add `password`(@0x20, the OLD pwd)
  then `newPassword`(strNewPwd @0x120).
- All paths then add: `vldCode`(@0x80), `language`(@0xA0), `OS`(@0xC0),
  `macAddress`(@0xE0), `private`(@0x100).

```xml
<data>
  <username>...</username>
  <type>SMS-IMC | CHANGEPWD | ...</type>
  <code>...</code>
  <language>...</language>
  <password>...</password>          <!-- when SMS-IMC or CHANGEPWD -->
  <newPassword>...</newPassword>    <!-- only when CHANGEPWD -->
  <vldCode>...</vldCode>
  <OS>...</OS>
  <macAddress>...</macAddress>
  <private>...</private>
</data>
```

---

## 5. XML response parsers

### 5.1 GetVpnConnInfo (`SslVpnXmlParser.cpp:145`, addr 0x73f30) — gateway capabilities
Path: `<data><gatewayinfo>...` then `<auth>` sub-element (offset +0xa0 = `auth`).
Node values read into `_VPNAuthUrlV7`:
| XML tag | struct field |
|---------|--------------|
| `supportPassword` | strSupportPwdState @0x00 |
| `supportCert`     | strSupportCertState @0x20 |
| `supportDKey`     | strSupportDKeyState @0x40 |
| `supportvldimg`   | strSupportVldimgState @0x60 |
| `vldimg` (attr `url`) | strVldImgURL @0x80 |
| `login`     | strLoginURL @0xA0 |
| `logout`    | strLogoutURL @0xC0 |
| `challenge` | CheckonlineURL/challenge URL @0xE0 |

### 5.2 GetDomainListInfo (`SslVpnXmlParser.cpp:106`, addr 0x73bf4) — domain list
Path: `<data><domainlist>` then iterate `<domain>` siblings; for each:
`<name>` → strDomainName, `<url>` → strDomainUrl (struct `_DomainUrlInfo`, 64 bytes).
Log: `svpn.xml.getDomainList: %s get Domain %s, with URL %s`.

### 5.3 GetLogInInfo (`SslVpnXmlParser.cpp:183`, addr 0x741e4) — login/challenge result
Path: `<data>`; node values read into `_VPNAuthUrlV7`:
| XML tag | meaning |
|---------|---------|
| `result` | "Success" / "Challenge" (overall auth status) |
| `replyMessage` | server message |
| `EMOServer` | EMO server addr |
| `private` | private data blob (size 0x820) |
| `type` | challenge type (SMS/SMS-IMC/CHANGEPWD/PROMPTPWD/SMS-GW) |
| `message` | display message |
| `smsDynamicPwdd` | sms dynamic pwd flag |
| `waitTime` | (int) wait before retry |
| `intervaltime` | (int) resend interval |

(also a node assigned via `operator=` literal around line 204.)

### 5.4 parseAuthRespMsgV7 (`HttpsAuth.cpp:1125`, addr 0x49c3c) — top-level response classifier
- Scans `Set-Cookie:` headers for session cookies.
- `result` field compared (strcmp) against **`Success`** and **`Challenge`**.
- If Challenge, `type` field compared against: **`SMS`**, **`SMS-GW`**, **`SMS-IMC`**,
  **`PROMPTPWD`**, **`CHANGEPWD`**. Unknown → log
  `CHttpsAuth::parseAuthRespMsgV7: unknown challenge type %s.` and fail (err `SSLVPN_NotSupportAuthPkt`).

---

## 6. Enums (from DWARF)

### ESvpnChallegeType (offset 0x31c94)
```
SVPN_CHALLENGE_NONE      = 0
SVPN_CHALLENGE_SMS       = 1
SVPN_CHALLENGE_SMS_IMC   = 2
SVPN_CHALLENGE_PROMPTPWD = 3
SVPN_CHALLENGE_CHANGEPWD = 4
SVPN_CHALLENGE_SMS_GW    = 5
```
Wire `type` string mapping: `SMS`→SMS, `SMS-GW`→SMS_GW, `SMS-IMC`→SMS_IMC,
`PROMPTPWD`→PROMPTPWD, `CHANGEPWD`→CHANGEPWD.

### ESvpnChallegeResult (offset 0x76608)
```
SVPN_CHALLENGE_RET_SUCCESS     = 0
SVPN_CHALLENGE_RET_NEWCHLLENGE = 1
SVPN_CHALLENGE_RET_FAILED      = 2
```

### EnumSmsVender (offset 0x74a66)
```
SSLVPN_SMS_NO    = 0
SSLVPN_SMS_IMC   = 1
SSLVPN_SMS_YAXIN = 2
SSLVPN_SMS_GW    = 3
```

### EHttpAuthStat / AUTHSTAT_* (offset 0x2618f) — auth state machine
```
AUTHSTAT_WAIT_CONN_RESP       = 0   (waiting for /svpn/index.cgi gatewayinfo)
AUTHSTAT_WAIT_REDIRECT_RESP   = 1   (waiting for redirect "getinfo")
AUTHSTAT_WAIT_DOMAINLIST_RESP = 2   (waiting for "getdomainlist")
```
`getHttpAuthStatFromLocStr(location)` (HttpsAuth.cpp:2943): if location contains
`getdomainlist` → state 2; if `getinfo` → state 1; else default 0.

---

## 7. Auth state machine (control flow)

```
START
  └─ GET /svpn/index.cgi  (buildHttpConReqV7)            [AUTHSTAT_WAIT_CONN_RESP]
       └─ resp: <data><gatewayinfo><auth>...  → GetVpnConnInfo
            (supportPassword/Cert/DKey/vldimg, login/logout/challenge URLs)
       └─ may 302/redirect; getHttpAuthStatFromLocStr(location):
            "getinfo"       → AUTHSTAT_WAIT_REDIRECT_RESP (re-query params)
            "getdomainlist" → AUTHSTAT_WAIT_DOMAINLIST_RESP
                 └─ resp: <data><domainlist><domain>... → GetDomainListInfo
       └─ (if supportvldimg) GET /svpn/image.cgi → captcha (getVerifyPic)
  └─ POST <loginURL e.g. /svpn/vpnuser/check.cgi>        (buildSslAuthPacketV7)
       body = request=URLENC(<data>username,password,vldCode,language,OS,
                              macAddress,supportChallengePwd,private</data>)
       └─ resp → parseAuthRespMsgV7 → GetLogInInfo
            result == "Success"  → AUTHENTICATED → NET_EXTEND tunnel
            result == "Challenge"→ type ∈ {SMS,SMS-IMC,SMS-GW,PROMPTPWD,CHANGEPWD}
                 └─ UI prompt (SendChallengeAuthInfo to iNodeClient over IPC)
                 └─ POST /svpn/vpnuser/check_return.cgi  (buildSslChallengeAuthPacketV7)
                      body = request=URLENC(<data>username,type,code,language,
                                            [password],[newPassword],vldCode,OS,
                                            macAddress,private</data>)
                      └─ resp result: Success | NewChallenge(loop) | Failed
  └─ on success: kick old user if needed (olduser_info.cgi / kickolduser.cgi)
  └─ NET_EXTEND / HTTP/1.1  + Cookie: <svpnginfo>  → start data tunnel
  └─ logout: GET /svpn/logout.cgi
```

Manager driver: `CSslVpnMgr::startConn` (0x76e46), `queryVpnPara` (0x7c5ee),
`queryVpnAuthParam` (0x79fb4), `queryDomainParam` (0x7b094),
`queryVertifyPic` (0x799e6), `syncModifyPwd` (0x7e43c).
IPC to UI: `SendChallengeAuthInfo`
(`SendChallengeAuthInfo: connid = %u, challengeType = %d, smsType = %d, waittime = %d, intervaltime = %d, challengeMsg = %s.`)
and `SendChallengeAuthResult`
(`SendChallengeAuthResult: connid = %u, challengeType = %d, challengeResult = %d.`).

---

## 8. Structs (from DWARF)

### _VPNLogInPacketInfoV7 (256 bytes) — each std::string is 32 bytes
```
+0x00 std::string strUserName
+0x20 std::string strPassword
+0x40 std::string strVldCode            (captcha code)
+0x60 std::string strLanguage
+0x80 std::string strOS                 ("Linux")
+0xA0 std::string strMacAddr
+0xC0 std::string strPrivate
+0xE0 std::string strSupportChallengePwd
```

### _VPN2ndLogInPacketInfoV7 (288 bytes)
```
+0x00 strUserName  +0x20 strPwd  +0x40 strType  +0x60 strCode
+0x80 strVldCode   +0xA0 strLanguage  +0xC0 strOS  +0xE0 strMacAddr
+0x100 strPrivate
```

### _VPNCahllengeAuthPacketInfo (320 bytes)
```
+0x00 strUserName  +0x20 strPwd  +0x40 strType  +0x60 strCode
+0x80 strVldCode   +0xA0 strLanguage  +0xC0 strOS  +0xE0 strMacAddr
+0x100 strPrivate  +0x120 strNewPwd
```

### _VPNAuthUrlV7 (568 bytes)
```
+0x00  strSupportPwdState
+0x20  strSupportCertState
+0x40  strSupportDKeyState
+0x60  strSupportVldimgState
+0x80  strVldImgURL
+0xA0  strLoginURL
+0xC0  strLogoutURL
+0xE0  CheckonlineURL
+0x100 str2ndLoginURL
+0x120 str2ndChallengeType
+0x140 str2ndChallengeMsg
```

### _DomainUrlInfo (64 bytes)
```
+0x00 strDomainName   +0x20 strDomainUrl
```

### _VPNAuthParams (224 bytes)
```
+0x00  ESslVpnVersion eVersion
+0x08  std::string strLocation       (redirect location)
+0x28  std::string strVerifyPic      (captcha image bytes/b64)
+0x48  std::string strVpnID
+0x68  map oDomainMap                (domain name -> url)
+0x98  map oAuthTypeMap
+0xC8  int iDftAuthType
+0xCC  int iSupportPwd
+0xD0  int iSupportCert
+0xD4  int iVerifyCodeState
+0xD8  int iDKeyState
```

---

## 9. Crypto / encoding notes

- Request XML bodies are **URL-encoded** with `URLEncoder::Encode(const std::string&)`
  before being placed in `request=`. The whole `<data>...</data>` doc is encoded,
  hence `<password>` → `%3Cpassword%3E`.
- `utl_base64_encode` is imported and used (captcha image / private blobs).
- TLS is via libACE_SSL / OpenSSL 1.1; SM2/SKF (Chinese GM crypto) engines present
  (`libskf_engine.so`, `buildSslCtx` references SKF/PIN). Password is sent in
  cleartext inside the (TLS-protected) XML — no client-side password hashing in this layer.
- `OS` field value observed: `"Linux"`.

---

## 10. Real string literals (citations)

- `<data></data>` (root template) — SslVpnXmlParser.cpp:29 (0x85227)
- tags: `data`, `username`, `password`, `newPassword`, `vldCode`, `language`, `OS`,
  `macAddress`, `private`, `supportChallengePwd`, `type`, `code`
- `SMS-IMC` (0x85393), `CHANGEPWD` (0x8539b) — challenge branch selectors
- response result: `Success` (0x80455), `Challenge` (0x8045f)
- response types: `SMS` (0x80469), `SMS-GW` (0x8046d), `SMS-IMC` (0x80474),
  `PROMPTPWD` (0x8047c), `CHANGEPWD` (0x80486)
- gatewayinfo tags: `gatewayinfo`,`auth`,`supportPassword`,`supportCert`,`supportDKey`,
  `supportvldimg`,`vldimg`,`url`,`login`,`logout`,`challenge`
- domain tags: `domainlist`,`domain`,`name`,`url`
- login-info tags: `result`,`replyMessage`,`EMOServer`,`message`,`smsDynamicPwdd`,
  `waitTime`,`intervaltime`
- `request=` (0x80f00), `POST ` (0x80f0c), ` HTTP/1.1\r\n` (0x7ff84)
- `Cookie: svpnginfo=` (0x80f84), `Content-Length: ` (0x80be2),
  `Content-Type: application/x-www-form-urlencoded\r\n` (0x80bb0)
- `User-Agent: SSLVPN-Client/7.0\r\n\r\n` (0x816c8), `User-Agent: SSLVPN-Client/3.0\r\n` (0x81688)
- `Referer: https://` (0x80b7f) + `/svpn/vpnuser/check.cgi`
- captcha cookie example: `svpnvldid=178; svpnuid=a48eafca8822d45b88f10a2118ec8400`
- `domainId=` + `; authId=-1; showOption=1; saveFlag=0; UserName=`
- legacy form: `txtMacAddr=`,`&txtUsrName=`,`&txtPassword=`,`&selDomain=`,
  `&selIdentity=1`,`&svpnlang=cn`
- `NET_EXTEND / HTTP/1.1\r\nCookie:` (tunnel handoff)
