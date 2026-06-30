# H3C iNode SSL VPN — Documentation & Deployment Ground Truth (KEY=docs)

This report distills the deployment/usage facts that pin down the real wire protocol for the
H3C iNode Linux SSL VPN client, cross-referencing the vendor PDFs/DOCX **and** the shipped
client config files and binary strings.

## 1. Product identity (what the client talks to)

The SSL VPN **gateway is an H3C SecPath F1000 firewall** (Comware-based) running the H3C SSL VPN
feature. Confirmed from the `SSLVPN User account.docx` admin-console screenshots, which show the
H3C web UI branded **"H3C SecPath F1000"** (top-left logo) with **RBM Primary Device** badge.

The client side is the **H3C iNode Intelligent Client 7.3**. The iNode product as a whole works
with **H3C IMC EIA (Endpoint Intelligent Access) / EAD Security Policy** for 802.1X/Portal, but
**SSL VPN auth terminates directly on the SecPath gateway, not on EIA** (the gateway acts as its
own AAA server doing Local/AD/LDAP/RADIUS auth — see §4).

Build/version provenance from `libiNodeSslvpnPt.so` DWARF paths:
`/root/gl/br_patch_PC_V7R3B05D151/LinuxClient/SRC/code/sslvpn` → client **PC V7 R3 B05 D151**.
Overseas SSL VPN installer: `iNodeSetup7.3_(E0624)_(overseas_sslvpn).exe`; Linux package version
in this tree is **7.3 (E0651)**. The gateway protocol is the H3C "**V7**" SSL VPN dialect
(functions `buildSslAuthPacketV7`, `parseAuthRespMsgV7`, `getSslvpnVersion`, etc.).

## 2. SSL VPN gateway URL format, port and HTTP endpoints

All requests are HTTPS (TLS) to the gateway's SSL VPN virtual host. Base URL:
`https://<gateway-host>:<port>/svpn/...`. Default HTTPS port is **443** (the gateway's "SSL VPN
gateway" listens on a configurable TCP port; the `.vif`/connection supplies host:port — there is
no separate fixed port baked into the client, the gateway address comes from the connection
config / `<remote>` element which is blank in the shipped template).

HTTP endpoints (exact, from `libiNodeSslvpnPt.so` string literals):

| Method | Path | Purpose |
|---|---|---|
| GET  | `/svpn/index.cgi` | initial page / session bootstrap |
| GET  | `/svpn/image.cgi` | fetch CAPTCHA / verify-code image (`buildVldImgReqV7`) |
| POST | `/svpn/vpnuser/login_submit.cgi` | submit primary credentials (username/password/vldCode) |
| POST | `/svpn/vpnuser/check_return.cgi` | submit 2nd-factor / challenge result (SMS / change-pwd) |
| GET  | `/svpn/vpnuser/check.cgi` | poll auth state |
| GET  | `/svpn/olduser_info.cgi?svpnlang=cn` | query whether the same user is already logged in |
| GET  | `/svpn/vpnuser/kickolduser.cgi?OldUserID=<id>&IsKick=1&svpnlang=cn` | kick an existing session |
| GET  | `/svpn/logout.cgi` | logout (`buildLogOutReqV7`) |

Domain-list query (auth-domain enumeration) is keyed by literal `getdomainlist` / `domainlist`
(handled by `CSslVpnMgr::queryVpnAuthParam(_SslvpnDomainListReq&, _SslvpnDomainListResp&)` and
`CSSLVpnXmlParser::GetDomainListInfo`).

Common header: `Content-Type: application/x-www-form-urlencoded`, plus `Host: <gateway>`.
Language query param `svpnlang=cn` (Chinese) or `svpnlang=1`.

## 3. Session / cookie handling

Cookies are the H3C `svpn*` family (from string literals):

- `svpnvldid=<n>` — verify/validation-image session id (set in response to `image.cgi`;
  log string: `svpn.HttpsAuth.getVerify: the response has no svpnvldid.`)
- `svpnuid=<hex>` — per-session user id (32 hex chars, e.g. `a48eafca8822d45b88f10a2118ec8400`)
- `svpnginfo=<...>` — gateway info / session context cookie
- `domainId=<id>` — selected auth domain id

Example request cookie line emitted by the client (literal):
`Cookie: svpnvldid=178; svpnuid=a48eafca8822d45b88f10a2118ec8400`

The client also appends a state string to the Cookie when submitting login:
`; authId=-1; showOption=1; saveFlag=0; UserName=<user>; svpnlang=1; `
(variants `authId=<n>; showOption=0; saveFlag=0; UserName=...`). The query string for domain
selection uses `&selDomain=<domainName>`.

## 4. Auth modes / login fields (the state machine)

From the shipped customization XML `custom/iNodeCustom.xml` `<sslvpn>` block (operator-authored
defaults pushed to the client) — these are the canonical SSL VPN parameters:

```
<sslvpn>
  <remote/>                          <!-- gateway host:port, blank in template -->
  <defaultAddress>0</defaultAddress>
  <retryInterval>5</retryInterval>   <!-- minutes -->
  <retries>3</retries>
  <authMode>7</authMode>             <!-- bitmask of allowed auth modes -->
  <authDefaultMode>0</authDefaultMode>
  <ulAuthType>15</ulAuthType>        <!-- bitmask: Local|AD|LDAP|RADIUS = 1|2|4|8 = 15 -->
  <authType>Local;AD;LDAP;RADIUS</authType>
  <authDefaultType>RADIUS</authDefaultType>
  <gatewayAuth>0</gatewayAuth>       <!-- 0 = no client-cert gateway auth -->
  <getSmsVryCountdownValue>60</getSmsVryCountdownValue>  <!-- SMS resend countdown (s) -->
  <TLSVersion>0</TLSVersion>         <!-- 0 = auto -->
  <certType>0</certType>             <!-- 0 = none/file, see INODE_CERT_* enum -->
  <edcode>0</edcode>
</sslvpn>
```

And the per-connection template `custom/clientfiles/7000/7001.icnf` (service id 7000 = SSL VPN):

```
CONNECT_NAME=SSL VPN连接   ("SSL VPN connection")
COIDENT=7001
USER_NAME=
PASSWORD=
SAVE_PASSWORD=1
MSGAUTH=0          <!-- message/SMS auth toggle -->
RSA=0              <!-- RSA SecurID toggle -->
AUTO_AUTHEN=0
REAUTHTIMES=3
REAUTHINTERVAL=5
AUTHTYPE=15        <!-- Local;AD;LDAP;RADIUS bitmask -->
AUTHNAME=RADIUS    <!-- default auth domain/type name -->
TLS_VERSION=0
CERT_TYPE=0
AUTHMODE=0
ROOTFILE=          <!-- CA cert path -->
CLIENTFILE=        <!-- client cert path -->
CLIENTCERTPWD=     <!-- client cert password -->
```

Auth flow / state machine (from binary symbols & log strings):
1. **Connect** — TLS handshake to `https://<gw>:<port>` (`conn2VpnGateway`, `buildSslCtx`).
2. **Query auth params / domain list** — `getdomainlist`; client may show a domain dropdown.
   State `AUTHSTAT_WAIT_DOMAINLIST_RESP`. Selected domain → cookie `domainId` / `&selDomain=`.
3. **(optional) Verify-code image** — `GET /svpn/image.cgi` → `svpnvldid` cookie; user types
   `vldCode` (CAPTCHA). Field `iNeedVerifyCode` / `iVerifyCodeState` gate this.
4. **Primary login** — `POST /svpn/vpnuser/login_submit.cgi` with the login XML (see §5).
   `buildSslAuthPacketV7` / `FormatLoginXML`.
5. **Old-user check / kick** — `GET /svpn/olduser_info.cgi`; if already online,
   `GET /svpn/vpnuser/kickolduser.cgi?OldUserID=<id>&IsKick=1`.
6. **Challenge / 2nd factor** — if gateway responds with a challenge
   (`H3C_MSG_CHALLENGE_AUTH_INFO`): types are **SMS_IMC** (SMS code) and **CHANGEPWD**
   (forced password change). Client sends `POST /svpn/vpnuser/check_return.cgi` with the
   2nd-login / challenge XML (`Format2ndLoginXML`, `FormatChallengeAuthXML`,
   `buildSsl2ndAuthPacketV7`, `buildSslChallengeAuthPacketV7`).
   Log: `SendChallengeAuthInfo: connid=%u, challengeType=%d, smsType=%d, waittime=%d,
   intervaltime=%d, challengeMsg=%s.`
7. **Auth result** — parsed via `H3C_AUTH_RESULT` / `parseAuthRespMsgV7`; on success the gateway
   returns VPN params (`getAlocParam`) and the client brings up the virtual NIC and starts the
   DTLS/TLS data tunnel (`chgVirtNet`, `hdlInput`/`hdlOutput`).
8. **Logout** — `GET /svpn/logout.cgi` (`buildLogOutReqV7`).

`authMode` enum (`ESslVpnAuthMode` / `dwAuthMode`): password, cert, password+cert, SMS, etc.;
shipped default `authMode=7`. `ulAuthType=15` = all four AAA backends enabled.

## 5. Login message formats (exact XML field names & ordering)

The client serializes credentials as a TidyXml `<data>` document. Field order is from
`SslVpnXmlParser.cpp` (cited lines):

**Primary login** (`CSSLVpnXmlParser::FormatLoginXML`, `SslVpnXmlParser.cpp:27-45`),
root `<data>` parsed from literal `"<data></data>"` (`SslVpnXmlParser.cpp:29`):

```xml
<data>
  <username>USER</username>                  <!-- :38 -->
  <password>ENC_PW</password>                <!-- :39  RSA/AES enc + base64 -->
  <vldCode>CAPTCHA</vldCode>                 <!-- :40 -->
  <language>cn|1</language>                  <!-- :41 -->
  <macAddress>AA:BB:CC:DD:EE:FF</macAddress> <!-- :43 -->
  <supportChallengePwd>1</supportChallengePwd> <!-- :44 -->
  <private>...</private>                      <!-- :45  client/version blob -->
</data>
```

**2nd login / challenge response** (`Format2ndLoginXML`, `SslVpnXmlParser.cpp:61-89`):

```xml
<data>
  <username>USER</username>     <!-- :72 -->
  <type>SMS_IMC|CHANGEPWD</type><!-- :73 -->
  <code>SMSCODE</code>          <!-- :74 -->
  <language>cn</language>       <!-- :75 -->
  <password>ENC_PW</password>   <!-- :78 (e.g. new password for CHANGEPWD) -->
  <vldCode>CAPTCHA</vldCode>    <!-- :79 -->
  <macAddress>...</macAddress>  <!-- :81 -->
  <private>...</private>        <!-- :82 -->
</data>
```

**Challenge auth** (`FormatChallengeAuthXML`, `SslVpnXmlParser.cpp:216-251`): same shape;
explicit `type` values `SMS_IMC` (`:231`) and `CHANGEPWD` (`:235`).

These XML bodies are POSTed url-form-encoded to `login_submit.cgi` / `check_return.cgi`.

## 6. Credential / challenge crypto & encoding

From `libiNodeSslvpnPt.so` symbols/strings:
- **Password is RSA-encrypted then base64-encoded** before being put in `<password>`.
  Symbols: `H3C_USER_RSAKEY` (server-supplied RSA public key, `szUserRsaKey`), `H3C_RSA`,
  `ER_RSA_ENCRYPT`, `pszEncryptContent`/`EncryptContentLenth`, `szPasswordBase64`,
  `szNewPasswordBase64`, `utl_base64_encode`/`utl_base64_decode`. (`max_exponent`/`min_exponent`
  are bignum RSA artifacts.)
- An **AES-256-CBC** path also exists: `utl_AES256CBC_encrypt`, `szEncryptedData` — used for the
  "minus-one packet" / tunnel param protection (`[buildMinusOnePacket] contentLen<..> key<..>
  encryptContent<..> strSrcIP<..> strAID<..>`).
- Verify code (CAPTCHA) image fetched as binary from `image.cgi`; mapping kept in
  `m_certVerifyCode2Reskey` / `OpenSSL_CertVerifyCode2ResKeyTab`.
- Client certificate auth supported (`H3C_CERT_FILE`, `H3C_CERT_PWD`, `H3C_CERTHASH`,
  `H3C_CERTISSUER`, `H3C_CERT_TYPE`, `H3C_CERT_VERIFYSVR`; cert types
  `INODE_CERT_FILE`, `INODE_CERT_PKCS11_UKEY`, `INODE_CERT_SKF_UKEY`).
- TLS version negotiable: `INODE_TLS_1_0`, `INODE_TLS_1_2`, `INODE_TLS_AUTO`, plus Chinese
  national crypto `INODE_GMTLS_1_1` (GM/T TLS). `TLS_VERSION=0` = auto.

## 7. Service-ID → connection-type map (clientfiles / `.icnf` / locations.xml)

`custom/clientfiles/locations.xml` ("我的场景" = "My Scenario") binds protocol id → coident, and
each `clientfiles/<proto>/<coident>.icnf` is the connection template. Authoritative mapping:

| proto (service id) | coident | Connection (CONNECT_NAME) | Meaning |
|---|---|---|---|
| **1100** | 1101 | `<none>` (SSID) | **Wireless / WLAN** connection |
| **2401** | 2402 | `L2TP IPsec VPN连接` | **L2TP/IPsec VPN** |
| **5020** | 5021 | `Portal连接` | **Portal** authentication |
| **7000** | 7001 | `SSL VPN连接` | **SSL VPN** (this assignment) |
| **8021** | 8022 | `802.1X连接` | **802.1X** authentication |
| **9019** | 9020 | `EAD直连` | **EAD direct-connect** (EADPORT=9019) |
| **19006** | 19007 | `零信任连接` | **Zero Trust / SPA** (controllerAuthPort=4433) |

Note: `EADPORT=9019` in `conf/iNode.conf` and `iNodeCustom.xml`; the EAD service id *is* 9019.
The Zero-Trust/SPA controller default auth port is **4433** (`CONTROLLERAUTHPORT=4433`).

## 8. How the operator config (.vif / customization) is generated

The official Windows/Linux install guides state the connections (Portal / 802.1X / **SSL VPN** /
L2TP/IPsec / Wireless) are "**customized by the iNode management center**" and pushed to the
client. In this tree that customization is the pair:
- `custom/iNodeCustom.xml`  — the master customization (functions, sslvpn/portal/x1/vpn/spa
  defaults, GUI options, locations). `<cusTimeString>2025-02-12 15:22:32</cusTimeString>`,
  `LangCode=2052` (zh-CN).
- `custom/iNodeCustomXml.vrf` — signature/verification file for the above.
- `custom/clientfiles/<svc>/<coident>.icnf` + `locations.xml` — the per-connection templates.

The runtime per-connection store mirrors these under `clientfiles/<svc>/` (empty in a fresh
install). Secrets in the customization are stored encrypted+base64 (e.g.
`uninstallPassword=c+PckpVimj0=`, L2TP `PRESHAREDKEY`/`L2TPTunnelPwd`, GUI `closeInodePwd`).

`conf/TRMClient.ini` carries a *terminal-management* proxy (`CustomizeProxyIP=10.10.10.10`,
`CustomizeProxyPort=9039`) — unrelated to SSL VPN data path.

## 9. Server-side user provisioning (from SSLVPN User account.docx)

To create an SSL VPN user on the SecPath F1000:
`Objects > User > User Management > Local Users > Create` → **Create User** form:
- **Username** (1-55 chars), **Password** (1-63 chars) / Confirm, optional *Set random password*.
- **Validity period** (start–end), **Authorization user group** (`system`), **Identity groups**.
- **Available services** checkboxes: ADVPN, IKE, IPoE, LAN access, Portal, PPP, **SSL VPN**
  (the SSL VPN box must be ticked for the user to use the iNode SSL VPN connection).
- **Max number of concurrent logins** (1-1024), **Phone number** (1-32, used for SMS 2FA),
  **Description**.
- **Authorization attributes**: ACL type IPv4/Layer-2, **Authorization ACL** (e.g. 2000/3000),
  Idle timeout, Authorization VLAN.
- **SSL VPN Authorization attributes**: **SSL VPN resource group** (e.g. `rg`) — controls which
  internal resources the user can reach.
- **Binding attributes**: Access interface, IPv4 address/mask, MAC address, VLAN (1-4094).
- **Password settings**: min length 4-32, min char types 1-4, expiration, max login attempts
  2-10, account idle time 0-365 days.

The existing example users show `Available service = SSL VPN` for `sslvpn`, `test`, `vpn` and
`PPP` for `vpnuser`, all in `Authorization user group = system`.

## 10. Operator-facing connection procedure (summary)

1. **Gateway side (SecPath F1000):** enable the SSL VPN gateway, create an SSL VPN resource
   group, create local AAA users with the **SSL VPN** service enabled and an SSL VPN resource
   group bound (above). Note the gateway's public **host + HTTPS port**.
2. **Client side (Linux iNode):** install via `tar -zxvf iNodeClient_Linux.tar.gz` then
   `./install.sh` (Ubuntu: `sudo ./install.sh`); verify with `ps -e | grep A` for
   **AuthenMngService**. Run `sh ./iNodeClient.sh`.
3. In the iNode GUI, the **SSL VPN connection** (pushed by the management center, or created via
   *Management Plat > add scenario*) is configured with the gateway address; the user clicks the
   connection > **Connect**, enters **Username/Password**, optional **CAPTCHA (vldCode)**, picks
   an **auth domain** (Local/AD/LDAP/RADIUS), and completes any **SMS code** or **forced password
   change** challenge. On success an internal route/virtual NIC is set up and intranet resources
   become reachable.

## 11. Source citations

- `custom/iNodeCustom.xml` `<sslvpn>` / `<locations>` / `<EAD>` / `<spa>` blocks.
- `custom/clientfiles/7000/7001.icnf` (SSL VPN), `.../5020/5021.icnf` (Portal),
  `.../8021/8022.icnf` (802.1X), `.../2401/2402.icnf` (L2TP), `.../9019/9020.icnf` (EAD),
  `.../19006/19007.icnf` (Zero Trust), `.../1100/1101.icnf` (Wireless), `locations.xml`.
- `libs/libiNodeSslvpnPt.so` strings & symbols; `SslVpnXmlParser.cpp:27-45,61-89,216-251`.
- `OneDrive_2_12-19-2025/SSLVPN User account.docx` screenshots (SecPath F1000 admin UI).
- `H3C_iNode_PC_7.3_E0651/manual/iNode Installation Guide_{Linux,Windows}.pdf` (install/usage).
- `H3C_iNode_PC_7.3_E0651/manual/...` Overview: iNode works with IMC EIA / EAD; supports
  802.1X, Portal, **SSL VPN**, L2TP/IPsec.
