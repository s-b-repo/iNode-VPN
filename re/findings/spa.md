# H3C iNode SSL VPN — Zero Trust / SPA (Single Packet Authorization) Protocol

Target libs:
- `libs/libZeroTrust.so` (not stripped, DWARF). Sources: `SpaPktMaker.cpp`, `SpaTask.cpp`, `SpaUtils.cpp`, `jsoncpp.cpp`, `ConfigFile.cpp`.
- `libs/libiNodeSslvpnPt.so` — `SslClient.cpp` (`SpaKnocksInfo`, `conn2Remote`, `buildMinusOnePacket`).

This is H3C's "SDP" (Software-Defined Perimeter) / Zero Trust gateway front-end. Before the SSL-VPN TLS port is reachable, the client sends a **UDP Single-Packet-Authorization "knock"** to the gateway/controller. The knock packet carries the client's AID (assigned at device registration), a random per-packet ID that doubles as an HOTP counter, and an HMAC-SHA1 HOTP "password". On a valid knock the firewall opens the TLS/auth port for that source IP, then the normal SSL-VPN handshake proceeds.

---

## 1. Is SPA always present? Trigger

SPA is **conditionally present**: it is the Zero-Trust / SDP deployment mode. When the client is configured to reach an SDP controller / ZT gateway, **every** outbound connection to a controller/gateway endpoint is preceded by a UDP knock. The knock entry point `onKnockUDPMsg(...)` (a.k.a. "KnockSpa") is invoked from essentially every control/data step:

- `CSpaTask::onStartSslvpnHandShake(SpaRegisterParams*)` — knock immediately before the **SSL-VPN TLS handshake** (logs `"succ to knock."` / `"failed to knock."`, `SpaTask.cpp`).
- `CSpaTask::onQuerySpaPwdAuthMsg`, `onQuerySpaSecondAuthMsg`, `onQuerySpaSecondAuthCode`, `onChangeUserPwd`, `onQuerySpaLogoutMsg`, `onQRCodeReqMsg`, `onQRCodeQueryRst` — knock before each HTTPS control call to the controller.
- `CSpaTask::KnockSpa(string ip, int port)` — public helper (calls the 5-arg knock with knock-port default `0x1f40`=8000).

If `strDstIp` is empty or `iDstPort == 0`, the knock is skipped: log `"[onKnockUDPMsg] strDstIp is empty or iDstPort is 0,no need to Knock"`. So in non-SDP/classic SSL-VPN mode there is no knock.

---

## 2. Transport: UDP knock socket

From `onKnockUDPMsg(SpaRegisterParams*, std::string dstIp, int dstPort, int knockPort, bool multi)` @ `0x22630` (and the simpler `onKnockUDPMsg(SpaRegisterParams*, bool)` @ `0x212a0`):

```
socket(AF_INET=2, SOCK_DGRAM=2, IPPROTO_UDP=0x11)   // UDP
sockaddr_in:
    sin_family = AF_INET (2)
    sin_port   = htons(knockPort)      // ror ax,8 == htons
    sin_addr   = inet_addr(dstIp)
sendto(sock, packet, packetLen, 0, &sin, 16)
close(sock)
```

The 5-arg variant additionally does, per port in the knock list: `connect()` + `getsockname()` to learn the local source port (these source ports are appended to the packet — see "portCount"/`spaKnockList`). Errors logged:
`"[onKnockUDPMsg] create socket failed with Err<%s>."`, `"[onKnockUDPMsg] connect Err <%s>."`, `"[onKnockUDPMsg] getsockname Err <%s>."`, `"[onKnockUDPMsg] send Packet Err <%s>."`.

### Knock destination ports (constants, `libiNodeSslvpnPt.so`, rodata @ 0x7f4c4, 16-bit LE)
| symbol | value | meaning |
|---|---|---|
| `Spa_Register_Port` (`_ZL17Spa_Register_Port`) | `0x4a3e` = **19006** | device-register UDP knock port |
| `Spa_Knock_Port`    (`_ZL14Spa_Knock_Port`)    | `0xea61` = **59993** | generic SPA knock port |
| `Spa_Knock_Port_GW` (`_ZL17Spa_Knock_Port_GW`) | `0x1f40` = **8000**  | knock port for the **SSL-VPN gateway** handshake |
| `Spa_Auth_Port`     (`_ZL13Spa_Auth_Port`)     | `0x01bb` = **443**   | controller HTTPS auth/control port |

For the SSL-VPN handshake the call is `onKnockUDPMsg(params, gwIp, vpnPort, 0x1f40 /*8000*/, 0)` (verified at `0x32b2f`: `mov ecx, 0x1f40`). The default knock port in the bool-variant is also constant-folded to 8000 (`and ax,0xcb21; add ax,0x1f40; ror ax,8`).

---

## 3. Knock packet byte layout (the "knock" / SPA packet)

Built in `onKnockUDPMsg` (`SpaPktMaker.cpp`). The send buffer is a stack struct; fields are written by `__memcpy_chk`/`mov`. **Multi-byte numeric fields are stored big-endian** (the code `bswap`s rand and uses `ror ax,8` = htons for ports).

```
struct SpaKnockPacket {            // base offset (decimal)
    uint16_t declaredLen;   // 0x00 (0)   = 0x0110 (272) — fixed buffer/declared length
    char     clientAid[32]; // 0x02 (2)   = clientAid string, up to 32 bytes (copy n=min(len,32), dstlen bound 0x2d)
    uint32_t pktID;         // 0x22 (34)  = bswap(rand())   — random per-packet ID == HOTP counter (big-endian)
    char     password[6];   // 0x26 (38)  = HOTP/OTP code (6 bytes; dword@0x26 + word@0x2a). 9-byte variant if longer.
    uint8_t  portCount;     // 0x2c (44)  = (numKnockPorts/2)+1   (a count byte)
    uint16_t port0;         // 0x2d (45)  = htons(first knock/source port)
    // --- fixed header above = 0x2f (47) bytes ---
    uint16_t portN[...];    // 0x2f (47)+ = htons(additional source ports) appended for multi-port knocks
};
// Actual bytes sent (sendto len) = 0x2f + (#extra ports*2). Field at 0x00 is the *declared* size 0x110.
```

Notes:
- `clientAid` is the AID returned by the SDP controller at device registration (JSON `clientAid`), persisted as `SdpAid-<ip>` in `/etc/spa/spa_cfg.cnf`.
- `pktID` and the HOTP counter are the **same** `rand()` value: `srand(time(0)); r = rand();` then `bswap` → pktID @0x22, and `r` (as `long`) → HOTP counter. So the counter is transmitted in clear (as pktID) and the receiver recomputes the HOTP with the shared key to validate.
- Debug log of the packet: `"[%s] send buffer: %s"`, then a textual dump
  `"pkt length=<len>; pktID=<id>; Conter=<counter>; Password=******; DestIP=<ip>; DstPort=<dport> <srcports...>; portCount=<n>; pkt length=<len>"`
  (`"Password=******"` — the OTP is masked in logs). Hex dump uses `%02X`.

---

## 4. Crypto: HMAC-SHA1 HOTP (RFC 4226) — the "Password"

`generateOTP(std::string key, long counter, int digits, bool addChecksum, int truncationOffset)` @ `0x1bd70` (`SpaUtils.cpp`). Standard RFC-4226 HOTP:

```
msg[8] = counter big-endian          // 8-byte counter (loop: byte[i]=counter&0xff; counter>>=8)
mac    = HMAC(EVP_sha1(), key, keyLen, msg, 8)        // 20-byte HMAC-SHA1
off    = mac[19] & 0x0f               // dynamic truncation (last nibble)
bin    = ((mac[off]&0x7f)<<24)|(mac[off+1]<<16)|(mac[off+2]<<8)|mac[off+3]
otp    = bin % DIGITS_POWER[digits]   // reduce to N digits, then sprintf("%d", otp)
```

Call from `onKnockUDPMsg`: `generateOTP(result, clientKey, rand_counter, /*digits*/5, /*bool*/1, /*hashAlg/off mode*/8)`. The resulting OTP string's bytes are copied into `password` (6 bytes). `DIGITS_POWER` is a static table (symbol `DIGITS_POWER` @ data 0x262060). Hash is **SHA-1** (`EVP_sha1`); 8-byte counter (`mov r8d, 8` before `HMAC`).

- Key = `clientKey` (the per-client SPA key from device registration), persisted as `SdpKey-<ip>`.
- Anti-replay: each knock has a fresh `rand()` counter/pktID; the gateway tracks/validates the HOTP. There is also a challenge-time mechanism (`getChallengeTime`/`saveChallengeTime`, keys `AuthTime`, `CURRENT_CHALLENG_TIME=`, `LAST_CHALLENGE_TIME=` in `spa_cfg.cnf`) used by the HTTPS control flow (`Get_HOTP_Code(string, string&)` @ `0x2a480`, also HMAC-SHA1) — distinct from the per-packet rand counter used in the UDP knock.

No SM2/SM3/SM4 in the knock path; only OpenSSL `HMAC`/`EVP_sha1`. (skf/sm wrappers exist elsewhere in the package but are not used by the knock.)

---

## 5. `SpaKnocksInfo` struct and how it is configured/used

`SpaKnocksInfo` (defined in `SslClient.cpp`, used by both libs). Fields (from symbols `strSpaKnocksIp`, `iSpaKnocksPort`, `vecSpaKnocksInfo`, `SpaKnocksInfoVec`, `initializer_list<SpaKnocksInfo>`):

```
struct SpaKnocksInfo {
    std::string strSpaKnocksIp;   // gateway/controller IP to knock
    int         iSpaKnocksPort;   // UDP knock port (8000/59993/19006 depending on phase)
    void reset();
};
std::vector<SpaKnocksInfo> vecSpaKnocksInfo;   // a.k.a. spaKnockList
```

- The list `spaKnockList` (JSON key `"spaKnockList"`) and per-entry IP/port come from the SDP controller responses (device register / app-list) and/or `/etc/spa/spa_cfg.cnf`. `iSpaKnocksPort` defaults from the `Spa_*_Port` constants above.
- The SSL-VPN connect path: `CSpaTask::sslVpnConnect` → (knock via `onStartSslvpnHandShake`) → `CSslClient::conn2Remote(_SslvpnUser, _SslVpnCfg, ..., SpaRegisterParams*)` (`SslClient.cpp:1761`). `conn2Remote` holds the SPA data in `CSslClient::m_poSpaData` and receives the `SpaRegisterParams*` so the TLS tunnel is built only after the knock.
- `buildMinusOnePacket(SpaRegisterParams*)` (`SslClient.cpp:143`) builds a special "−1" packet: allocates two 0x240-byte buffers, enumerates local interfaces via `getifaddrs`/`freeifaddrs` (collects local MAC/IP), used in the EAD/posture path of the SDP exchange.

---

## 6. SDP control channel (HTTPS / curl JSON) — context around the knock

The controller control plane is HTTPS (libcurl) JSON, port 443 (`Spa_Auth_Port`). Base URL:

```
https://%s/api/terminal/          (default 443)
https://%s:%d/api/terminal/       (explicit port)
Headers:  Content-Type: application/json
          accept: application/json
Method:   POST (curl_easy_setopt + curl_slist_append)
```

Endpoint suffixes (appended after base): `pc/getAppList`, `pc/getSecondAuthCode`, `pc/secondAuth`, `pc/userLogout`, `sdp/checkUserStatus`, plus device-register / pwd-auth / sms endpoints.

### Request JSON bodies (real field names)
- **Device register** (`AssembleDevRegisterReq`, response `ParseDevRegisterResp`):
  ```json
  {"userAccount":"<u>","userPassword":"<p>","clientSn":"<sn>","clientMac":"<mac>","clientOsType":"<os>"}
  ```
  Response `{"code":..,"data":{"clientAid":"<aid>","clientKey":"<key>", ...}}` → AID/Key persisted (`SaveSpaAidWithSdpIP`→`SdpAid-<ip>`, `SaveSpaKeyWithSdpIP`→`SdpKey-<ip>`).
- **Password auth** (`AssemblePwdAuthReq`):
  ```json
  {"userAccount":"<u>","userPassword":"<p>","clientAid":"<aid>","clientMac":"<mac>",
   "clientSn":"<sn>","clientPrivate":"<...>","clientVersion":"<v>","clientSrcIp":"<ip>",
   "clientOSInfo":"<info>","clientOsType":"<os>"}
  ```
- Other JSON tokens seen: `appId`, `agentId`, `dynamicKey`, `userToken`, `firstAuthToken`, `secondAuthToken`, `secondAuthType`, `secondAuthCode`, `spaKnockList`, `code`, `data`.
- WeCom (WeChat Work) QR SSO login URL:
  `https://login.work.weixin.qq.com/wwlogin/sso/login?login_type=CorpApp&appid=%s&agentid=%s&redirect_uri=%s&state=%s`

The SSL-VPN message dispatcher tags (`libiNodeSslvpnPt.so`): `H3C_MSG_QUERY_SPA_REGISTER`, `H3C_MSG_QUERY_SPA_AUTH`, `H3C_MSG_QUERY_SPA_SECONDAUTH`, `H3C_MSG_QUERY_SPA_SECONDAUTHCODE`, `H3C_MSG_QUERY_SPA_SMSAUTH`, `H3C_MSG_QUERY_SPA_SMSREQ`, `H3C_MSG_QUERY_SPA_GETAPPLIST`, `H3C_MSG_QUERY_SPA_LOGOUT`, `H3C_MSG_QUERY_SPA_UPDATEPWD`, `H3C_MSG_SPA_QRCODE_REQURL`, `H3C_MSG_SPA_QRCODE_QUERYRSLT`, `H3C_MSG_SPA_QRCODE_CANCEL`.

---

## 7. Persistent config: `/etc/spa/spa_cfg.cnf` (`ConfigFile.cpp`)

INI-style key/value, per SDP-IP suffixed keys (`ConfigFile::parse`, `clearLine`, `save` with `chmod`):
- `SdpAid-<ip>`   = clientAid for that SDP gateway
- `SdpKey-<ip>`   = clientKey (HOTP key)
- `SMSPassword-<ip>` = cached SMS password
- `AuthTime` / `CURRENT_CHALLENG_TIME=` / `LAST_CHALLENGE_TIME=` = challenge timestamps

Helpers: `GetSpaAidBySdpIP`, `GetSpaKeyBySdpIP`, `SaveSpaAidWithSdpIP`, `SaveSpaKeyWithSdpIP`, `GetSpaKeyBySdpIP`.

---

## 8. State machine (knock-gated SSL-VPN connect)

```
DEVICE_REGISTER  --POST /api/terminal/.../register-->  store clientAid,clientKey  --> REGISTERED
REGISTERED  --UDP knock(port 19006/8000)+POST pwdAuth/secondAuth/...-->  AUTHED (userToken)
AUTHED  --onStartSslvpnHandShake: UDP knock(gwIp, vpnPort, knockPort=8000)-->  PORT_OPEN
PORT_OPEN  --CSslClient::conn2Remote(... SpaRegisterParams*) TLS-->  TUNNEL_UP ("SSLVPN Tunnel Build SUCCESSFULLY")
TUNNEL_UP  --periodic CheckUserStatusTimer / sdp/checkUserStatus-->  (stay) or LOGOUT (SendSpaLogout)
```

Every transition that talks to the gateway/controller is **preceded by a fresh UDP knock** (new rand counter → new HOTP), so the firewall pinhole is re-opened per connection.

---

## 9. Reproduction recipe for an interoperable client

1. Register the device over HTTPS `POST https://<gw>/api/terminal/.../register` to obtain `clientAid` and `clientKey`.
2. Before each connect, build the 47+ byte UDP packet:
   - `[0..1]` = `0x01 0x10` (declaredLen 0x0110, big-endian)
   - `[2..33]` = `clientAid` ASCII (≤32 bytes)
   - `[34..37]` = `pktID` = a random uint32, **big-endian**
   - `[38..43]` = HOTP password: `HOTP_SHA1(key=clientKey, counter=pktID_value, digits=6)` ASCII
   - `[44]` = portCount byte = `(numPorts/2)+1`
   - `[45..46]` = `htons(knockPort)` (and append more `htons(port)` for multi-port)
3. `sendto` it as UDP to `<gw>:8000` (gateway) / `:19006` (register) / `:59993` (generic) / `:443` not used for knock.
4. Immediately open the corresponding TLS (443) or auth connection.

---

## Key string literals / citations
- `"00000000000000000000000000000000"` (HMAC/AID 32-char placeholder) @ 0x51c18
- `"[onKnockUDPMsg] clientAid<%s>,clientKey<%s>"` @ 0x51c40; `"get AID[%s] and Key[%s] succ"` @ 0x521f4
- `"; pktID="` @ 0x5223d, `"; Conter="` @ 0x52246, `"; Password=******; "` @ 0x52269, `"DestIP="` @ 0x5227d, `"; DstPort=<"` @ 0x52285, `"; portCount="` @ 0x52291, `"; pkt length="` @ 0x5229f, `"SpaKnocksPort:"` @ 0x52211, `"%02X"` @ 0x52264
- `"failed to knock."` @ 0x54161, `"succ to knock."` @ 0x54172, `"knock successful!"`
- `"https://%s:%d/api/terminal/"`, `"Content-Type: application/json"`, `"accept: application/json"`, `"pc/getAppList"`, `"pc/secondAuth"`, `"pc/userLogout"`, `"sdp/checkUserStatus"`
- `"/etc/spa/spa_cfg.cnf"` @ 0x51453, `"SdpAid-"` @ 0x520a2, `"SdpKey-"` @ 0x520aa, `"SMSPassword-"`, `"AuthTime"` @ 0x548a0
- JSON: `clientAid`@0x51f2c, `clientKey`@0x520b2, `userAccount`@0x51ef3, `userPassword`@0x51eff, `clientSn`@0x51f0c, `clientMac`@0x51f15, `clientOsType`@0x51f1f, `clientPrivate`@0x51f36, `clientVersion`@0x51f44, `clientSrcIp`@0x51f52, `clientOSInfo`@0x51f5e, `spaKnockList`, `dynamicKey`, `userToken`, `secondAuthToken`, `firstAuthToken`
