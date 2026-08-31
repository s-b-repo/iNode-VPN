# H3C iNode — Service Orchestration & IPC (KEY=service)

Component: **AuthenMngService** daemon + **libpipc.so** (named-pipe IPC) — the connection-lifecycle backbone that the GUI (`iNodeClient`) drives to bring up an SSL VPN connection.

Binaries analyzed (all carry C++ symbols + DWARF):
- `iNodeClient/AuthenMngService` — ELF x86-64, `with debug_info, not stripped`. Source files compiled in: `linux1xCenter.cpp`, `ReadInstruction.cpp`, `crack.cpp`, `iNodeDetectorMessage.cpp`.
- `iNodeClient/libs/libpipc.so` — named-pipe (FIFO) message bus (`npipe.cpp`, `msg_npipe.cpp`).
- `iNodeClient/libs/libutility.so` (and `libInodeUtility.so`) — `packet.cpp` provides the on-wire `CPacketItem` TLV packet (`createPacket`/`parsePackage`), `createSocket`, `CMsgCmd`.
- `iNodeClient/libs/libiNodeSslvpnPt.so` — `CSslVpnMgr` SSL VPN protocol engine (the actual TLS/HTTP wire protocol; out of scope here, but it is the callee).

Version string (`linux1xCenter.cpp:5849`): `AuthMngSvc 1.8.2 MT-D124 E0624[2023.9.28.15.40]`.

---

## 1. Process model & startup (`main`, linux1xCenter.cpp:5806+)

`main()` sequence:
1. `daemonInit()` — fork to background daemon.
2. `utl_InitVerifyAndLoad()` (license/integrity); on fail prints `"Failed to call utl_InitVerifyAndLoad!"` and exits.
3. Single-instance lock; if already running: `"The Process is running now, can not exist two instances!"`.
4. `InitInstance()` (linux1xCenter.cpp:5411) → `LoadSystemConfInfo()` then loads language resource `<installdir>/resource/inode_zh.txt`.
5. `write_pid_to_file()`, `setCoreLimit()`, set core pattern via `echo "core-%e-%p-%t.core" | tee /proc/sys/kernel/core_pattern`.
6. `LibOpswatManager::loadLibrary()` of `libwaapi.so`.
7. **`createThread()`** — spawns all worker threads.
8. Blocks until `utl_IsExit()`, then `clear_pid_from_file()`, `LibOpswatManager::cleanup()`, `ExitInstance()`, logs `"[main] quit!"`.

### Worker threads (`createThread`, linux1xCenter.cpp:5090+)
Created with `pthread_create`:
| Thread fn | Role |
|---|---|
| `processMain(void*)` | **Primary IPC dispatcher** — runs both the named-pipe receiver and a UDP command socket. |
| `jobMain(void*)` | Background job queue. |
| `processDetector(void*)` | Server-discovery / detector UDP listener (port 20102). |
| `ProcessAclMonitor(void*)` | ACL monitor (only when `utl_IsAclCustom()`). |
| `processSig(void*)` | DBus signal handler (`LibDBus::LoadLibrary()`); handles e.g. `procSysWakeUp`. |
| (also) `NetMonitor::startNetMonThread()`, `StartVncRAThread()` | network change + VNC remote-assist. |

---

## 2. Two IPC channels

The daemon exposes **two** transports, both initialized inside `processMain` (linux1xCenter.cpp:3376+):

### (A) Named-pipe (FIFO) bus — `libpipc.so` — control/notify channel to the GUI
Created via `mkdir -p -m a+rwx /tmp/iNode/` (`npipe_init`, npipe.cpp:11-13, runs `system()`), then `mkfifo` per endpoint under `/tmp/iNode/`.

- `npipe_init(name)` sets a global `listenPath` and ensures `/tmp/iNode/` exists (`npipe.cpp`).
- `npipe_build(name)` (npipe.cpp:18+) builds the FIFO path `"/tmp/iNode/" + name` and `mkfifo()`s it; it creates a pair (loops twice, var `2 → 1`), i.e. a read FIFO and a write FIFO, retrying with a `try ppath:` log line on collision.
- Receiver side: `msgReceiver<msgRecver, msgProcessor<msgSender,msgSendRecver>>`.
  - `msgRecverInit(name)`, `getMainRecver()`, `recvMsg(int&,void*,len,flags)`.
- Sender side: `msgSender::sendMsg(int seq, void* buf, unsigned long len, int flags)`, `sendRecvMsg(...)` for synchronous request/reply.
- A pipe message type enum exists: **`ASYNC_PIPE_MSG`** and **`ASYNC_PIPE_MSG_RESP`** (the `type` field).

#### IPC message header `npmsghdr` (libpipc, `msg_npipe.h:24`, total **48 bytes**)
From DWARF (`npmsghdr`, byte_size 48):
```c
struct npmsghdr {            // big-endian on wire not required; same-host
    uint8_t  type;           // off 0   ASYNC_PIPE_MSG / ASYNC_PIPE_MSG_RESP
    uint32_t seq;            // off 4   request sequence id (padding at 1..3)
    uint8_t  path[32];       // off 8   destination FIFO basename (e.g. "iNodeCmn")
    uint32_t subMod;         // off 40  sub-module selector -> handler (see table)
    uint32_t datalen;        // off 44  payload length following the header
};
```
`dumpMsghdr()` prints: `ppath:` + `msghdr:[type=… ;seq=… ;path=… ]` (msg_npipe.cpp:285-288).

The daemon's main receiver listens on path **`iNodeCmn`** and registers per-`subMod` handlers via `msgProcessor::addMsgHandler(subMod, fn)`:

| subMod | handler (linux1xCenter.cpp) | purpose |
|---|---|---|
| 0 | `iNodeProcMsg`   | common / iNode core |
| 2 | `eadProcMsg`     | EAD security check |
| 3 | `dot1xProcMsg`   | 802.1X |
| 4 | `portalProcMsg`  | Portal |
| **5** | **`SslvpnMsgProc`** | **SSL VPN** |
| 6 | `IPSecvpnMsgProc`| IPSec/L2TP VPN |
| 7 | `loadMsgProc`    | connection loader (auto-run / load .icnf) |
| 8 | `spaVpnMsgProc`  | SPA / zero-trust |

The GUI publishes to FIFO basename **`iNodeClient`** to receive async notifications/responses (a second `msgProcessor` is constructed for `iNodeClient`).

### (B) Local UDP command socket — `CPacketItem` TLV protocol (primary request channel)
Inside `processMain`, `createSocket(fd, port=0xC351, ip)` opens a `socket(AF_INET, SOCK_DGRAM, 0)` (`packet.cpp:490`) bound to **127.0.0.1:50001** (`0xC351`). The loop does `select()` → `recvfrom()` → `parsePackage(buf, len, oItem)` → big `switch (oItem.m_ucMsgType)` dispatch. Replies are sent with `CMsgCmd` / `sendto`. Log lines: `"procMain: Receive Package:"`, `"procMain: The MsgType is %d."`.

---

## 3. `CPacketItem` wire packet (packet.cpp, libutility.so)

The on-wire frame for the UDP channel (also used inside some pipe payloads). Header is **12 bytes**, then a list of TLV attributes.

### `createPacket(CPacketItem&, uint8_t* buf, int& len)` (packet.cpp:444)
Header layout (big-endian via `htons`):
```
offset 0  uint16  ProtocolType   (htons)   <- m_nProtocolType
offset 2  uint16  ConnectId      (htons)   <- m_nConnectId
offset 4  uint8   MsgType                  <- m_ucMsgType   (H3C_* code)
offset 5  uint8   MsgValue                 <- m_ucMsgValue
offset 6..7       (reserved)
offset 8  uint16  TotalAttrLen   (htons, written last)
offset 10..11     (reserved / attr count area)
offset 12         attributes start  (writer initializes write-cursor = 0x0C)
```
Each attribute (loop over `m_unAttrNum`):
```
uint8   AttrType      (= CAttrItem.m_ucAttrType)
uint8   ValueType     (6 = integer; string otherwise)
  if integer:  uint32  IntegerValue        (network order)
  if string :  uint8   StringLen ; bytes[StringLen]   (memcpy of m_pucStringValue)
```
`parsePackage` (packet.cpp:383) reverses this: `ntohs` the three header words, validates `Attr Total Len` vs received len (`"parsePkg: Invalid Length(Attr Total Len=%d, Received Len=%d)."`), then walks attributes from offset 12.

### `CPacketItem` struct (DWARF, byte_size 2056)
```c
class CPacketItem {
    uint16_t   m_nProtocolType;   // off 0
    uint16_t   m_nConnectId;      // off 2
    uint8_t    m_ucMsgType;       // off 4  (H3C_* message code)
    uint8_t    m_ucMsgValue;      // off 5
    uint32_t   m_unAttrNum;       // off 8
    uint32_t   m_unMaxAttrNum;    // off 12
    CAttrItem* m_pAttrItem;       // off 16
};
class CAttrItem {                 // byte_size 24
    uint8_t  m_ucAttrType;        // off 0
    uint8_t  m_ucValueType;       // off 1   (6 = integer)
    uint32_t m_unIntegerValue;    // off 4
    uint8_t* m_pucStringValue;    // off 8
    uint8_t  m_ucStringLen;       // off 16
};
```
Accessors: `CPacketItem::setAttrValue(type, uint)`, `setAttrValue(type, char const*)`, `setAttrValue(type, uchar const*, uchar len)`, `getAttrValue(type, void*, int*, int*)`, `getAttrValue(type, std::string&)`.
`CMsgCmd` wraps send/recv: `CMsgCmd(CPacketItem&)`, `send(int)`, `send(CPacketItem&,int)`, `recv(char*,int,int)`, `echo(int)`, `kill(int)`, `sendNotifyInfo(...)`. There is a per-attribute dictionary symbol `PACKET_ATTR_DICTION`.

---

## 4. H3C message-type codes (`m_ucMsgType`) — full enum (DWARF const_value)

These are the verbs the GUI sends to the daemon and notifications the daemon sends back. Selected/relevant values:

| Code | Name |
|---|---|
| 1 / 2 | H3C_AUTH_REQUEST / H3C_AUTH_RESPONSE |
| 3 / 4 | H3C_LOGOFF_REQ / H3C_LOGOFF_RESPONSE |
| 5 / 6 | H3C_CONFIG_REQUEST / H3C_CONFIG_RESPONSE |
| 7 / 8 | H3C_QUERY_STATE_REQUEST / RESPONSE |
| 9 / 10 | H3C_DEV_INFO_REQUEST / RESPONSE |
| 11..13 | H3C_MSG_NOTIFY / _NOTIFY_INFO / _NOTIFY_LOGOFF |
| 14 / 15 | H3C_SET_AUTO_AUTH / H3C_UNSET_AUTO_AUTH |
| 16 / 17 | H3C_AUTH_NOTIFY / H3C_LOGOFF_NOTIFY |
| 21 | H3C_EAD_AUTH_REQUEST |
| 22..30 | H3C_EAD_AUTHEN_INFO, _RESULT_NOTIFY, _REAUTH, _PMCHECK(+RETURN), _WEAKPWCHECK_CURUSERNAME(+RETURN), _SCREENSAVERCHECK(+RETURN) |
| 31 / 32 | H3C_PORTAL_REQUEST_SMS / RESPONSE_SMS |
| 49 / 50 | H3C_EAD_CHANGE_PASSWORD_REQ / H3C_EAD_CHGPASSWD_RESULT |
| 61 | H3C_DIF_AUTH_REQUEST |
| 100 | H3C_KILL_PROCESS |
| 101 / 102 / 103 | H3C_ECHO_REQUEST / RESPONSE / H3C_ECHO_LOGOFF |
| 104 / 105 | H3C_MSG_UPDATEINFO / _NOTIFY_UPDATEINFO |
| 109 | H3C_MSG_SYS_WAKE_UP |
| 110 | H3C_MSG_SYS_USER_LOG_OUT |
| 111 / 112 | H3C_MSG_SYS_QUERY_ONLINE_CONN / _RES |
| 113 | H3C_MSG_FRONT_START  (GUI front-end started handshake) |
| **200** | **H3C_SSLVPN_QUERY_AUTH_PARAM** |
| **201** | **H3C_SSLVPN_QUERY_DOMAIN_PARAM** |
| **202** | **H3C_SSLVPN_QUERY_VERTIFY_PIC** (captcha image) |
| **203** | **H3C_SSLVPN_SHUTDOWN** (offline) |
| **204** | **H3C_MSG_GET_AUTH_INFO** |
| 300..307 | H3C_MSG_STACHG, _CONN_INFO, _CHALLENGE_AUTH_INFO, _SSLVPN_INFO, _DEPLOY_CERT, _NOTIFY_USERTOKEN, _NOTIFY_VDIGATEWAY, _CHALLENGE_AUTH_RESULT |
| 400..411 | H3C_MSG_QUERY_SPA_* (SPA/zero-trust register/auth/sms/secondauth/applist/logout, QR-code) |

(Note: codes 113 collide between `H3C_EAD_SETIPADDRINFO_RESULT` and `H3C_MSG_FRONT_START` in the enum dump — they are in different enum scopes.)

---

## 5. SSL VPN connect lifecycle (the orchestration path)

There are two entry styles: GUI-driven (pipe subMod 5, `SslvpnMsgProc`) for the interactive query/auth steps, and the file-driven loader (`procSslVpnAuthReq` / `LoadSslVpnRun` / `CreateSslConn`) that consumes a `.icnf` profile.

### 5a. Interactive query/auth over the pipe — `SslvpnMsgProc` (linux1xCenter.cpp:3095)
Dispatches by the inner message type and forwards to the SSL VPN engine `CSslVpnMgr` (singleton `CSslVpnMgr::instance()`), then `msgSender::sendMsg(...)` the reply back to the GUI (path `iNodeClient`). Mapping observed:
- `H3C_SSLVPN_QUERY_AUTH_PARAM (200)` → `CSslVpnMgr::queryVpnAuthParam(_SslvpnDomainListReq&, _SslvpnDomainListResp&)` — get login domains / auth methods from gateway.
- `H3C_SSLVPN_QUERY_DOMAIN_PARAM (201)` → `CSslVpnMgr::queryDomainParam(_SslvpnConnInfoReq&, _SslvpnConnInfoResp&)` — per-domain parameters.
- `H3C_SSLVPN_QUERY_VERTIFY_PIC (202)` → `CSslVpnMgr::queryVertifyPic(_SslvpnQueryPicReq&, _SslvpnQueryPicResp&)` — captcha image.
- `H3C_SSLVPN_SHUTDOWN (203)` → `CSslVpnMgr::onSslVpnConnOfflineMsg()` — tear down.
Other `CSslVpnMgr` entry points: `init()`, `startConn(bool)`, `stopConn(int)`, `stopCurConn()`, `setSslvpnUser(_SslvpnUser)`, `getSslvpnUser()`, `getConnStatus()`, `getNetWorkStatus()`, `syncModifyPwd(char*)`, `setAutoReconTunnel(uint)`. `CSslVpnMgr::init()` is called once early in `processMain` (linux1xCenter.cpp:3387).

### 5b. Auth request that loads a `.icnf` profile — `procSslVpnAuthReq(CPacketItem&)` (linux1xCenter.cpp:1277)
1. Logs `"svpn.procAuthReq: Begin."` (logger tag `iNodeSslvpn`).
2. `CPacketItem::getAttrValue(...)` pulls the **ConnName** attribute → `"svpn.procAuthReq: ConnName is %s."`.
3. `FindSslVpnConnectLink(connName)` checks for an existing live link.
4. `utl_GetSslvpnConfPath()` → `opendir()` and iterate the SSL VPN conf dir, matching files ending in **`.icnf`** (skip `.`/`..`, `stat`, `strstr(name,".icnf")`).
5. Match the profile whose `CONNECT_NAME` == ConnName, then `CreateSslConn(profilePath)`.

### 5c. `CreateSslConn(const char* cfgPath)` (linux1xCenter.cpp:9716)
1. Validate path (else `"creatSslConn: err config file path,return value = 1"`).
2. `CCfgFileMgr::loadFromFile(path, ...)` — load the `.icnf` (INI/key=value).
3. Read `CONNECT_NAME`, resolve link via `FindSslVpnConnectLink`.
4. Build path `"%s%s%s"` = `<sslvpnConfPath><connect><.icnf>`.
5. `utl_InitVerifyAndLoad()` then `utl_LoadSSLVPNCusInfo()` (customization).
6. Re-emit config lines into a buffer: `"CONNECT_NAME="`, `"USER_NAME="`, … then `utl_encrpt()` to encrypt the password fields before handing to the engine.
7. Drive `CSslVpnMgr` (`setSslvpnUser` / `startConn`) to actually establish the TLS tunnel.

### 5d. Auto-connect on startup — `LoadSslvpnAutoRun()` (linux1xCenter.cpp:6593)
Called from `startAutoLogin()`. Scans `utl_GetSslvpnConfPath()` for `*.icnf`, and for each profile with auto-auth set, calls `LoadSslVpnRun(connName, action, bExtra)` (linux1xCenter.cpp:9052) which:
- `opendir` conf path, iterate `.icnf`, `CCfgFileMgr::loadFromFile`, `strcasecmp` against key `CONNECT_NAME`.
- Builds a `CMsgCmd(CPacketItem&)` and `CMsgCmd::send(int)` to push the auth, then `CMsgCmd::recv(...)` + `parsePackage(...)` to read the result. (i.e. it loops back through the same UDP packet protocol.)
- `ENUM_LOAD_LINK_ACTION` enumerates the load action (start / stop / query).

### `.icnf` SSL VPN profile keys (parsed by `CCfgFileMgr::loadFromFile`)
Observed string keys in `CreateSslConn`/`LoadSslVpnRun`:
```
CONNECT_NAME      connection display name (matched to GUI ConnName)
USER_NAME         login username
PASSWORD          (stored encrypted; utl_encrpt)
SAVE_PASSWORD     0/1
AUTO_AUTHEN       0/1  auto-connect at startup
REMOTEIP / STRREMOTEIP   gateway IP(s)
DOMAINID / DOMAINNAME    login domain
AUTHMODE / AUTHTYPE / AUTHNAME   auth method selectors
CHOOSECERT / CLIENTCERTPWD       client cert selection + cert password
MSGAUTH           message/secondary auth flag
REAUTHTIMES / REAUTHINTERVAL     re-auth policy
```
Profiles live under the directory returned by `utl_GetSslvpnConfPath()` (per-connection `*.icnf`).

---

## 6. Server detection / heartbeat — `iNodeDtctrMessage` (iNodeDetectorMessage.cpp)

`processDetector(void*)` (linux1xCenter.cpp:3007) opens a UDP socket via `createSocket(&g_iDtctrSocketFD, 0x4E86, ...)` = bound on **port 20102** (`0x4E86`), and answers EAD/detector probes using `iNodeDtctrMessage` and `DtctrReportInfo(sockaddr_in&, uint, uchar*)`.

### `iNodeDtctrMessage` struct (DWARF, byte_size 640) — a RADIUS-style detector frame
```c
class iNodeDtctrMessage {
    char     m_szShareKey[64];          // off 0    shared secret (SetShareKey/GetShareKey)
    uint32_t m_ulPacketCode;            // off 64   packet code (SetPacketCode/GetPacketCode)
    uint32_t m_ulPackeIdentifier;       // off 68   identifier (SetIdentifier/GetIdentifier)
    uint16_t m_usPacketLength;          // off 72   total length (SetPacketLength/GetPacketLength)
    uint8_t  m_arraybyteAuthenticator[16]; // off 74  16-byte authenticator (MD5-style)
    char     m_szNodeVersion[...];      // off 90   iNode client version (SetiNodeVersion)
    string   m_strComputerName;         // off 352  local machine name
    char     m_szOSVersion[...];        // off 384  OS version
};
```
Serialize: `MakeUpMessageIntoBuffer(uint8_t*, int&)`; parse: `ParseBufferIntoMessage(uint8_t const*, int)` (validates against `arrayValidate` / `arrayAuthenticator`). The authenticator is an MD5/HMAC over the message keyed by `m_szShareKey` (classic H3C EAD detector pattern).

---

## 7. Config files & EAD constants

### `<installdir>/conf/iNode.conf` (read by `LoadSystemConfInfo`, linux1xCenter.cpp:5181)
Path built as `"%s/conf/iNode.conf"`. Sample shipped:
```
LOG_LEVEL=5      ; verbosity; if missing -> "loadSysConfInfo: failed to load LOG_LEVEL."
FORBID_PAP=0     ; -> X1_SetForbidPap(dwForbidPap); logs "LoadSystemConfInfo: dwForbidPap %d."
EADIP=           ; EAD security server IPv4 (primary); fallback source for 802.1X EAD
EADPORT=9019     ; EAD server UDP port; default constant 0x233B = 9019
```
- **FORBID_PAP**: when non-zero, PAP is disabled and the 802.1X/EAD client must use CHAP/EAP (not plaintext PAP). Pushed into the dot1x engine via `X1_SetForbidPap(int)`; also seen as `dwDisablePapOpt` / `PAP_TYPE` in the SPA path. Use this to decide credential encoding for the 802.1X leg.
- **EADIP / EADPORT (default 9019)**: address of the EAD (Endpoint Admission Defense) security-policy server. `LoadEadAutoRun()` (linux1xCenter.cpp:10389+) prefers the `.icnf` keys `EADSERVER`/`EADSTANDBYSERVER`/`EADIPV6SERVER`; if absent it logs `"LoadEadAutoRun: no item EADSERVER, so read conf/iNode.conf"` and falls back to `conf/iNode.conf` `EADIP`/`EADIPBAK`/`EADPORT`. Internal fields: `strEadIPV4/strEadIPV6/szEadIP/szEadPort/strStandbyEADIP/strStandbyEADPort/m_usEADIpv6`.

### `<installdir>/conf/TRMClient.ini` (read by TrmClient/iNodeTRM, not the daemon)
```
[ServerInfo] / [MainInfo]
CustomizeProxyIP=10.10.10.10  CustomizeProxyPort=9039   (+ Bak)
MakeSetup / MakeUpdate / InstallUsbDrv / LogLevel
```
Used by the management/update agent (TRM), not by AuthenMngService directly.

### `*.icnf`
Per-connection SSL VPN / VPN profiles (keys in §5). Plus `iNode.vif` is a binary/encrypted version-info blob (not plaintext).

---

## 8. End-to-end SSL VPN connect ordering (interoperable client target)

1. **Daemon boot**: `main` → `InitInstance` → `LoadSystemConfInfo` (reads `conf/iNode.conf`: LOG_LEVEL, FORBID_PAP→`X1_SetForbidPap`, EADIP/EADPORT) → `createThread` → `processMain` opens `/tmp/iNode/` FIFO bus (path `iNodeCmn`, handlers by subMod) + UDP **127.0.0.1:50001** command socket; `processDetector` on UDP 20102. `CSslVpnMgr::init()` runs.
2. **GUI handshake**: GUI sends `H3C_MSG_FRONT_START (113)` (UDP `CPacketItem`); daemon logs `"Process H3C_MSG_FRONT_START Request."` and may answer `H3C_MSG_GET_AUTH_INFO (204)`.
3. **Pick gateway/domain**: GUI → pipe subMod 5 `H3C_SSLVPN_QUERY_AUTH_PARAM (200)` → `CSslVpnMgr::queryVpnAuthParam` (gateway returns domains/auth modes). Optionally `H3C_SSLVPN_QUERY_DOMAIN_PARAM (201)`.
4. **Captcha (if required)**: `H3C_SSLVPN_QUERY_VERTIFY_PIC (202)` → `queryVertifyPic`.
5. **Authenticate**: GUI sends `H3C_AUTH_REQUEST (1)` / SSL VPN auth carrying credentials (encrypted via `utl_encrpt`). Server-side challenge handled through `H3C_MSG_CHALLENGE_AUTH_INFO (302)` / `H3C_MSG_CHALLENGE_AUTH_RESULT (307)`. Either the daemon loads a matching `*.icnf` (`procSslVpnAuthReq` → `CreateSslConn`) or uses the live params; then `CSslVpnMgr::setSslvpnUser` + `CSslVpnMgr::startConn(true)` brings up the TLS tunnel (real wire protocol in `libiNodeSslvpnPt.so`).
6. **Connected notifications**: daemon pushes `H3C_AUTH_NOTIFY (16)`, `H3C_MSG_SSLVPN_INFO (303)`, `H3C_MSG_CONN_INFO (301)`, `H3C_MSG_STACHG (300)` to FIFO `iNodeClient`.
7. **Disconnect**: GUI → `H3C_SSLVPN_SHUTDOWN (203)` (pipe) or `H3C_LOGOFF_REQ (3)` (UDP); daemon `procSslVpnLogOff(CPacketItem&)` → `CSslVpnMgr::onSslVpnConnOfflineMsg()` / `stopConn`. On shutdown `logOffAllConnections()`.
8. **Auto-reconnect / startup auto-login**: `startAutoLogin()` → `LoadSslvpnAutoRun()` → `LoadSslVpnRun(name, action, …)` for each `.icnf` with `AUTO_AUTHEN=1`.

### Key constants
- `/tmp/iNode/` — FIFO IPC dir (mode `a+rwx`), created by `system("mkdir -p -m a+rwx /tmp/iNode/")`.
- UDP command socket: **127.0.0.1:50001** (`0xC351`, `AF_INET/SOCK_DGRAM`).
- Detector UDP socket: **port 20102** (`0x4E86`).
- EAD default port: **9019** (`0x233B`).
- `CPacketItem` header = 12 bytes (attrs at offset 12), big-endian; attr ValueType `6` = integer.
- `npmsghdr` = 48 bytes (`type`, `seq`, `path[32]`, `subMod`, `datalen`).
- subMod 5 = SSL VPN; pipe path `iNodeCmn` (daemon listen) / `iNodeClient` (GUI listen).

### Open questions / out-of-scope
- The actual SSL VPN TLS/HTTP wire protocol (URLs, headers, XML/JSON bodies, cookie names, challenge crypto) lives in `libiNodeSslvpnPt.so::CSslVpnMgr` — analyzed separately.
- The `utl_encrpt` credential cipher and `_SslvpnUser`/`_SslvpnDomainListReq/Resp` struct layouts are defined in the SSL VPN/utility libs.
- Exact `PACKET_ATTR_DICTION` attribute-type numbering (the `m_ucAttrType` constants) needs a dump of that table in `libutility.so`.
