# H3C iNode SSL VPN — Data Plane / Tunnel (KEY=tunnel)

Reverse-engineered from `libs/libiNodeSslvpnPt.so` and `libs/libvnic.so`
(both unstripped, DWARF source line refs present). Source tree:
`/root/gl/br_patch_PC_V7R3B05D151/LinuxClient/SRC/code/{sslvpn,vnictun}`.
Version markers in binary: `User-Agent: SSLVPN-Client/7.0`, V7 structs (`_VPNAuthUrlV7`,
`_VPNLogInPacketInfoV7`).

----------------------------------------------------------------------
## 1. Transport overview — single TLS socket, HTTP-then-tunnel upgrade

The data tunnel is **TCP-over-TLS** (single connection). There is **NO** UDP/DTLS data
channel in the Linux client — DTLS is *recognised but rejected*: a config frame
sub-type that means "DTLS" is logged `svpn.cli.hdlInput: data of network configure is DTLS data.`
and otherwise ignored (`SslClient.cpp:746-749`). All tunnel traffic flows over the same
TLS socket that did the HTTPS auth.

Connection life-cycle (state strings from `CSslVpnMgr::startConn`, `SslvpnMgr.cpp`):
```
SSLVPN_StartAuthReq  -> SSLVPN_UserAuthSuccess
                     -> SSLVPN_StartVpnTunnel -> SSLVPN_VpnTunnelSuccess
(failures: SSLVPN_UserAuthFail / SSLVPN_VpnTunnelFail)
```

TCP+TLS connect is done by `CSslVpnConnector::conn2VpnGateway(CSslVpnSockStream&,
ACE_INET_Addr const&, EVP_PKEY*, int, std::string)` (`SslvpnConnector.cpp`):
- TCP connect to gateway `ip:port`.
- `setsockopt(TCP_USER_TIMEOUT)` (log: `set TCP_USER_TIMEOUT option error`).
- `SSL_connect()` with server-cert verification. Cert errors mapped to
  `SSLVPN_VERITY_CERT_BAD_CERTIFICATE / _CERTIFICATE_EXPIRED / _UNKONWN_CA / _AUTHFAIL`.

### "ioc" fd vs "data" fd
There are two distinct fd concepts, but only one is a *network* socket:
- The **SSL/TLS socket** to the gateway = the tunnel data channel (read/written in
  `CSslClient::handle_input` / `handle_output`).
- `NS_VNIC::tunif::iocfd` (in libvnic) is **not** a tunnel data fd — it is a plain
  `AF_INET` datagram socket used only to issue `SIOCSIF*` ioctls on the TUN interface
  (`getiocfd()/getiocfdptr()`). `NS_ROUTE::rtlook::nlsock` is a separate `AF_NETLINK`
  socket for route programming. The TUN char-device fd (`/dev/net/tun`) is the local
  end of the data path.

----------------------------------------------------------------------
## 2. Post-auth tunnel-upgrade request:  NET_EXTEND

After authentication succeeds (HTTP `POST /svpn/vpnuser/login_submit.cgi` etc., handled
in the auth component), the client upgrades the SAME TLS connection from HTTP to the raw
tunnel protocol by sending a non-standard request line **`NET_EXTEND / HTTP/1.1`**.
Built by `CSslClient::buildIPHandshakeReq(...)` (`SslClient.cpp:1177-1218`,
xrefs to `.rodata` at `0x841a0`/`0x841c4`).

Two template variants exist in `.rodata`:
```
NET_EXTEND / HTTP/1.1\r\nCookie:        (0x841a0)
NET_EXTEND / HTTP/1.1\r\n               (0x841c4)
```

Assembled request (header order observed via the ostringstream `<<` sequence):
```
NET_EXTEND / HTTP/1.1\r\n
Host: <gateway-host>\r\n                         (SslClient.cpp:1188-1190)
User-Agent: SSLVPN-Client/7.0\r\n                (SslClient.cpp:1194-1196)
Cookie: svpnginfo=<svpnginfo-cookie>\r\n          (SslClient.cpp:1209-1211; utf82gbk'd)
\r\n
```
- `svpnginfo` is the session cookie obtained from the auth `Set-Cookie:` headers.
  Other session cookies seen in the codebase: `svpnvldid`, `svpnuid`, `vldID`,
  `domainId`, plus example `Cookie: svpnvldid=178; svpnuid=a48eafca8822d45b88f10a2118ec8400`.
- The cookie value is UTF-8 converted via `utf82gbk()` before being placed in the header
  (note the misleading log string `CHttpsAuth::buildLogOutReqV7: failed to convert
  strSslVpnginfo to utf8.` reused here at `SslClient.cpp:1206`).

The gateway replies with an HTTP-style response on the same socket; on success the
connection is then treated as a **raw bidirectional frame stream** (no further HTTP).
The first thing the gateway pushes down the tunnel is a **network-config frame**
(type 3 / sub 2, see §3) carrying the assigned virtual IP, mask, gateway, DNS and routes.

----------------------------------------------------------------------
## 3. PER-PACKET FRAMING over the TLS socket

Every message on the tunnel (both directions) is a 4-byte header + payload:

```
 offset  size  field
 ------  ----  -----------------------------------------------
   0      1    type      (uint8)
   1      1    subtype   (uint8)
   2      2    length    (uint16, BIG-ENDIAN / network order) = payload byte count
   4   length  payload
```
Total frame size = `length + 4`. Confirmed in both directions:

- **Egress build** `CSslClient::send2Remote(char* pkt, int len)` (`SslClient.cpp:1999-2005`):
  `buf = new[len+4]; buf[0]=1; buf[1]=0; *(uint16*)(buf+2)=htons(len);
   memcpy(buf+4, pkt, len);` then pushed to the entunnel queue.
- **Egress heartbeat** `CSslClient::heartBeat()` (`SslClient.cpp:600-611`):
  `buf = new[4]; buf[0]=2; buf[1]=1; *(uint16*)(buf+2)=0;` (length 0).
- **Ingress parse** `CSslClient::handle_input(int)` (`SslClient.cpp:689-707`):
  needs >=4 bytes header; reads `len = ntohs(*(uint16*)(buf+2))`, dispatches on `buf[0]`,
  then advances the recv cursor by `len + 4` (`SslClient.cpp:778`).

### Type / sub-type dispatch (from handle_input)
```
type=1            IP DATA packet.  payload = raw IP packet -> CVirNIC::Data_Input(payload, len)
                  (written to the TUN device).                      (SslClient.cpp:697-708)
type=2            "check type" — keepalive / heartbeat ack from gateway. Resets recv
                  cursor and the per-conn no-response state.         (SslClient.cpp:765-770)
type=3            NETWORK CONFIG, sub-type = buf[1]:
                    sub=1  "The data of network configure is empty" (error)  (713-716)
                    sub=2  "Updating the configure of network" -> changeVirNetWork()
                           payload is XML config; re-programs vIP/mask/gw/DNS/routes. (718-744)
                    sub=3  "data of network configure is DTLS data" (ignored)  (746-749)
type=4            "sslvpn gateway force client logoff, connection id %d" -> shutdown. (752-763)
default           "svpn.cli.hdlInput: Unknown type." -> drop.        (774-776)
```
Egress: the client only ever emits `type=1`(data, sub=0) and `type=2`(heartbeat, sub=1).

### Send path detail (egress aggregation)
- `pushEntunnelQ(void* frame)` queues an already-framed buffer onto `m_oEntunnelQ`
  (guarded by `m_oEntunnelQLock`); queue cap 255 ("entunnel Q too long" at >0xFF),
  then sets the ACE reactor WRITE mask so `handle_output` runs. (`SslClient.cpp:968-1016`)
- `fillSendBigBuf()` drains the queue into a 0x14000 (81920) byte "big buffer":
  for each queued frame it reads `pktlen = ntohs(*(uint16*)(frame+2)) + 4` and memcpy's
  the whole frame; stops when the big buf would overflow 0x14000. (`SslClient.cpp:846-878`)
- `flushSendBigBuf()` / `handle_output()` `SSL_write()` the big buffer to the gateway.
- Receive side reads into a per-conn 0x14000 buffer at struct off `+0x58`, cursor at
  `+0x34`, via `SSL_read` (wrapper at 0x446a0). Partial frames are retained across reads.

### Key CSslClient struct offsets (recovered)
```
+0x30  connection id (int)               (logged in force-logoff/notify)
+0x34  recv buffer cursor (int)
+0x3c  poll tick counter (++ each pollVirtualNetwork)         (SslClient.cpp:1734)
+0x40  ESslVpnVersion / config (int)
+0x44  consecutive heartbeats with NO response (int)
+0x48  max no-response threshold (int, from gateway config)   (offline when 0x44>=0x48)
+0x4c  "got response" flag, reset to 0 on activity            (SslClient.cpp:563)
+0x50  bool: network-config received / poll enabled
+0x58  recv buffer base (0x14000 bytes)
+0x60  send big buffer base (0x14000 bytes)
+0x140 send big buf total length
+0x144 send big buf fill cursor
+0xac  m_bPollVirNet (bool)                                   (SslClient.cpp:1725)
+0xb0  m_oEntunnelQ (ACE message queue)
+0xc8  m_oEntunnelQLock
```

----------------------------------------------------------------------
## 4. Heartbeat / keepalive ("tickle" / pollVirtualNetwork)

- A dedicated heartbeat thread is spawned by `CSslClient::startHeartBeat()`
  (`SslClient.cpp:2434-2443`, `pthread_create`, log `svpn.cli.startHbeat: start heart
  beat thread.`). The thread body (`SslvpnHeartBeatTimer`, `SslvpnMgr.cpp:210-229`) loops
  with `usleep(0xf4240)` = **1,000,000 us = 1 second** between iterations and calls
  `heartBeat()`.
- `heartBeat()` (`SslClient.cpp:560-619`):
  - If `+0x44 (noRespCount) >= +0x48 (maxOutTimes)`: log `The consecutive <N> heartbeat
    packets got no response. The user will be offline.` and notify UI (uses code 0x4a3e),
    then sleep `usleep(0xc350)`=50000us, set offline.
  - Otherwise: increment `+0x44`, build the 4-byte frame `02 01 00 00`, push to entunnel
    Q (drop+log on failure: `CSslClient::heartBeat failed push to entunnel Q, dropped.`).
- Receiving any frame from the gateway (notably a `type=2` "check type" ack) clears the
  no-response state, so the link stays up.
- `pollVirtualNetwork(int)` (`SslClient.cpp:1724-1757`) increments `+0x3c` each tick and
  is a no-op unless `+0xac (m_bPollVirNet)` is set (only after a network-config frame).

**Heartbeat frame on the wire (egress): `02 01 00 00` (4 bytes, no payload).**

----------------------------------------------------------------------
## 5. Virtual IP / netmask / gateway / DNS / routes assignment

These are delivered **in-band** in the `type=3 / sub=2` config frame (NOT in the auth
XML). `CSslClient::changeVirNetWork(istringstream&, string&)` parses the frame payload,
extracts the params via `getVpnParamFromResp`, and on change calls
`CVirNIC::changeVirNetwork(uint16, int, int, _tagNICInfo&, bool, string&, bool,bool,bool,bool)`
which delegates to `CVirNIC::configVirtNetwork(...)` (`VirNIC.cpp` / vnic). Logs:
`svpn.cli.chgVirtNet: ...` and `vnic.cfgVnet: interface %s set ip %s mask %s.`

Parameter struct `_tagNICInfo` fields (from `.debug_str` and isChange* methods):
```
iLocalGatewayIP   local (physical) IP used to reach the gateway
iPhyGateway       physical default gateway
iGateway          assigned VPN gateway (tunnel peer / vIP gateway)
iSubnetMask, iSubnetMaskLen    assigned netmask
(inner/virtual IP)              assigned virtual IP   (isChangeInnerIp)
ulDnsAddr0, ulDnsAddr1          DNS servers (v4)
oDnsAddrs / oDnsIPv6            DNS lists (v4/v6)
m_routes / m_fallBackRoutes     include + fallback routes  (NS_ROUTE::rte / std::pair<rte,fallBackInfo>)
bDefaultGateway   redirect-all-traffic flag
bChangeDns, bChangeRoute, bChangeWins, bRouteLimit, bRouteLimitIPv6, ...
```
Change detection: `isChangeInnerIp`, `isChangeRoute`, `isChangeDns` — config frames can
arrive mid-session to re-program the tunnel without tearing it down.

Note: `CSSLVpnXmlParser::GetVpnConnInfo(char const*, _VPNAuthUrlV7&)` (`SslVpnXmlParser.cpp
:145-180`) parses the *auth-page* XML (`<SSLVpnXml><gatewayinfo><data><auth>...`:
`supportPassword/supportCert/supportDKey/supportvldimg`, `url/vldimg/login/logout/
challenge`) — it is the auth capability advertisement, not the IP assignment.

----------------------------------------------------------------------
## 6. libvnic — TUN device creation and address/route/DNS programming

### 6.1 TUN device  (vnic_tun.cpp, NS_VNIC::tunif)
`ifopen()` (`vnic_tun.cpp:160-191`):
```
fd = open("/dev/net/tun", O_RDWR /*=2*/);
struct ifreq ifr; memset(&ifr,0,0x28);
ifr.ifr_flags = 0x1001;                  // IFF_TUN | IFF_NO_PI
strncpy(ifr.ifr_name, <name>, 16);       // interface name (e.g. "inode%d")
ioctl(fd, 0x400454ca /*TUNSETIFF = 0x40000|0x400054ca*/, &ifr);
```
`ifup()` (`vnic_tun.cpp:273-310`):
```
ioctl(iocfd,  0x8913 /*SIOCGIFFLAGS*/, &ifr);
ifr.ifr_flags |= IFF_UP;
ioctl(iocfd,  0x8914 /*SIOCSIFFLAGS*/, &ifr);   // and on v6iocfd
```
`iocfd` is a separate `AF_INET` socket for ioctls; `v6iocfd` an `AF_INET6` socket.

### 6.2 Address / netmask  (vnic_tun.cpp, ifsetaddr)
`ifsetaddr(addr, mask, dstaddr)` (`vnic_tun.cpp:369-451`) issues:
```
ioctl(iocfd, 0x8916 /*SIOCSIFADDR*/,    ...)   // set tunnel IP
ioctl(iocfd, 0x891a /*SIOCSIFNETMASK*/, ...)   // set netmask
ioctl(iocfd, 0x8918 /*SIOCSIFDSTADDR*/, ...)   // set P-t-P dst (when provided)
ioctl(iocfd, 0x891c /*SIOCSIFBRDADDR*/, ...)   // broadcast
```
(Full SIOC set observed across tunif: 0x8913,0x8914,0x8916,0x8918,0x891a,0x891c,0x8936.)
MTU: struct field `ifru_mtu`/`ulMTU`/`rt_mtu` is carried in config but no `SIOCSIFMTU`
ioctl is used directly here; MTU is applied via the route entry (`rt_mtu`) / left at the
TUN default.

### 6.3 Routes  (vnic_route.cpp, NS_ROUTE::rtlook / rte)
- IPv4 routes are programmed via **rtnetlink**:
  `do_init()` (`vnic_route.cpp:672-728`): `nlsock = socket(AF_NETLINK=16, SOCK_RAW,
  NETLINK_ROUTE)`, then `bind()` a `sockaddr_nl`.
  `nl_send_recv(nlmsghdr*, nlmsghdr*, int)` (`vnic_route.cpp:1300-1346`): builds an
  `nlmsghdr` (len/type/flags/seq/pid) + `rtmsg` with `RTA_GATEWAY`, `RTA_METRICS`, sends
  via `sendmsg`, reads via `recvmsg` (8000-byte buf), checks `nlmsgerr`.
  Route message types: `RTM_NEWROUTE`/`RTM_DELROUTE` (strings `NET_NEW_ROUTE`,
  `NET_DEL_ROUTE`). Include routes (`m_routes`), exclude routes, and fallback routes are
  all supported (`getRoutesFromStr`, `EXCLUDE ROUTES:`, `m_fallBackRoutes`).
- IPv6 routes are programmed by shelling out:
  `ip -6 route add %s/%d dev %s metric %d` / `ip -6 route del ...`
  (`ifAddIpv6Route`, `ifConifgIpv6Route`, `ifClearIpv6Route`).
- `bDefaultGateway` => full redirect; otherwise split-tunnel per route list. Metric and
  next-hop lookups via `linux_get_route`/`linux_gateway`/`set_nexthop_lookup`.

### 6.4 DNS  (vnic_dns.cpp, NS_DNS::dnserver)
`dnserver::add()` (`vnic_dns.cpp:41-...`) rewrites **`/etc/resolv.conf`**:
each server appended as `nameserver <ip>` followed by the marker
`#Line Generated by iNode SSL VPN Client`. `del()`/`clear()` restore. Both
`dns0`/`dns1` (v4, `ulDnsAddr0/1`) and IPv6 DNS (`oDnsIPv6`) are written
(logs `vnic.cfgVnet: add IPv4Dns<%s>.` / `add IPv6Dns<%s>.`).

----------------------------------------------------------------------
## 7. HTTP endpoints (control plane, same TLS host) — for context
```
GET  /svpn/image.cgi HTTP/1.1                                   (captcha image)
GET  /svpn/olduser_info.cgi?svpnlang=cn HTTP/1.1
GET  /svpn/vpnuser/kickolduser.cgi?OldUserID=...&IsKick=1&svpnlang=cn HTTP/1.1
POST /svpn/vpnuser/login_submit.cgi HTTP/1.1                    (credential submit)
POST /svpn/vpnuser/check_return.cgi HTTP/1.1                    (challenge / 2nd factor)
GET  /svpn/vpnuser/check.cgi
GET  /svpn/index.cgi  /  /svpn/logout.cgi
Common headers: Host:, User-Agent: SSLVPN-Client/7.0 (older: SSLVPN-Client/3.0 / MSIE),
  Content-Type: application/x-www-form-urlencoded, Content-Length:, Connection: Keep-Alive,
  Cookie: svpnginfo=/svpnvldid=/svpnuid=/domainId=/vldID=
```
Then `NET_EXTEND / HTTP/1.1` (§2) switches to the frame tunnel.

----------------------------------------------------------------------
## 8. Minimal interop recipe (data plane)
1. TLS-connect to gateway, run the HTTPS auth (separate component), collect the
   `svpnginfo` (and friends) session cookie(s).
2. On the SAME TLS socket send:
   `NET_EXTEND / HTTP/1.1\r\nHost: <gw>\r\nUser-Agent: SSLVPN-Client/7.0\r\n
    Cookie: svpnginfo=<cookie>\r\n\r\n`
3. Read the gateway response, then switch to raw 4-byte-framed mode.
4. Read frames: `[type][sub][len_be16][payload]`. Handle:
   - type=3/sub=2 -> parse config -> create `/dev/net/tun` (IFF_TUN|IFF_NO_PI),
     `SIOCSIFADDR`/`SIOCSIFNETMASK`, bring up, add routes (rtnetlink), write resolv.conf.
   - type=1 -> write `payload` to TUN.
   - type=2 -> heartbeat ack (clear no-response counter).
   - type=4 -> server forced logoff.
5. Read IP packets from TUN, wrap as `01 00 <htons(len)> <ip-packet>`, SSL_write.
6. Every 1 s send heartbeat `02 01 00 00`; if N consecutive heartbeats get no inbound
   data, go offline.
```
