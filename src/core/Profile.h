#pragma once

#include "Protocol.h"
#include <QString>
#include <QUuid>

namespace inode {

// How the supplicant / PPP session negotiates its credential exchange.
// Mirrors FORBID_PAP in the original client's conf/iNode.conf plus the
// rjv3/minieap command-line toggle set.
enum class AuthMode {
    Auto = 0,      // let the supplicant decide
    Pap,
    Chap,
    MsChapV2,
    EapMd5,
    EapPeap,
    HcChapV2,      // H3C proprietary — what libInodeX1Pt.so speaks
};

// Whether the profile wants a static IP or DHCP after the link is up.
// Matches the "CMN_IpModeSetFoul" branch in the original client.
enum class IpMode {
    Inherit = 0,   // don't touch whatever the OS already has
    Dhcp,
    Static,
};

// The original client has a "trust mode" for servers that validates the
// EAD/Portal server's TLS cert. Exposed here so users on locked-down
// campuses can flip it off.
enum class TrustMode {
    System = 0,    // validate against the system CA store
    Pinned,        // validate against caCertPath
    None,          // skip (for lab use only; UI nags)
};

// A single connection profile — maps to one <location><connection> in the
// original client's custom/clientfiles/locations.xml, plus the options
// that iNodeCustom.xml layers on top.
struct Profile {
    QUuid        id;
    QString      name;
    ProtocolKind kind = ProtocolKind::Dot1x;

    // ---- Common identity ----
    QString      username;
    QString      domain;
    QString      serviceName;         // optional "service" field the server expects (H3C real-name/display-name)
    QString      serverHost;
    quint16      serverPort = 0;
    QString      iface;                // network interface (802.1X, WLAN)

    // ---- Credential/session handling ----
    bool         savePassword   = false;
    bool         autoConnect    = false;     // connect on app start if true
    bool         autoReconnect  = false;     // reconnect on unexpected drop
    int          reconnectMaxTries = 5;
    int          reconnectBackoffSec = 10;   // initial backoff; doubles up to 60s
    int          heartbeatSec   = 30;        // keep-alive heartbeat (0 = off)
    int          logLevel       = 3;         // 0 quiet .. 5 verbose

    // ---- IP / routing ----
    IpMode       ipMode         = IpMode::Inherit;
    QString      staticIp;
    QString      staticNetmask;
    QString      staticGateway;
    QString      staticDns;

    // ---- Cert / trust ----
    TrustMode    trustMode      = TrustMode::System;
    QString      caCertPath;
    QString      userCertPath;
    QString      userCertPin;

    // ---- 802.1X / WLAN ----
    AuthMode     authMode       = AuthMode::Auto;
    bool         dot1xUseRjv3   = true;       // rjv3 extension (H3C/Ruijie)
    int          dot1xServiceType = 1;        // rjv3 'service' (1=iNode typical)
    QString      dot1xCarrier;                // rjv3 '--pwd-hash-once' carrier hint
    QString      dot1xExtraArgs;              // free-form args appended to supplicant
    QString      wlanSsid;                    // WLAN only: SSID to associate with
    bool         wlanHiddenSsid = false;

    // ---- Portal ----
    QString      portalSecret;                // shared secret; often "h3c" or "huawei3com"
    int          portalDialect  = 0;          // 0=standard GB/T 28181, 1=H3C TLV (not yet impl.)

    // ---- SSL VPN ----
    QString      sslvpnUrl;
    bool         sslvpnSplitTunnel = true;    // route only the gateway's subnets
                                              // (enterprise); keep internet direct
    QString      sslvpnPinSha256;             // pin the gateway cert SHA-256
                                              // (secure way to trust a self-signed
                                              // gateway; overrides trust mode)
    bool         sslvpnEadHostcheck = false;  // send the EAD host-check ack (-> --ead)
    // Zero-Trust / SDP single-packet-authorization knock (hex key/AID from an
    // SDP enrollment; when a key is set the client knocks before connecting).
    QString      sslvpnSpaKey;
    QString      sslvpnSpaAid;
    QString      sslvpnSpaPorts;              // comma-separated, default 443

    // ---- L2TP / IPSec ----
    QString      psk;                         // IPSec PSK
    bool         l2tpForceUdpEncap = true;    // NAT-T

    // ---- EAD (posture) ----
    QString      eadServer;
    quint16      eadPort         = 9019;
    bool         eadRequired     = false;

    static Profile makeNew() {
        Profile p;
        p.id = QUuid::createUuid();
        return p;
    }
};

// Helpers for (de)serialization of the enums.
QString authModeToString(AuthMode m);
AuthMode authModeFromString(const QString& s);
QString ipModeToString(IpMode m);
IpMode ipModeFromString(const QString& s);
QString trustModeToString(TrustMode m);
TrustMode trustModeFromString(const QString& s);

} // namespace inode
