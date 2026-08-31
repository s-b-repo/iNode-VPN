#include "Protocol.h"

namespace inode {

QString protocolName(ProtocolKind k) {
    switch (k) {
        case ProtocolKind::Dot1x:     return QStringLiteral("802.1X");
        case ProtocolKind::Portal:    return QStringLiteral("Portal");
        case ProtocolKind::SslVpn:    return QStringLiteral("SSL VPN");
        case ProtocolKind::L2tpIpsec: return QStringLiteral("L2TP/IPSec");
        case ProtocolKind::Wlan:      return QStringLiteral("WLAN");
        case ProtocolKind::Ead:       return QStringLiteral("EAD");
        case ProtocolKind::Sdp:       return QStringLiteral("SDP");
    }
    return QStringLiteral("Unknown");
}

ProtocolKind protocolFromInt(int value) {
    switch (value) {
        case 8021:  return ProtocolKind::Dot1x;
        case 5020:  return ProtocolKind::Portal;
        case 7000:  return ProtocolKind::SslVpn;
        case 2401:  return ProtocolKind::L2tpIpsec;
        case 1100:  return ProtocolKind::Wlan;
        case 9019:  return ProtocolKind::Ead;
        case 19006: return ProtocolKind::Sdp;
    }
    return ProtocolKind::Dot1x;
}

QString stateName(ConnectionState s) {
    switch (s) {
        case ConnectionState::Disconnected:   return QObject::tr("Disconnected");
        case ConnectionState::Connecting:     return QObject::tr("Connecting");
        case ConnectionState::Authenticating: return QObject::tr("Authenticating");
        case ConnectionState::Connected:      return QObject::tr("Connected");
        case ConnectionState::Disconnecting:  return QObject::tr("Disconnecting");
        case ConnectionState::Failed:         return QObject::tr("Failed");
    }
    return {};
}

void IProtocol::setState(ConnectionState s) {
    if (m_state == s) return;
    m_state = s;
    emit stateChanged(s);
}

void IProtocol::setStats(const ConnectionStats& s) {
    m_stats = s;
    emit statsUpdated(m_stats);
}

} // namespace inode
