#include "ProtocolFactory.h"

#include "protocols/Dot1xProtocol.h"
#include "protocols/L2tpIpsecProtocol.h"
#include "protocols/PortalProtocol.h"
#include "protocols/SslVpnProtocol.h"
#include "protocols/EadProtocol.h"
#include "protocols/WlanProtocol.h"

namespace inode {

std::unique_ptr<IProtocol> ProtocolFactory::create(ProtocolKind kind, QObject* parent) {
    switch (kind) {
        case ProtocolKind::Dot1x:     return std::make_unique<Dot1xProtocol>(parent);
        case ProtocolKind::L2tpIpsec: return std::make_unique<L2tpIpsecProtocol>(parent);
        case ProtocolKind::Portal:    return std::make_unique<PortalProtocol>(parent);
        case ProtocolKind::SslVpn:    return std::make_unique<SslVpnProtocol>(parent);
        case ProtocolKind::Ead:       return std::make_unique<EadProtocol>(parent);
        case ProtocolKind::Wlan:      return std::make_unique<WlanProtocol>(parent);
        case ProtocolKind::Sdp:
            // SDP (software-defined perimeter) is, in H3C's stack, an SSL VPN
            // preceded by a Single-Packet-Authorization knock that opens the
            // gateway port. We drive it with the same backend, supplying the
            // SPA knock parameters from the profile.
            return std::make_unique<SslVpnProtocol>(parent);
    }
    return nullptr;
}

} // namespace inode
