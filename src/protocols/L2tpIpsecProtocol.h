#pragma once

#include "core/Profile.h"
#include "core/Protocol.h"

#include <QByteArray>

class QProcess;
class QTimer;

namespace inode {

// L2TP/IPSec via system strongswan + xl2tpd.
//
// Flow:
//   1. Write /etc/ipsec.conf.d/inode-<id>.conf and an xl2tpd lns section
//      into /etc/xl2tpd/xl2tpd.conf.d/ (via the inode-l2tp-helper, polkit).
//   2. strongswan-starter reload + `ipsec up inode-<id>`
//   3. `echo "c inode-<id>" > /var/run/xl2tpd/l2tp-control`
//   4. Watch `ip addr show ppp0` for the tunnel address.
//
// Works against iMC/EIA deployments that accept RFC-compliant L2TP/IPSec.
// Deployments using H3C's proprietary negotiation extensions will need
// additional work inside the helper.
class L2tpIpsecProtocol : public IProtocol {
    Q_OBJECT
public:
    explicit L2tpIpsecProtocol(QObject* parent = nullptr);
    ~L2tpIpsecProtocol() override;

    ProtocolKind kind() const override { return ProtocolKind::L2tpIpsec; }
    bool isImplemented() const override { return true; }

    void connectWith(const Profile& profile) override;
    void disconnect() override;

private:
    // Runs the privileged helper. Any secrets are passed on the helper's stdin
    // (never in argv) so they cannot be seen in `ps` / /proc.
    bool runHelper(const QStringList& args, const QByteArray& stdinData = {});
    void pollStats();

    QUuid   m_profileId;
    QString m_connName;
    QTimer* m_statsTimer = nullptr;
};

} // namespace inode
