#pragma once

#include <QString>
#include <QVector>

namespace inode {

struct InterfaceInfo {
    QString name;
    QString hwAddress;
    bool    isUp = false;
    bool    isWireless = false;
    bool    isLoopback = false;
    bool    hasCarrier = false;
};

class InterfaceDiscovery {
public:
    // Enumerate usable interfaces, skipping loopback and virtual interfaces
    // that can't carry 802.1X traffic (bridges/dummies/bonds are not
    // filtered — they may be legitimate in some deployments).
    static QVector<InterfaceInfo> list();

    // Subset: only wired candidates suitable for 802.1X.
    static QVector<InterfaceInfo> wired();

    // Subset: only wireless candidates suitable for WLAN.
    static QVector<InterfaceInfo> wireless();
};

} // namespace inode
