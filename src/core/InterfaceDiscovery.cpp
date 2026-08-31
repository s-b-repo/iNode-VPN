#include "InterfaceDiscovery.h"

#include <QFile>
#include <QFileInfo>
#include <QNetworkInterface>

namespace inode {

static bool isWireless(const QString& name) {
    // The kernel exposes a `wireless` directory under
    // /sys/class/net/<iface>/wireless for every Wi-Fi interface.
    const QString path = QStringLiteral("/sys/class/net/%1/wireless").arg(name);
    return QFileInfo::exists(path);
}

static bool hasCarrier(const QString& name) {
    QFile f(QStringLiteral("/sys/class/net/%1/carrier").arg(name));
    if (!f.open(QIODevice::ReadOnly | QIODevice::Text)) return false;
    return f.readAll().trimmed() == QByteArrayLiteral("1");
}

QVector<InterfaceInfo> InterfaceDiscovery::list() {
    QVector<InterfaceInfo> out;
    const auto all = QNetworkInterface::allInterfaces();
    out.reserve(all.size());
    for (const auto& ifs : all) {
        InterfaceInfo ii;
        ii.name       = ifs.name();
        ii.hwAddress  = ifs.hardwareAddress();
        ii.isUp       = ifs.flags().testFlag(QNetworkInterface::IsUp);
        ii.isLoopback = ifs.flags().testFlag(QNetworkInterface::IsLoopBack);
        ii.isWireless = inode::isWireless(ii.name);
        ii.hasCarrier = hasCarrier(ii.name);
        out.push_back(ii);
    }
    return out;
}

QVector<InterfaceInfo> InterfaceDiscovery::wired() {
    QVector<InterfaceInfo> out;
    for (const auto& i : list()) {
        if (i.isLoopback || i.isWireless) continue;
        if (i.hwAddress.isEmpty()) continue;   // skip dummies with no MAC
        out.push_back(i);
    }
    return out;
}

QVector<InterfaceInfo> InterfaceDiscovery::wireless() {
    QVector<InterfaceInfo> out;
    for (const auto& i : list()) if (i.isWireless) out.push_back(i);
    return out;
}

} // namespace inode
