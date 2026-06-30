#pragma once

#include <QDateTime>
#include <QMetaType>
#include <QString>

namespace inode {

// Snapshot of a live connection's observable state. Emitted periodically by
// IProtocol implementations so the UI status bar can show the same
// information that the original client surfaces: interface, IP, gateway,
// uptime, and byte counters.
struct ConnectionStats {
    QString    iface;
    QString    localIp;
    QString    gatewayIp;
    QString    remoteIp;
    qint64     bytesRx = 0;
    qint64     bytesTx = 0;
    QDateTime  connectedAt;

    bool isValid() const { return connectedAt.isValid(); }
};

} // namespace inode

Q_DECLARE_METATYPE(inode::ConnectionStats)
