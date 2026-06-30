#include "NetUtil.h"

#include <QFile>
#include <QHostAddress>
#include <QNetworkInterface>
#include <QRegularExpression>

#include <climits>

namespace inode::netutil {

QString primaryIpv4(const QString& iface) {
    if (iface.isEmpty()) return {};
    const auto ifs = QNetworkInterface::allInterfaces();
    for (const auto& i : ifs) {
        if (i.name() != iface) continue;
        for (const auto& e : i.addressEntries()) {
            const auto a = e.ip();
            if (a.protocol() == QAbstractSocket::IPv4Protocol) return a.toString();
        }
    }
    return {};
}

QString defaultGateway(const QString& iface) {
    // /proc/net/route fields:
    //   Iface  Dest  Gateway  Flags  RefCnt  Use  Metric  Mask  MTU  Window  IRTT
    // values in little-endian hex. We want rows where Dest == 00000000 (default).
    QFile f(QStringLiteral("/proc/net/route"));
    if (!f.open(QIODevice::ReadOnly | QIODevice::Text)) return {};
    QString bestGw;
    int bestMetric = INT_MAX;
    bool first = true;
    while (!f.atEnd()) {
        const auto line = QString::fromLatin1(f.readLine()).trimmed();
        if (first) { first = false; continue; }
        const auto parts = line.split(QRegularExpression(QStringLiteral("\\s+")), Qt::SkipEmptyParts);
        if (parts.size() < 8) continue;
        if (parts.at(1) != QStringLiteral("00000000")) continue;
        if (!iface.isEmpty() && parts.at(0) != iface) continue;
        bool ok = false;
        const quint32 rawGw = parts.at(2).toUInt(&ok, 16);
        if (!ok) continue;
        int metric = parts.at(6).toInt();
        if (metric > bestMetric) continue;
        bestMetric = metric;
        // Little-endian — byte-reverse to dotted-quad.
        bestGw = QString::asprintf("%u.%u.%u.%u",
                                   rawGw        & 0xffu,
                                  (rawGw >>  8) & 0xffu,
                                  (rawGw >> 16) & 0xffu,
                                  (rawGw >> 24) & 0xffu);
    }
    return bestGw;
}

void readByteCounters(const QString& iface, qint64* rx, qint64* tx) {
    if (rx) *rx = -1;
    if (tx) *tx = -1;
    if (iface.isEmpty()) return;
    QFile f(QStringLiteral("/proc/net/dev"));
    if (!f.open(QIODevice::ReadOnly | QIODevice::Text)) return;
    while (!f.atEnd()) {
        const auto line = QString::fromLatin1(f.readLine());
        const int colon = line.indexOf(':');
        if (colon <= 0) continue;
        const auto name = line.left(colon).trimmed();
        if (name != iface) continue;
        const auto parts = line.mid(colon + 1).split(QRegularExpression(QStringLiteral("\\s+")),
                                                     Qt::SkipEmptyParts);
        if (parts.size() >= 9) {
            if (rx) *rx = parts.at(0).toLongLong();
            if (tx) *tx = parts.at(8).toLongLong();
        }
        return;
    }
}

void refreshStats(ConnectionStats& s) {
    if (s.iface.isEmpty()) return;
    s.localIp   = primaryIpv4(s.iface);
    s.gatewayIp = defaultGateway(s.iface);
    readByteCounters(s.iface, &s.bytesRx, &s.bytesTx);
}

} // namespace inode::netutil
