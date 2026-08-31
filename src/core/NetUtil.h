#pragma once

#include "ConnectionStats.h"
#include <QString>

namespace inode::netutil {

// Best-effort resolution of the IPv4 address currently bound to iface.
// Returns an empty string if the interface does not exist or has no IPv4.
QString primaryIpv4(const QString& iface);

// Best-effort resolution of the default gateway *reachable through* iface.
// Parses `/proc/net/route` — no external process.
QString defaultGateway(const QString& iface);

// Reads RX/TX byte counters for iface from /proc/net/dev. Values are set to
// -1 on failure (missing iface / parse error).
void readByteCounters(const QString& iface, qint64* rx, qint64* tx);

// Fills in .localIp, .gatewayIp, .bytesRx, .bytesTx by reading /proc.
// Leaves .iface/.connectedAt unchanged.
void refreshStats(ConnectionStats& s);

} // namespace inode::netutil
