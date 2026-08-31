#pragma once

#include <QObject>
#include <QString>

namespace inode::dhcp {

// Kicks off a DHCP renew on the given interface. Mirrors the flow in the
// original client's `renew.ps`: prefer `nmcli device reapply`, fall back to
// `dhclient -r && dhclient <iface>`. Always runs via the system's usual
// DHCP machinery (no polkit needed for nmcli on normal desktops).
//
// Returns true if the helper was *invoked*; inspect the Logger for the
// actual outcome. Emits on Logger::info/warn/error as it goes.
bool renew(const QString& iface);

} // namespace inode::dhcp
