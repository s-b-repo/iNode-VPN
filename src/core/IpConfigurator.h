#pragma once

#include <QString>

namespace inode {

class Profile;

// Applies a profile's IP mode (Inherit / DHCP / Static) to a given interface
// after the link is up. Inherit is a no-op; DHCP reuses dhcp::renew(); Static
// programs the address/route/DNS through the privileged inode-ipcfg-helper.
//
// This is meant for protocols that own a real local NIC (802.1X, WLAN) — for
// tunnel protocols the server/tunnel assigns addressing, so IP mode is ignored.
class IpConfigurator {
public:
    // Returns true on success (or a clean no-op). Failures are logged.
    static bool apply(const Profile& profile, const QString& iface);
    // Undo a previously-applied static configuration (no-op unless Static).
    static void clear(const Profile& profile, const QString& iface);

    // dotted mask ("255.255.255.0") or already-a-prefix ("24") -> prefix length.
    static int maskToPrefix(const QString& mask);

private:
    static QString helperPath();
    static bool runHelper(const QStringList& args);
};

} // namespace inode
