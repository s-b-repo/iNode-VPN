#pragma once

#include <QString>

#include <functional>

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
    // Synchronous (bounded 30 s) — the DHCP path blocks on dhclient.
    static bool apply(const Profile& profile, const QString& iface);
    // Asynchronous variant for GUI call paths: never blocks; DHCP mode runs
    // dhclient in the background and `onDone` fires when the bind settles.
    static void applyAsync(const Profile& profile, const QString& iface,
                           std::function<void(bool)> onDone = {});
    // Undo a previously-applied static configuration (no-op unless Static).
    static void clear(const Profile& profile, const QString& iface);
    // Asynchronous teardown — used from GUI paths (protocol teardown).
    static void clearAsync(const Profile& profile, const QString& iface);

    // dotted mask ("255.255.255.0") or already-a-prefix ("24") -> prefix length.
    static int maskToPrefix(const QString& mask);

private:
    static QString helperPath();
    static bool runHelper(const QStringList& args);
    static void runHelperAsync(const QStringList& args,
                               std::function<void(bool)> onDone = {});
    // Builds the helper argv for a static apply/clear. Returns false when
    // the profile has no static address configured.
    static bool staticArgs(const Profile& p, const QString& iface, bool apply,
                           QStringList* out);
};

} // namespace inode
