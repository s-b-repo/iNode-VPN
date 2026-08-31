#pragma once

#include "core/Profile.h"
#include "core/Protocol.h"
#include "Dot1xProtocol.h"

class QProcess;

namespace inode {

// Wireless 802.1X. The typical iNode WLAN flow is:
//   1. Associate with the target SSID via NetworkManager. If the SSID is
//      open/enterprise the user completes the underlying 802.1X through
//      NetworkManager itself and no extra work is needed.
//   2. For pre-shared-key SSIDs that also gate on 802.1X afterwards
//      (campus captive-network topology), we chain into the normal Dot1x
//      supplicant on the associated interface.
//
// Falls back to pure 802.1X if wlanSsid is empty.
class WlanProtocol : public IProtocol {
    Q_OBJECT
public:
    explicit WlanProtocol(QObject* parent = nullptr);
    ~WlanProtocol() override;

    ProtocolKind kind() const override { return ProtocolKind::Wlan; }
    bool isImplemented() const override { return true; }

    void connectWith(const Profile& profile) override;
    void disconnect() override;

private:
    void associate(const Profile& profile);
    void runDot1x(const Profile& profile);

    Dot1xProtocol* m_inner = nullptr;
    QString        m_ssid;
    QString        m_iface;
};

} // namespace inode
