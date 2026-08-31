#pragma once

#include "core/Protocol.h"
#include "core/Profile.h"

class QProcess;
class QTimer;

namespace inode {

// 802.1X auth wrapping the minieap (or mentohust) CLI. These are open-source
// reimplementations of the H3C/Ruijie HC-CHAPv2 802.1X variant that the
// original iNodeClient uses on campus/enterprise wired networks.
//
// Requires: minieap OR mentohust installed and either CAP_NET_RAW on the
// binary or root (pkexec wrapper).
class Dot1xProtocol : public IProtocol {
    Q_OBJECT
public:
    explicit Dot1xProtocol(QObject* parent = nullptr);
    ~Dot1xProtocol() override;

    ProtocolKind kind() const override { return ProtocolKind::Dot1x; }
    bool isImplemented() const override { return true; }

    void connectWith(const Profile& profile) override;
    void disconnect() override;

private:
    void startProcess(const QString& binary, const QStringList& args,
                      const QByteArray& stdinData = {});
    void onReadyRead();
    void onFinished(int exitCode, int exitStatus);
    void pollStats();

    QProcess* m_proc = nullptr;
    QTimer*   m_statsTimer = nullptr;
    QString   m_password;     // held only during the auth window
    QString   m_iface;
    Profile   m_profile;      // kept so the IP mode can be applied post-auth
};

} // namespace inode
