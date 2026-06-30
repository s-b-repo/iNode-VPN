#pragma once

#include "core/Profile.h"
#include "core/Protocol.h"

#include <QUuid>

class QProcess;
class QTimer;

namespace inode {

// H3C SSL VPN (iNode "SVPN", protocol V7) — XML-over-HTTPS auth followed by a
// NET_EXTEND data tunnel over TLS, programmed into a TUN device.
//
// Rather than re-deriving the wire format in C++, this plugin drives the
// bundled clean-room backend (`backends/h3csvpn`, a small pure-Python
// implementation reverse-engineered from the unstripped Linux iNode 7.3
// client and validated against a live SSLVPN-Gateway/7.0). This mirrors how
// the 802.1X plugin wraps minieap and the L2TP plugin wraps strongswan: the
// proprietary protocol lives in a dedicated, separately-testable backend, and
// the Qt layer owns the UI/state/credential/stat surface.
//
// Flow:
//   1. Build the backend command line from the Profile (gateway, user, domain,
//      TLS trust, client cert, --auto-captcha).
//   2. The tunnel needs CAP_NET_ADMIN, so launch via the inode-svpn-helper
//      through pkexec (or directly if already root). The password is streamed
//      to the helper on stdin, never placed in argv.
//   3. Parse the backend's stdout/stderr to drive the connection state and
//      live stats (interface / IP / DNS).
//   4. disconnect() runs `inode-svpn-helper stop`, which SIGINTs the backend
//      so it logs out of the gateway and tears the TUN down cleanly.
//
// Limitations are the backend's: GM/SM2 (CNTLS / SKF UKey) gateways and
// Zero-Trust SDP registration are out of scope. See backends/h3csvpn and
// docs/PROTOCOLS.md.
class SslVpnProtocol : public IProtocol {
    Q_OBJECT
public:
    explicit SslVpnProtocol(QObject* parent = nullptr);
    ~SslVpnProtocol() override;

    ProtocolKind kind() const override { return ProtocolKind::SslVpn; }
    bool isImplemented() const override { return true; }

    void connectWith(const Profile& profile) override;
    void disconnect() override;

private:
    void onReadyRead();
    void onFinished(int exitCode, int exitStatus);
    void pollStats();

    // Build the [launcher, args] pair that runs the helper, prepending pkexec
    // (or sudo) unless we are already root. Returns false if no escalation
    // path exists when one is needed.
    bool buildHelperInvocation(const QStringList& helperArgs,
                               QString* launcher, QStringList* full) const;
    // Synchronously ask the helper to tear the tunnel down (SIGINT backend).
    void requestStop();

    // Locate the vendored python backend dir (the one *containing* h3csvpn/).
    static QString backendDir();
    // Locate the inode-svpn-helper script.
    static QString helperPath();

    QProcess* m_proc       = nullptr;
    QTimer*   m_statsTimer = nullptr;
    QString   m_connName;        // svpn-<id8>; also the helper pidfile key
    QString   m_iface;           // TUN device the backend reports
    QString   m_password;        // held only until streamed to the helper
    QString   m_lastError;       // last "[x] ..." line from the backend
    bool      m_userDisconnect = false;
};

} // namespace inode
