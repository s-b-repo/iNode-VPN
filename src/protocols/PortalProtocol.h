#pragma once

#include "core/Profile.h"
#include "core/Protocol.h"

class QUdpSocket;
class QTimer;

namespace inode {

// H3C / CMCC Portal authentication.
//
// Two sub-dialects are handled:
//   - standard GB/T 28181 (Portal v2) — UDP/2000 by default. Fully on the
//     wire here: REQ_CHALLENGE → ACK_CHALLENGE → REQ_AUTH → ACK_AUTH →
//     AFF_ACK_AUTH, with MD5 checksums keyed on the shared secret.
//   - H3C proprietary dialect — recovered from libInodePortalPt.so. NOT just
//     "v2 plus a TLV": it uses a private opcode space (LOGIN=0x64, LOGOUT=0x66,
//     HANDSHAKE=0x68, …) and a distinct attribute set (BAS_IP=0x0A,
//     USER_NAME=0x65, USER_PASSWORD=0x66, PRIVATE_IP=0x67, PUBLIC_IP=0x68,
//     START_TIME=0x71, …). The 32-byte header and the MD5 authenticator
//     (= MD5(packet-with-auth-zeroed || shared_secret)) are shared with v2.
//     Implemented best-effort and UNTESTED against a live H3C Portal (we have
//     none). The H3C "anti-track" hash challenge (server attr 0x82 → 32-byte
//     client attr 0x83) is acknowledged best-effort only; its exact digest
//     (a function-code-dispatched MD5) was not fully recovered.
//
// The standard wire format follows the portal-v2 protocol ("Portal 2.0") that
// H3C documents publicly; many iMC/EIA Portal deployments accept a v2 client
// as long as the shared secret matches.
class PortalProtocol : public IProtocol {
    Q_OBJECT
public:
    explicit PortalProtocol(QObject* parent = nullptr);
    ~PortalProtocol() override;

    ProtocolKind kind() const override { return ProtocolKind::Portal; }
    bool isImplemented() const override { return true; }

    void connectWith(const Profile& profile) override;
    void disconnect() override;

private:
    enum class Step { Idle, Challenge, Auth, Affirm, KeepAlive };

    void sendChallenge();
    void sendAuth(const QByteArray& challenge);
    void sendAffirm();
    void sendLogout();
    void onDatagram();
    void onKeepAlive();

    // H3C proprietary dialect (m_dialect == 1).
    void sendH3cLogin();
    void sendH3cLogout();
    void sendH3cHeartbeat();
    void handleH3cPacket(const QByteArray& data);
    void replyH3cHashChallenge(const QByteArray& data);

    QUdpSocket* m_sock     = nullptr;
    QTimer*     m_keepAlive = nullptr;
    QString     m_host;
    quint16     m_port     = 2000;
    QString     m_secret;
    QString     m_user;
    QString     m_pass;
    QByteArray  m_userIp;     // 4 bytes
    QByteArray  m_userMac;    // 6 bytes (H3C TLV dialect)
    int         m_dialect    = 0;   // 0 = standard v2, 1 = H3C TLV
    quint16     m_serialNo   = 0;
    quint16     m_reqId      = 0;
    Step        m_step       = Step::Idle;
    int         m_retries    = 0;
};

} // namespace inode
