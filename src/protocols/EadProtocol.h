#pragma once

#include "core/Profile.h"
#include "core/Protocol.h"

class QUdpSocket;
class QTimer;

namespace inode {

// EAD (End-point Admission Defense) — H3C/iMC standalone posture check, the
// "SEC" protocol over UDP/9019.
//
// This is a clean-room implementation of the wire protocol recovered from the
// licensed client's libInodeSecurityAuth.so (see docs/PROTOCOLS.md). Contrary
// to the long-standing assumption that EAD needs a signed blob from a closed
// collector, the SEC posture packet carries *no* RSA/HMAC signature: it is
// sealed only by a keyed-MD5 checksum over a hardcoded seed
// ("SC-EAD_Server$REQ&ShareKey@9019"), which is constant across all clients.
// A clean-room client can therefore build a SEC_CHECK_RESULT the server
// accepts. The posture itself is reported "compliant" (each *checkResult field
// empty = pass).
//
// Header (28 bytes, big-endian length/pktId/opcode):
//   +0  u32  ulPktHeadId   = bytes 00 0A D8 77
//   +4  u16  usPktHeadLen  = 28 + body length
//   +6  u8[16] checkSum    = MD5(packet-with-cksum-zeroed || seed)
//   +22 u32  pktId         = per-packet correlator
//   +26 u16  opcode        = SECURITY_AUTH_MSG
//   +28 ...  body          = UTF-8 XML (unencrypted on the initial handshake)
//
// Transport is plain UDP; no privileges required (like PortalProtocol).
// Body encryption (ECB-XTEA) is only negotiated for later, post-handshake
// packets and is not exercised here — the handshake packets are unencrypted.
//
// Untested against a live iMC EIA server (we have none); the framing,
// checksum, field schema and state machine are faithful to the binary.
class EadProtocol : public IProtocol {
    Q_OBJECT
public:
    explicit EadProtocol(QObject* parent = nullptr);
    ~EadProtocol() override;

    ProtocolKind kind() const override { return ProtocolKind::Ead; }
    bool isImplemented() const override { return true; }

    void connectWith(const Profile& profile) override;
    void disconnect() override;

private:
    enum class Step { Idle, Start, AwaitVerdict, Online };

    void sendStart();
    void sendCheckResult(quint16 opcode);
    void sendHeartbeat();
    void sendOffline();
    void onDatagram();
    void onHeartbeat();
    void onRetry();

    QByteArray buildPacket(quint16 opcode, const QByteArray& body);
    QByteArray buildPostureXml() const;
    void transmit(const QByteArray& pkt);

    QUdpSocket* m_sock      = nullptr;
    QTimer*     m_heartbeat = nullptr;
    QTimer*     m_retry     = nullptr;
    QString     m_host;
    quint16     m_port      = 9019;
    QString     m_user;
    QString     m_iface;
    QByteArray  m_mac;          // identity: client MAC (xx:xx:..)
    QByteArray  m_ip;           // identity: IPv4 dotted string
    quint32     m_pktId     = 0;
    Step        m_step      = Step::Idle;
    int         m_retries   = 0;
    QByteArray  m_lastPkt;      // for retransmit
};

} // namespace inode
