#include "EadProtocol.h"

#include "core/Logger.h"
#include "core/NetUtil.h"

#include <QCryptographicHash>
#include <QHostAddress>
#include <QHostInfo>
#include <QNetworkDatagram>
#include <QNetworkInterface>
#include <QSysInfo>
#include <QTimer>
#include <QUdpSocket>
#include <QtEndian>

#include <cstring>

namespace inode {

// SEC message types (enum SECURITY_AUTH_MSG), recovered from
// libInodeSecurityAuth.so. Opcode is the 16-bit big-endian field at +26.
static constexpr quint16 SEC_START          = 1;
static constexpr quint16 SEC_CHECK_LIST     = 2;
static constexpr quint16 SEC_CHECK_RESULT   = 3;
static constexpr quint16 SEC_CHCK_SUCCESS   = 4;
static constexpr quint16 SEC_CHECK_FAIL     = 6;
static constexpr quint16 SEC_HEARTBEAT      = 17;
static constexpr quint16 SEC_HEARTBEAT_RESP = 18;
static constexpr quint16 SEC_OFFLINE        = 19;
static constexpr quint16 SEC_ACL_REQUEST    = 97;

// Keyed-MD5 checksum seed (constant across all clients/sessions; the only
// "secret" sealing the posture packet). 31 bytes, no trailing NUL.
static constexpr char SEC_SEED[] = "SC-EAD_Server$REQ&ShareKey@9019";
static constexpr int  HEADER_LEN = 28;

static QByteArray md5(const QByteArray& in) {
    return QCryptographicHash::hash(in, QCryptographicHash::Md5);
}

EadProtocol::EadProtocol(QObject* parent) : IProtocol(parent) {}

EadProtocol::~EadProtocol() {
    if (m_sock) m_sock->close();
}

// Build a 28-byte SEC header + body, with the keyed-MD5 checksum filled in.
QByteArray EadProtocol::buildPacket(quint16 opcode, const QByteArray& body) {
    QByteArray pkt(HEADER_LEN, '\0');
    auto* p = reinterpret_cast<uchar*>(pkt.data());

    // ulPktHeadId — fixed magic, on the wire as bytes 00 0A D8 77.
    p[0] = 0x00; p[1] = 0x0A; p[2] = 0xD8; p[3] = 0x77;
    // usPktHeadLen (big-endian) = total packet length.
    qToBigEndian<quint16>(static_cast<quint16>(HEADER_LEN + body.size()), p + 4);
    // checkSum[16] @+6 left zeroed; computed below.
    // pktId @+22 (big-endian) — per-packet correlator.
    qToBigEndian<quint32>(++m_pktId, p + 22);
    // opcode @+26 (big-endian).
    qToBigEndian<quint16>(opcode, p + 26);

    pkt.append(body);

    // checkSum = MD5(packet-with-cksum-zeroed || seed); write back at +6.
    QByteArray forHash = pkt;
    forHash.append(SEC_SEED, int(sizeof(SEC_SEED) - 1));
    const QByteArray digest = md5(forHash);
    std::memcpy(pkt.data() + 6, digest.constData(), 16);
    return pkt;
}

// A "compliant" posture report: every *checkResult field is empty (the binary
// only appends a fault token on failure, so empty == pass), accompanied by the
// identity fields the server keys the session on.
QByteArray EadProtocol::buildPostureXml() const {
    QString items;
    const auto add = [&items](const char* name, const QString& value) {
        items += QStringLiteral("<i n=\"%1\">%2</i>")
                     .arg(QLatin1String(name), value.toHtmlEscaped());
    };

    // Identity / asset fields (SendSecTrapPkt order).
    add("userName",       m_user);
    add("hwAddr",         QString::fromLatin1(m_mac));
    add("ipAddr",         QString::fromLatin1(m_ip));
    add("hostname",       QHostInfo::localHostName());
    add("osType",         QStringLiteral("Linux"));
    add("OSInfo",         QSysInfo::prettyProductName());
    add("OSKernelVersion", QSysInfo::kernelVersion());
    add("arch",           QSysInfo::currentCpuArchitecture());
    add("clientVersion",  QStringLiteral("iNodeClient-Qt"));

    // Result fields — empty value = pass for every check.
    for (const char* f : {"checkResult", "AScheckResult", "APcheckResult",
                          "FWcheckResult", "HDcheckResult", "PMcheckResult",
                          "passwordCheckResult", "antiServiceCheckResult"}) {
        add(f, QString());
    }
    // Screensaver is a state report, not a pass/fail token: enabled|lock|timeout.
    add("screenSaverResult", QStringLiteral("true|true|600"));

    const QString xml =
        QStringLiteral("<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
                       "<msg><ver></ver><content><data>%1</data></content></msg>")
            .arg(items);
    return xml.toUtf8();
}

void EadProtocol::transmit(const QByteArray& pkt) {
    m_lastPkt = pkt;
    const auto addr = QHostInfo::fromName(m_host).addresses().value(0, QHostAddress(m_host));
    m_sock->writeDatagram(pkt, addr, m_port);
    if (m_retry) m_retry->start();
}

void EadProtocol::connectWith(const Profile& profile) {
    m_host = profile.eadServer.isEmpty() ? profile.serverHost : profile.eadServer;
    if (m_host.isEmpty()) {
        emit errorOccurred(tr("EAD requires a posture server (eadServer or serverHost)."));
        setState(ConnectionState::Failed);
        return;
    }
    if (profile.username.isEmpty()) {
        emit errorOccurred(tr("Username is required for EAD posture reporting."));
        setState(ConnectionState::Failed);
        return;
    }
    m_port  = profile.eadPort ? profile.eadPort : 9019;
    m_user  = profile.username;
    m_iface = profile.iface;
    m_pktId = 0;
    m_retries = 0;

    // Identity values.
    const QString ip = netutil::primaryIpv4(m_iface);
    m_ip = (ip.isEmpty() ? QStringLiteral("0.0.0.0") : ip).toLatin1();
    m_mac.clear();
    for (const auto& i : QNetworkInterface::allInterfaces()) {
        if (!m_iface.isEmpty() && i.name() != m_iface) continue;
        if (i.flags().testFlag(QNetworkInterface::IsLoopBack)) continue;
        if (!i.hardwareAddress().isEmpty()) { m_mac = i.hardwareAddress().toLatin1(); break; }
    }

    m_sock = new QUdpSocket(this);
    if (!m_sock->bind(QHostAddress::AnyIPv4, 0)) {
        emit errorOccurred(tr("EAD: failed to bind UDP socket: %1").arg(m_sock->errorString()));
        setState(ConnectionState::Failed);
        return;
    }
    connect(m_sock, &QUdpSocket::readyRead, this, &EadProtocol::onDatagram);

    m_retry = new QTimer(this);
    m_retry->setSingleShot(true);
    m_retry->setInterval(3000);
    connect(m_retry, &QTimer::timeout, this, &EadProtocol::onRetry);

    setState(ConnectionState::Connecting);
    sendStart();
}

void EadProtocol::sendStart() {
    m_step = Step::Start;
    // SEC_START carries the posture report so a server that skips CHECK_LIST can
    // adjudicate immediately; a server that wants it again replies CHECK_LIST.
    Logger::instance().info(tr("EAD: SEC_START → %1:%2 (user '%3')")
                                .arg(m_host).arg(m_port).arg(m_user));
    transmit(buildPacket(SEC_START, buildPostureXml()));
    setState(ConnectionState::Authenticating);
}

void EadProtocol::sendCheckResult(quint16 opcode) {
    m_step = Step::AwaitVerdict;
    Logger::instance().info(tr("EAD: SEC_CHECK_RESULT (compliant posture)"));
    transmit(buildPacket(opcode, buildPostureXml()));
}

void EadProtocol::sendHeartbeat() {
    transmit(buildPacket(SEC_HEARTBEAT, QByteArray()));
}

void EadProtocol::sendOffline() {
    if (!m_sock) return;
    // Fire-and-forget; we tear down regardless of the response.
    const auto addr = QHostInfo::fromName(m_host).addresses().value(0, QHostAddress(m_host));
    m_sock->writeDatagram(buildPacket(SEC_OFFLINE, QByteArray()), addr, m_port);
    Logger::instance().info(QStringLiteral("EAD: SEC_OFFLINE sent"));
}

void EadProtocol::onRetry() {
    if (m_step == Step::Online) return;
    if (++m_retries > 3) {
        emit errorOccurred(tr("EAD: no response from posture server after %1 attempts.")
                               .arg(m_retries - 1));
        setState(ConnectionState::Failed);
        if (m_sock) m_sock->close();
        return;
    }
    Logger::instance().warn(tr("EAD: retransmit (attempt %1)").arg(m_retries));
    if (!m_lastPkt.isEmpty()) transmit(m_lastPkt);
}

void EadProtocol::onDatagram() {
    while (m_sock && m_sock->hasPendingDatagrams()) {
        const QByteArray data = m_sock->receiveDatagram().data();
        if (data.size() < HEADER_LEN) {
            Logger::instance().warn(QStringLiteral("EAD: short packet"));
            continue;
        }
        const auto* p = reinterpret_cast<const uchar*>(data.constData());
        // Accept the magic id family 0x000AD877..0x000AD879.
        const quint32 id = qFromBigEndian<quint32>(p);
        if (id < 0x000AD877u || id > 0x000AD879u) {
            Logger::instance().warn(QStringLiteral("EAD: bad packet head id"));
            continue;
        }
        const quint16 opcode = qFromBigEndian<quint16>(p + 26);
        if (m_retry) m_retry->stop();
        m_retries = 0;

        switch (opcode) {
        case SEC_CHECK_LIST:
            Logger::instance().info(tr("EAD: server sent SEC_CHECK_LIST → replying SEC_CHECK_RESULT"));
            sendCheckResult(SEC_CHECK_RESULT);
            break;
        case SEC_CHCK_SUCCESS: {
            Logger::instance().info(tr("EAD: posture accepted (SEC_CHCK_SUCCESS)"));
            m_step = Step::Online;
            ConnectionStats s;
            s.localIp     = QString::fromLatin1(m_ip);
            s.connectedAt = QDateTime::currentDateTime();
            setStats(s);
            setState(ConnectionState::Connected);
            if (!m_heartbeat) {
                m_heartbeat = new QTimer(this);
                m_heartbeat->setInterval(60 * 1000);  // server-driven; 60s default
                connect(m_heartbeat, &QTimer::timeout, this, &EadProtocol::onHeartbeat);
            }
            m_heartbeat->start();
            break;
        }
        case SEC_CHECK_FAIL:
            emit errorOccurred(tr("EAD: posture rejected by server (SEC_CHECK_FAIL)."));
            setState(ConnectionState::Failed);
            if (m_sock) m_sock->close();
            break;
        case SEC_HEARTBEAT_RESP:
            // keep-alive acknowledged; nothing to do.
            break;
        case SEC_ACL_REQUEST:
            Logger::instance().info(QStringLiteral("EAD: server SEC_ACL_REQUEST (informational)"));
            break;
        default:
            Logger::instance().info(tr("EAD: unhandled SEC opcode %1").arg(opcode));
            break;
        }
    }
}

void EadProtocol::onHeartbeat() {
    sendHeartbeat();
}

void EadProtocol::disconnect() {
    if (!m_sock) return;
    setState(ConnectionState::Disconnecting);
    if (m_heartbeat) m_heartbeat->stop();
    if (m_retry) m_retry->stop();
    sendOffline();
    QTimer::singleShot(800, this, [this] {
        if (m_sock) { m_sock->close(); m_sock->deleteLater(); m_sock = nullptr; }
        setState(ConnectionState::Disconnected);
    });
}

} // namespace inode
