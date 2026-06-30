#include "PortalProtocol.h"

#include "core/CredentialStore.h"
#include "core/Logger.h"
#include "core/NetUtil.h"

#include <QCryptographicHash>
#include <QDateTime>
#include <QHostAddress>
#include <QHostInfo>
#include <QNetworkDatagram>
#include <QNetworkInterface>
#include <QTimer>
#include <QUdpSocket>
#include <QtEndian>

#include <cstring>

// Portal v2 packet layout:
//
//   offset 0  : Version   (1 byte, 0x02)
//   offset 1  : Type      (1 byte: 0x01 REQ_CHALLENGE .. 0x07 AFF_ACK_LOGOUT)
//   offset 2  : AuthType  (1 byte: 0x00 CHAP, 0x01 PAP)
//   offset 3  : Reserved  (1 byte)
//   offset 4  : SerialNo  (2 bytes, big-endian)
//   offset 6  : ReqId     (2 bytes, big-endian)
//   offset 8  : UserIp    (4 bytes)
//   offset 12 : UserPort  (2 bytes, 0)
//   offset 14 : ErrCode   (1 byte)
//   offset 15 : AttrNum   (1 byte)
//   offset 16 : Auth      (16 bytes; MD5 checksum, zeroed while computing)
//   offset 32 : Attributes…

namespace inode {

static constexpr quint8 VERSION   = 0x02;
static constexpr quint8 TYPE_REQ_CHALLENGE = 0x01;
static constexpr quint8 TYPE_ACK_CHALLENGE = 0x02;
static constexpr quint8 TYPE_REQ_AUTH      = 0x03;
static constexpr quint8 TYPE_ACK_AUTH      = 0x04;
static constexpr quint8 TYPE_REQ_LOGOUT    = 0x05;
static constexpr quint8 TYPE_ACK_LOGOUT    = 0x06;
static constexpr quint8 TYPE_AFF_ACK_AUTH  = 0x07;

static constexpr quint8 ATTR_USERNAME      = 0x01;
static constexpr quint8 ATTR_PASSWORD      = 0x02;
static constexpr quint8 ATTR_CHALLENGE     = 0x03;
static constexpr quint8 ATTR_CHAPPASSWORD  = 0x04;
static constexpr quint8 ATTR_TEXTINFO      = 0x05;
static constexpr quint8 ATTR_IPCONFIG      = 0x06;
static constexpr quint8 ATTR_BASEIP        = 0x07;

// ---- H3C proprietary dialect (libInodePortalPt.so) ----
// Private opcode space (header byte at offset 1), not the standard 0x01–0x07.
static constexpr quint8 H3C_LOGIN_REQUEST  = 0x64;
static constexpr quint8 H3C_LOGIN_RESPONSE = 0x65;
static constexpr quint8 H3C_LOGOUT_REQUEST = 0x66;
static constexpr quint8 H3C_HANDSHAKE      = 0x68;   // heartbeat
static constexpr quint8 H3C_HASH_RESPONSE  = 0x7A;   // client→server (anti-track)
// H3C attribute type codes (TLV: Type, Len=value+2, Value).
static constexpr quint8 H3C_ATTR_BAS_IP    = 0x0A;   // NB: 0x0A is BAS_IP, *not* user-mac
static constexpr quint8 H3C_ATTR_RELAY     = 0x21;   // base64 product-version / ip-config blob
static constexpr quint8 H3C_ATTR_ENCRYPT   = 0x38;   // EX_ATTR_ENCRYPT_ENABLE / MsgAuth
static constexpr quint8 H3C_ATTR_USER_NAME = 0x65;
static constexpr quint8 H3C_ATTR_PASSWORD  = 0x66;
static constexpr quint8 H3C_ATTR_PRIVATE_IP = 0x67;  // 16-byte IP blob
static constexpr quint8 H3C_ATTR_PUBLIC_IP  = 0x68;  // 16-byte IP blob
static constexpr quint8 H3C_ATTR_START_TIME = 0x71;  // 4-byte BE timestamp
static constexpr quint8 H3C_ATTR_HASH_KEY   = 0x82;  // server→client challenge key
static constexpr quint8 H3C_ATTR_HASH_VALUE = 0x83;  // client→server 32-byte response

static QByteArray md5(const QByteArray& in) {
    return QCryptographicHash::hash(in, QCryptographicHash::Md5);
}

static void appendAttr(QByteArray& out, quint8 type, const QByteArray& value) {
    out.append(static_cast<char>(type));
    out.append(static_cast<char>(2 + value.size())); // length includes header
    out.append(value);
}

static QByteArray buildHeader(quint8 type, quint8 authType, quint16 serial, quint16 req,
                              const QByteArray& userIp) {
    QByteArray h(32, '\0');
    h[0] = static_cast<char>(VERSION);
    h[1] = static_cast<char>(type);
    h[2] = static_cast<char>(authType);
    // h[3] reserved
    qToBigEndian<quint16>(serial, reinterpret_cast<uchar*>(h.data()) + 4);
    qToBigEndian<quint16>(req,    reinterpret_cast<uchar*>(h.data()) + 6);
    std::memcpy(h.data() + 8, userIp.constData(), 4);
    // h[12..13] userPort = 0
    // h[14]     errCode
    // h[15]     attrNum (filled later)
    // h[16..31] checksum (zeroed; MD5 computed later over whole packet + secret)
    return h;
}

// The 6-byte hardware address of an interface, for the H3C user-mac TLV.
static QByteArray macFromIface(const QString& iface) {
    QByteArray out;
    const auto all = QNetworkInterface::allInterfaces();
    for (const auto& i : all) {
        if (!iface.isEmpty() && i.name() != iface) continue;
        const QStringList parts = i.hardwareAddress().split(QLatin1Char(':'),
                                                            Qt::SkipEmptyParts);
        if (parts.size() != 6) continue;
        for (const QString& b : parts) out.append(char(b.toUInt(nullptr, 16)));
        break;
    }
    return out;
}

static QByteArray userIpFromLocal(const QString& iface) {
    const QString ip = iface.isEmpty() ? QString() : netutil::primaryIpv4(iface);
    const QHostAddress a(ip.isEmpty() ? QStringLiteral("0.0.0.0") : ip);
    const quint32 raw = a.toIPv4Address();
    QByteArray b(4, '\0');
    qToBigEndian<quint32>(raw, reinterpret_cast<uchar*>(b.data()));
    return b;
}

PortalProtocol::PortalProtocol(QObject* parent) : IProtocol(parent) {}

QHostAddress PortalProtocol::resolveHost() const {
    const auto addrs = QHostInfo::fromName(m_host).addresses();
    if (!addrs.isEmpty()) return addrs.first();
    QHostAddress fallback(m_host);
    if (!fallback.isNull()) return fallback;
    Logger::instance().warn(
        QStringLiteral("Portal: DNS resolution failed for %1").arg(m_host));
    return {};
}

PortalProtocol::~PortalProtocol() {
    if (m_sock) { m_sock->close(); }
}

void PortalProtocol::connectWith(const Profile& profile) {
    if (profile.serverHost.isEmpty()) {
        emit errorOccurred(tr("Portal requires a server host."));
        setState(ConnectionState::Failed);
        return;
    }
    if (profile.username.isEmpty()) {
        emit errorOccurred(tr("Username is required."));
        setState(ConnectionState::Failed);
        return;
    }
    m_dialect = profile.portalDialect;
    if (m_dialect == 1) {
        m_userMac = macFromIface(profile.iface);
        Logger::instance().info(tr(
            "Portal: H3C proprietary dialect (experimental, untested) — single-shot "
            "LOGIN_REQUEST (0x64) with H3C attributes. The anti-track hash challenge "
            "is acknowledged best-effort only."));
    }

    m_host   = profile.serverHost;
    m_port   = profile.serverPort ? profile.serverPort : 2000;
    m_secret = profile.portalSecret.isEmpty() ? QStringLiteral("h3c") : profile.portalSecret;
    m_user   = profile.username;

    QString pw;
    CredentialStore::instance().retrieve(profile.id, &pw);
    if (pw.isEmpty()) {
        emit errorOccurred(tr("No stored password for profile."));
        setState(ConnectionState::Failed);
        return;
    }
    m_pass = pw;
    m_userIp = userIpFromLocal(profile.iface);
    m_serialNo = static_cast<quint16>(QDateTime::currentSecsSinceEpoch() & 0xffffu);
    m_reqId = 0;
    m_retries = 0;

    m_sock = new QUdpSocket(this);
    if (!m_sock->bind(QHostAddress::AnyIPv4, 0)) {
        emit errorOccurred(tr("Portal: failed to bind UDP socket: %1").arg(m_sock->errorString()));
        setState(ConnectionState::Failed);
        return;
    }
    connect(m_sock, &QUdpSocket::readyRead, this, &PortalProtocol::onDatagram);

    setState(ConnectionState::Connecting);
    if (m_dialect == 1) sendH3cLogin();
    else                sendChallenge();
}

void PortalProtocol::sendChallenge() {
    m_step = Step::Challenge;
    QByteArray pkt = buildHeader(TYPE_REQ_CHALLENGE, 0x00, m_serialNo, m_reqId, m_userIp);
    pkt[15] = 0; // attrNum

    // Portal v2 uses a trailing checksum over (packet || secret) in slot 16..31.
    // For REQ_CHALLENGE the "Auth" field is typically zeroed; we still MD5 to
    // populate it as some iMC builds validate REQ_CHALLENGE too.
    QByteArray forHash = pkt + m_secret.toUtf8();
    std::memcpy(pkt.data() + 16, md5(forHash).constData(), 16);

    Logger::instance().info(tr("Portal: REQ_CHALLENGE → %1:%2").arg(m_host).arg(m_port));
    const auto addr = resolveHost();
    m_sock->writeDatagram(pkt, addr, m_port);
    setState(ConnectionState::Authenticating);
}

void PortalProtocol::sendAuth(const QByteArray& challenge) {
    m_step = Step::Auth;
    ++m_reqId;

    // Compute CHAP password = MD5(ReqId || password || challenge), 16 bytes.
    QByteArray forChap;
    forChap.append(static_cast<char>(m_reqId & 0xff));
    forChap.append(m_pass.toUtf8());
    forChap.append(challenge);
    const QByteArray chapPw = md5(forChap);

    QByteArray pkt = buildHeader(TYPE_REQ_AUTH, 0x00 /* CHAP */, m_serialNo, m_reqId, m_userIp);

    QByteArray attrs;
    const quint8 attrNum = 2;
    appendAttr(attrs, ATTR_USERNAME, m_user.toUtf8());
    appendAttr(attrs, ATTR_CHAPPASSWORD, chapPw);
    pkt[15] = static_cast<char>(attrNum); // attrNum

    QByteArray full = pkt + attrs;
    // checksum = MD5(packet-with-zero-auth || attrs || secret)
    QByteArray forHash = full + m_secret.toUtf8();
    std::memcpy(full.data() + 16, md5(forHash).constData(), 16);

    Logger::instance().info(tr("Portal: REQ_AUTH user='%1' reqId=%2").arg(m_user).arg(m_reqId));
    const auto addr = resolveHost();
    m_sock->writeDatagram(full, addr, m_port);
}

void PortalProtocol::sendAffirm() {
    QByteArray pkt = buildHeader(TYPE_AFF_ACK_AUTH, 0x00, m_serialNo, m_reqId, m_userIp);
    pkt[15] = 0;
    QByteArray forHash = pkt + m_secret.toUtf8();
    std::memcpy(pkt.data() + 16, md5(forHash).constData(), 16);
    const auto addr = resolveHost();
    m_sock->writeDatagram(pkt, addr, m_port);
    Logger::instance().info(QStringLiteral("Portal: AFF_ACK_AUTH sent"));
}

void PortalProtocol::sendLogout() {
    if (!m_sock) return;
    ++m_reqId;
    QByteArray pkt = buildHeader(TYPE_REQ_LOGOUT, 0x00, m_serialNo, m_reqId, m_userIp);
    pkt[15] = 0;
    QByteArray forHash = pkt + m_secret.toUtf8();
    std::memcpy(pkt.data() + 16, md5(forHash).constData(), 16);
    const auto addr = resolveHost();
    m_sock->writeDatagram(pkt, addr, m_port);
    Logger::instance().info(QStringLiteral("Portal: REQ_LOGOUT sent"));
}

void PortalProtocol::onDatagram() {
    while (m_sock && m_sock->hasPendingDatagrams()) {
        const auto dg = m_sock->receiveDatagram();
        const QByteArray data = dg.data();
        if (data.size() < 32) { Logger::instance().warn(QStringLiteral("Portal: short packet")); continue; }
        if (m_dialect == 1) { handleH3cPacket(data); continue; }
        const quint8 type = static_cast<quint8>(data.at(1));
        const quint8 err  = static_cast<quint8>(data.at(14));

        if (type == TYPE_ACK_CHALLENGE) {
            if (err != 0) {
                emit errorOccurred(tr("Portal: challenge rejected (code %1)").arg(err));
                setState(ConnectionState::Failed);
                return;
            }
            // Extract challenge attribute.
            int off = 32;
            QByteArray challenge;
            while (off + 2 <= data.size()) {
                const quint8 t = static_cast<quint8>(data.at(off));
                const quint8 l = static_cast<quint8>(data.at(off + 1));
                if (l < 2 || off + l > data.size()) break;
                if (t == ATTR_CHALLENGE) challenge = data.mid(off + 2, l - 2);
                off += l;
            }
            if (challenge.isEmpty()) {
                emit errorOccurred(tr("Portal: ACK_CHALLENGE contained no challenge attribute"));
                setState(ConnectionState::Failed);
                return;
            }
            sendAuth(challenge);
        } else if (type == TYPE_ACK_AUTH) {
            if (err != 0) {
                emit errorOccurred(tr("Portal: auth rejected (code %1)").arg(err));
                setState(ConnectionState::Failed);
                return;
            }
            sendAffirm();

            ConnectionStats s;
            s.iface       = QString();
            s.localIp     = QHostAddress(qFromBigEndian<quint32>(m_userIp.constData())).toString();
            s.connectedAt = QDateTime::currentDateTime();
            setStats(s);
            setState(ConnectionState::Connected);

            // Start a minute-ish keep-alive so iMC doesn't age the session out.
            if (!m_keepAlive) {
                m_keepAlive = new QTimer(this);
                m_keepAlive->setInterval(45 * 1000);
                connect(m_keepAlive, &QTimer::timeout, this, &PortalProtocol::onKeepAlive);
            }
            m_keepAlive->start();
            m_step = Step::KeepAlive;
        } else if (type == TYPE_ACK_LOGOUT) {
            Logger::instance().info(QStringLiteral("Portal: ACK_LOGOUT"));
            if (m_keepAlive) m_keepAlive->stop();
            setState(ConnectionState::Disconnected);
        }
    }
}

void PortalProtocol::onKeepAlive() {
    // Portal v2 doesn't mandate a dedicated keep-alive packet; re-sending the
    // affirm keeps NAT mappings open and lets us detect a dropped server.
    if (m_dialect == 1) sendH3cHeartbeat();
    else                sendAffirm();
}

// ---------------------------------------------------------------------------
// H3C proprietary dialect
// ---------------------------------------------------------------------------

// A 16-byte IP blob (IPv4 left-aligned, zero-padded) for PRIVATE_IP/PUBLIC_IP.
static QByteArray ipBlob16(const QByteArray& ip4) {
    QByteArray b(16, '\0');
    std::memcpy(b.data(), ip4.constData(), qMin(4, ip4.size()));
    return b;
}

void PortalProtocol::sendH3cLogin() {
    m_step = Step::Auth;
    QByteArray pkt = buildHeader(H3C_LOGIN_REQUEST, 0x01 /* PAP */, m_serialNo, m_reqId, m_userIp);

    QByteArray attrs;
    quint8 attrNum = 0;
    const auto add = [&](quint8 t, const QByteArray& v) { appendAttr(attrs, t, v); ++attrNum; };

    // Observed login attribute order: 0x21 → 0x67 → 0x68 → 0x65 → 0x66 → 0x71.
    // The 0x21 relay blob is a base64 product-version/ip-config struct; we send
    // a minimal client-version marker (full struct layout is UNCONFIRMED).
    add(H3C_ATTR_RELAY,      QByteArrayLiteral("iNodeClient-Qt").toBase64());
    add(H3C_ATTR_PRIVATE_IP, ipBlob16(m_userIp));
    add(H3C_ATTR_PUBLIC_IP,  ipBlob16(m_userIp));
    add(H3C_ATTR_USER_NAME,  m_user.toUtf8());
    add(H3C_ATTR_PASSWORD,   m_pass.toUtf8());          // PAP: plaintext (inside trusted net)
    add(H3C_ATTR_BAS_IP,     m_userIp);                 // best-effort: our own IP as BAS hint
    QByteArray ts(4, '\0');
    qToBigEndian<quint32>(static_cast<quint32>(QDateTime::currentSecsSinceEpoch()),
                          reinterpret_cast<uchar*>(ts.data()));
    add(H3C_ATTR_START_TIME, ts);

    pkt[15] = static_cast<char>(attrNum);
    QByteArray full = pkt + attrs;
    QByteArray forHash = full + m_secret.toUtf8();
    std::memcpy(full.data() + 16, md5(forHash).constData(), 16);

    Logger::instance().info(tr("Portal(H3C): LOGIN_REQUEST user='%1' (%2 attrs)")
                                .arg(m_user).arg(attrNum));
    const auto addr = resolveHost();
    m_sock->writeDatagram(full, addr, m_port);
    setState(ConnectionState::Authenticating);
}

void PortalProtocol::sendH3cHeartbeat() {
    QByteArray pkt = buildHeader(H3C_HANDSHAKE, 0x01, m_serialNo, m_reqId, m_userIp);
    QByteArray attrs;
    appendAttr(attrs, H3C_ATTR_BAS_IP, m_userIp);
    pkt[15] = 1;
    QByteArray full = pkt + attrs;
    QByteArray forHash = full + m_secret.toUtf8();
    std::memcpy(full.data() + 16, md5(forHash).constData(), 16);
    const auto addr = resolveHost();
    m_sock->writeDatagram(full, addr, m_port);
}

void PortalProtocol::sendH3cLogout() {
    if (!m_sock) return;
    QByteArray pkt = buildHeader(H3C_LOGOUT_REQUEST, 0x01, m_serialNo, m_reqId, m_userIp);
    QByteArray attrs;
    appendAttr(attrs, H3C_ATTR_USER_NAME, m_user.toUtf8());
    appendAttr(attrs, H3C_ATTR_BAS_IP, m_userIp);
    pkt[15] = 2;
    QByteArray full = pkt + attrs;
    QByteArray forHash = full + m_secret.toUtf8();
    std::memcpy(full.data() + 16, md5(forHash).constData(), 16);
    const auto addr = resolveHost();
    m_sock->writeDatagram(full, addr, m_port);
    Logger::instance().info(QStringLiteral("Portal(H3C): LOGOUT_REQUEST sent"));
}

// Best-effort answer to the H3C anti-track hash challenge: echo MD5(hashKey ||
// secret) as the 32-byte response. The real digest is a function-code-dispatched
// MD5 we did not fully recover, so this is unlikely to satisfy a strict BAS.
void PortalProtocol::replyH3cHashChallenge(const QByteArray& data) {
    QByteArray hashKey;
    int off = 32;
    while (off + 2 <= data.size()) {
        const quint8 t = static_cast<quint8>(data.at(off));
        const quint8 l = static_cast<quint8>(data.at(off + 1));
        if (l < 2 || off + l > data.size()) break;
        if (t == H3C_ATTR_HASH_KEY) hashKey = data.mid(off + 2, l - 2);
        off += l;
    }
    QByteArray resp = md5(hashKey + m_secret.toUtf8());
    resp.append(md5(resp + m_secret.toUtf8()));  // pad to 32 bytes
    resp.truncate(32);

    QByteArray pkt = buildHeader(H3C_HASH_RESPONSE, 0x01, m_serialNo, m_reqId, m_userIp);
    QByteArray attrs;
    appendAttr(attrs, H3C_ATTR_HASH_VALUE, resp);
    pkt[15] = 1;
    QByteArray full = pkt + attrs;
    QByteArray forHash = full + m_secret.toUtf8();
    std::memcpy(full.data() + 16, md5(forHash).constData(), 16);
    const auto addr = resolveHost();
    m_sock->writeDatagram(full, addr, m_port);
    Logger::instance().warn(QStringLiteral(
        "Portal(H3C): answered anti-track hash challenge (best-effort; "
        "exact digest not recovered)."));
}

void PortalProtocol::handleH3cPacket(const QByteArray& data) {
    const quint8 type = static_cast<quint8>(data.at(1));
    const quint8 err  = static_cast<quint8>(data.at(14));

    if (type == H3C_HASH_RESPONSE - 1 || type == H3C_HASH_RESPONSE) {
        // Some builds use 0x79 for HASH_REQUEST; the 0x82 attr is the tell.
        replyH3cHashChallenge(data);
        return;
    }
    if (type == H3C_LOGIN_RESPONSE) {
        if (err != 0) {
            emit errorOccurred(tr("Portal(H3C): login rejected (code %1)").arg(err));
            setState(ConnectionState::Failed);
            return;
        }
        ConnectionStats s;
        s.localIp     = QHostAddress(qFromBigEndian<quint32>(m_userIp.constData())).toString();
        s.connectedAt = QDateTime::currentDateTime();
        setStats(s);
        setState(ConnectionState::Connected);
        if (!m_keepAlive) {
            m_keepAlive = new QTimer(this);
            m_keepAlive->setInterval(45 * 1000);
            connect(m_keepAlive, &QTimer::timeout, this, &PortalProtocol::onKeepAlive);
        }
        m_keepAlive->start();
        m_step = Step::KeepAlive;
        Logger::instance().info(QStringLiteral("Portal(H3C): login accepted"));
        return;
    }
    Logger::instance().info(tr("Portal(H3C): opcode 0x%1 (err %2)")
                                .arg(type, 0, 16).arg(err));
}

void PortalProtocol::disconnect() {
    if (!m_sock) return;
    setState(ConnectionState::Disconnecting);
    if (m_keepAlive) m_keepAlive->stop();
    if (m_dialect == 1) sendH3cLogout();
    else                sendLogout();
    // Give the server a moment to reply; then tear down regardless.
    QTimer::singleShot(1500, this, [this] {
        if (m_sock) { m_sock->close(); m_sock->deleteLater(); m_sock = nullptr; }
        setState(ConnectionState::Disconnected);
    });
}

} // namespace inode
