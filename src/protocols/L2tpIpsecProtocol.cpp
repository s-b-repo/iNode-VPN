#include "L2tpIpsecProtocol.h"

#include "core/CredentialStore.h"
#include "core/Logger.h"
#include "core/NetUtil.h"

#include <QCoreApplication>
#include <QDateTime>
#include <QDir>
#include <QFileInfo>
#include <QProcess>
#include <QStandardPaths>
#include <QTimer>

#include <unistd.h>

namespace inode {

L2tpIpsecProtocol::L2tpIpsecProtocol(QObject* parent) : IProtocol(parent) {
    m_statsTimer = new QTimer(this);
    m_statsTimer->setInterval(2000);
    connect(m_statsTimer, &QTimer::timeout, this, &L2tpIpsecProtocol::pollStats);
}

L2tpIpsecProtocol::~L2tpIpsecProtocol() {
    if (!m_connName.isEmpty()) disconnect();
}

static QString helperPath() {
    QString local = QCoreApplication::applicationDirPath() + QStringLiteral("/../scripts/inode-l2tp-helper");
    if (QFileInfo::exists(local)) return QFileInfo(local).absoluteFilePath();
    QString libexec = QStringLiteral("/usr/libexec/iNodeClient-Qt/inode-l2tp-helper");
    if (QFileInfo::exists(libexec)) return libexec;
    return QStringLiteral("inode-l2tp-helper");
}

bool L2tpIpsecProtocol::runHelper(const QStringList& args, const QByteArray& stdinData) {
    const QString helper = helperPath();

    // Pick the privilege launcher the same way the SSL VPN path does: run the
    // helper directly when already root, else pkexec, else non-interactive sudo
    // (`-n` so a missing TTY fails fast instead of hanging the GUI forever).
    QString launcher;
    QStringList full;
    if (geteuid() == 0) {
        launcher = helper;
        full = args;
    } else if (const QString pkexec = QStandardPaths::findExecutable(QStringLiteral("pkexec"));
               !pkexec.isEmpty()) {
        launcher = pkexec;
        full = QStringList{} << helper << args;
    } else if (const QString sudo = QStandardPaths::findExecutable(QStringLiteral("sudo"));
               !sudo.isEmpty()) {
        launcher = sudo;
        full = QStringList{} << QStringLiteral("-n") << helper << args;
    } else {
        emit errorOccurred(tr("Need root for L2TP/IPSec, but neither pkexec nor "
                              "sudo is available. Install polkit or run as root."));
        return false;
    }

    QProcess proc;
    proc.setProcessChannelMode(QProcess::MergedChannels);
    proc.start(launcher, full);
    if (!proc.waitForStarted(5000)) {
        emit errorOccurred(tr("Could not start helper (%1)").arg(launcher));
        return false;
    }
    // Stream secrets (PSK, then password) on stdin so they never reach argv/ps.
    if (!stdinData.isEmpty()) proc.write(stdinData);
    proc.closeWriteChannel();
    // Bounded wait: `ipsec up` can take a while, but must never block forever.
    if (!proc.waitForFinished(120000)) {
        proc.kill();
        proc.waitForFinished(2000);
        emit errorOccurred(tr("L2TP/IPSec helper timed out."));
        return false;
    }
    const QByteArray out = proc.readAll();
    for (const auto& line : out.split('\n')) {
        if (!line.trimmed().isEmpty()) emit logLine(QString::fromUtf8(line));
    }
    return proc.exitCode() == 0;
}

void L2tpIpsecProtocol::connectWith(const Profile& profile) {
    if (profile.serverHost.isEmpty() || profile.psk.isEmpty()) {
        emit errorOccurred(tr("L2TP/IPSec requires a server host and PSK."));
        setState(ConnectionState::Failed);
        return;
    }

    QString password;
    CredentialStore::instance().retrieve(profile.id, &password);
    if (password.isEmpty()) {
        emit errorOccurred(tr("No stored password for profile."));
        setState(ConnectionState::Failed);
        return;
    }

    m_profileId = profile.id;
    m_connName  = QStringLiteral("inode-%1").arg(profile.id.toString(QUuid::WithoutBraces).left(8));

    setState(ConnectionState::Connecting);

    QStringList args;
    args << QStringLiteral("up")
         << QStringLiteral("--name")     << m_connName
         << QStringLiteral("--server")   << profile.serverHost
         << QStringLiteral("--username") << profile.username
         << QStringLiteral("--secrets-stdin");
    if (profile.l2tpForceUdpEncap)
        args << QStringLiteral("--force-udp-encap");

    // PSK and password go on the helper's stdin (one per line), never argv.
    QByteArray secrets = profile.psk.toUtf8() + '\n' + password.toUtf8() + '\n';

    setState(ConnectionState::Authenticating);
    const bool ok = runHelper(args, secrets);
    secrets.fill('\0');   // scrub the plaintext copy
    if (!ok) {
        setState(ConnectionState::Failed);
        return;
    }

    // Tunnel up — stats come from ppp0 (xl2tpd's default) until the user
    // overrides it. If no ppp0 exists yet we'll leave stats blank and retry.
    ConnectionStats s;
    s.iface = QStringLiteral("ppp0");
    s.connectedAt = QDateTime::currentDateTime();
    netutil::refreshStats(s);
    setStats(s);
    m_statsTimer->start();

    setState(ConnectionState::Connected);
}

void L2tpIpsecProtocol::pollStats() {
    ConnectionStats s = stats();
    if (s.iface.isEmpty()) s.iface = QStringLiteral("ppp0");
    netutil::refreshStats(s);
    setStats(s);
}

void L2tpIpsecProtocol::disconnect() {
    if (m_connName.isEmpty()) return;
    setState(ConnectionState::Disconnecting);
    m_statsTimer->stop();
    runHelper({QStringLiteral("down"), QStringLiteral("--name"), m_connName});
    m_connName.clear();
    setState(ConnectionState::Disconnected);
}

} // namespace inode
