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

#include <functional>
#include <unistd.h>

namespace inode {

L2tpIpsecProtocol::L2tpIpsecProtocol(QObject* parent) : IProtocol(parent) {
    m_statsTimer = new QTimer(this);
    m_statsTimer->setInterval(2000);
    connect(m_statsTimer, &QTimer::timeout, this, &L2tpIpsecProtocol::pollStats);
}

L2tpIpsecProtocol::~L2tpIpsecProtocol() {
    if (!m_connName.isEmpty()) requestTeardownDetached();
    if (m_helper) {
        QObject::disconnect(m_helper, nullptr, this, nullptr);
        if (m_helper->state() != QProcess::NotRunning) m_helper->kill();
        m_helper->deleteLater();
        m_helper = nullptr;
    }
    if (m_helperTimeout) m_helperTimeout->stop();
}

static QString helperPath() {
    QString local = QCoreApplication::applicationDirPath() + QStringLiteral("/../scripts/inode-l2tp-helper");
    if (QFileInfo::exists(local)) return QFileInfo(local).absoluteFilePath();
    QString libexec = QStringLiteral("/usr/libexec/iNodeClient-Qt/inode-l2tp-helper");
    if (QFileInfo::exists(libexec)) return libexec;
    return QStringLiteral("inode-l2tp-helper");
}

static bool buildHelperInvocation(const QStringList& args,
                                  QString* launcher, QStringList* full) {
    const QString helper = helperPath();

    // Pick the privilege launcher the same way the SSL VPN path does: run the
    // helper directly when already root, else pkexec, else non-interactive sudo
    // (`-n` so a missing TTY fails fast instead of hanging the GUI forever).
    if (geteuid() == 0) {
        *launcher = helper;
        *full = args;
        return true;
    }
    if (const QString pkexec = QStandardPaths::findExecutable(QStringLiteral("pkexec"));
            !pkexec.isEmpty()) {
        *launcher = pkexec;
        *full = QStringList{} << helper << args;
        return true;
    }
    if (const QString sudo = QStandardPaths::findExecutable(QStringLiteral("sudo"));
            !sudo.isEmpty()) {
        *launcher = sudo;
        *full = QStringList{} << QStringLiteral("-n") << helper << args;
        return true;
    }
    return false;
}

void L2tpIpsecProtocol::runHelperAsync(const QStringList& args,
                                       const QByteArray& stdinData,
                                       std::function<void(bool)> onDone) {
    QString launcher;
    QStringList full;
    if (!buildHelperInvocation(args, &launcher, &full)) {
        emit errorOccurred(tr("Need root for L2TP/IPSec, but neither pkexec nor "
                              "sudo is available. Install polkit or run as root."));
        if (onDone) onDone(false);
        return;
    }

    if (m_helper) {   // re-entry safety: a helper is still running
        QObject::disconnect(m_helper, nullptr, this, nullptr);
        if (m_helper->state() != QProcess::NotRunning) m_helper->kill();
        m_helper->deleteLater();
        m_helper = nullptr;
    }
    if (m_helperTimeout) m_helperTimeout->stop();

    auto* proc = new QProcess(this);
    m_helper = proc;
    proc->setProcessChannelMode(QProcess::MergedChannels);
    connect(proc, &QProcess::readyRead, this, [this, proc] {
        while (proc->canReadLine()) {
            const QString line = QString::fromUtf8(proc->readLine()).trimmed();
            if (!line.isEmpty()) emit logLine(line);
        }
    });
    connect(proc, &QProcess::errorOccurred, this, [this](QProcess::ProcessError e) {
        if (e == QProcess::FailedToStart)
            emit errorOccurred(tr("Could not start the L2TP/IPSec helper."));
    });

    // Bounded runtime: `ipsec up` can take a while but must never run forever.
    if (!m_helperTimeout) {
        m_helperTimeout = new QTimer(this);
        m_helperTimeout->setSingleShot(true);
    }
    // Drop the previous run's timeout lambda — it captures a dead QProcess.
    QObject::disconnect(m_helperTimeout, nullptr, this, nullptr);
    const bool isUp = args.size() > 0 && args.first() == QStringLiteral("up");
    connect(m_helperTimeout, &QTimer::timeout, this, [this, proc] {
        if (proc->state() != QProcess::NotRunning) {
            proc->kill();
            emit errorOccurred(tr("L2TP/IPSec helper timed out."));
        }
    });
    m_helperTimeout->start(isUp ? 120000 : 30000);

    connect(proc, &QProcess::finished, this,
            [this, proc, cb = std::move(onDone)](int exitCode, QProcess::ExitStatus) {
        if (m_helperTimeout) m_helperTimeout->stop();
        if (m_helper == proc) m_helper = nullptr;
        proc->deleteLater();
        if (cb) cb(exitCode == 0);
    });

    proc->start(launcher, full);
    // Stream secrets (PSK, then password) on stdin so they never reach argv/ps.
    if (!stdinData.isEmpty()) proc->write(stdinData);
    proc->closeWriteChannel();
}

void L2tpIpsecProtocol::requestTeardownDetached() {
    QStringList args{QStringLiteral("down"), QStringLiteral("--name"), m_connName};
    QString launcher;
    QStringList full;
    if (!buildHelperInvocation(args, &launcher, &full)) return;
    QProcess::startDetached(launcher, full);
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
    runHelperAsync(args, secrets, [this](bool ok) {
        if (!ok) {
            emit errorOccurred(tr("L2TP/IPSec bring-up failed — see the ipsec/xl2tpd "
                                  "output above. Typical causes: wrong PSK or password, "
                                  "server unreachable on UDP 500/4500 (firewall/NAT), "
                                  "strongSwan or xl2tpd not installed, or a previous "
                                  "tunnel still up (try Disconnect, then Connect)."));
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
    });
    // The stdin copy was buffered into the QProcess by runHelperAsync.
    secrets.fill('\0');
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
    runHelperAsync({QStringLiteral("down"), QStringLiteral("--name"), m_connName},
                   {}, [this](bool) {
        m_connName.clear();
        setState(ConnectionState::Disconnected);
    });
}

} // namespace inode
