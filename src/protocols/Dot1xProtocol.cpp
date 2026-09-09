#include "Dot1xProtocol.h"

#include "core/CredentialStore.h"
#include "core/IpConfigurator.h"
#include "core/Logger.h"
#include "core/NetUtil.h"

#include <QCoreApplication>
#include <QDateTime>
#include <QFileInfo>
#include <QProcess>
#include <QStandardPaths>
#include <QTimer>

#include <unistd.h>

namespace inode {

namespace {
// The dot1x helper is the only path that understands --stdin-password (it
// re-injects the password as -p without exposing it in ps) and the only
// binary allow-listed by the polkit policy for this action. It lives in the
// dev tree next to the other helpers, or in /usr/libexec after install.
QString dot1xHelperPath() {
    const QString local = QCoreApplication::applicationDirPath()
                          + QStringLiteral("/../scripts/inode-dot1x-helper");
    if (QFileInfo::exists(local)) return QFileInfo(local).absoluteFilePath();
    const QString libexec = QStringLiteral("/usr/libexec/iNodeClient-Qt/inode-dot1x-helper");
    if (QFileInfo::exists(libexec)) return libexec;
    return QStringLiteral("inode-dot1x-helper");
}
} // namespace

Dot1xProtocol::Dot1xProtocol(QObject* parent) : IProtocol(parent) {
    m_statsTimer = new QTimer(this);
    m_statsTimer->setInterval(2000);
    connect(m_statsTimer, &QTimer::timeout, this, &Dot1xProtocol::pollStats);
}

Dot1xProtocol::~Dot1xProtocol() {
    if (m_proc && m_proc->state() != QProcess::NotRunning) {
        m_proc->terminate();
        m_proc->waitForFinished(2000);
    }
}

static QStringList minieapArgs(const Profile& profile) {    QStringList args;
    args << QStringLiteral("--nogui")
         << QStringLiteral("-u") << profile.username
         << QStringLiteral("-n") << profile.iface
         << QStringLiteral("--auth-round") << QStringLiteral("1")
         << QStringLiteral("--daemonize") << QStringLiteral("0");

    // Heartbeat / re-auth interval. 0 means "let the server decide".
    if (profile.heartbeatSec > 0)
        args << QStringLiteral("-r") << QString::number(profile.heartbeatSec);

    // Match the three-letter log-level convention minieap uses.
    args << QStringLiteral("--log-level") << QString::number(qBound(0, profile.logLevel, 5));

    if (profile.dot1xUseRjv3) {
        args << QStringLiteral("--module") << QStringLiteral("rjv3");
        if (profile.dot1xServiceType >= 0)
            args << QStringLiteral("--rj-service-type") << QString::number(profile.dot1xServiceType);
        if (!profile.dot1xCarrier.isEmpty())
            args << QStringLiteral("--rj-carrier") << profile.dot1xCarrier;
    }

    // Auth mode mapping — minieap falls back to auto if unset.
    switch (profile.authMode) {
        case AuthMode::Pap:       args << QStringLiteral("--auth-method") << QStringLiteral("pap"); break;
        case AuthMode::Chap:      args << QStringLiteral("--auth-method") << QStringLiteral("chap"); break;
        case AuthMode::MsChapV2:  args << QStringLiteral("--auth-method") << QStringLiteral("mschapv2"); break;
        case AuthMode::EapMd5:    args << QStringLiteral("--auth-method") << QStringLiteral("eap-md5"); break;
        case AuthMode::EapPeap:   args << QStringLiteral("--auth-method") << QStringLiteral("eap-peap"); break;
        case AuthMode::HcChapV2:  args << QStringLiteral("--auth-method") << QStringLiteral("hc-chapv2"); break;
        case AuthMode::Auto: default: break;
    }

    if (!profile.dot1xExtraArgs.isEmpty())
        args << profile.dot1xExtraArgs.split(QLatin1Char(' '), Qt::SkipEmptyParts);

    return args;
}

void Dot1xProtocol::connectWith(const Profile& profile) {
    if (profile.iface.isEmpty()) {
        emit errorOccurred(tr("No network interface selected for 802.1X profile."));
        setState(ConnectionState::Failed);
        return;
    }
    if (profile.username.isEmpty()) {
        emit errorOccurred(tr("Username is required."));
        setState(ConnectionState::Failed);
        return;
    }

    CredentialStore::instance().retrieve(profile.id, &m_password);
    if (m_password.isEmpty()) {
        emit errorOccurred(tr("No stored password for profile."));
        setState(ConnectionState::Failed);
        return;
    }
    m_iface = profile.iface;
    m_profile = profile;      // remember it so we can apply the IP mode post-auth

    QString bin = QStandardPaths::findExecutable(QStringLiteral("minieap"));
    QStringList args;
    if (!bin.isEmpty()) {
        args = minieapArgs(profile);
    } else {
        bin = QStandardPaths::findExecutable(QStringLiteral("mentohust"));
        if (bin.isEmpty()) {
            emit errorOccurred(
                tr("Neither minieap nor mentohust found in PATH.\n"
                   "Install one of these 802.1X clients: "
                   "https://github.com/updateing/minieap"));
            setState(ConnectionState::Failed);
            return;
        }
        args << QStringLiteral("-u") << profile.username
             << QStringLiteral("-n") << profile.iface
             << QStringLiteral("-w");
        if (profile.heartbeatSec > 0)
            args << QStringLiteral("-t") << QString::number(profile.heartbeatSec);
        if (!profile.dot1xExtraArgs.isEmpty())
            args << profile.dot1xExtraArgs.split(QLatin1Char(' '), Qt::SkipEmptyParts);
    }

    QString launcher;
    QStringList finalArgs;
    // Route through the helper: it strips the --stdin-password marker, reads
    // the password from stdin (never argv/ps) and execs the supplicant with
    // -p <pw>. Launching the supplicant directly here would fail twice over:
    // minieap/mentohust reject --stdin-password, and pkexec would not match
    // the policy's allow-listed exec path.
    const QString helper = dot1xHelperPath();
    if (geteuid() == 0) {
        launcher = helper;
        finalArgs << QStringLiteral("--stdin-password") << args;
    } else {
        const QString pkexec = QStandardPaths::findExecutable(QStringLiteral("pkexec"));
        if (pkexec.isEmpty()) {
            emit errorOccurred(tr(
                "pkexec is required to run the 802.1X supplicant with elevated "
                "privileges. Install polkit, or run the client as root."));
            setState(ConnectionState::Failed);
            return;
        }
        launcher = pkexec;
        finalArgs << helper << QStringLiteral("--stdin-password") << args;
    }

    // A missing helper would surface as a bare FailedToStart ("Process
    // error: 0") — explain the real problem instead. dot1xHelperPath()
    // returns a bare name only when neither the dev tree nor /usr/libexec
    // had it.
    if (!helper.startsWith(QLatin1Char('/'))) {
        emit errorOccurred(tr(
            "The 802.1X helper (inode-dot1x-helper) was not found. Install the "
            "package so it lands in /usr/libexec/iNodeClient-Qt/."));
        setState(ConnectionState::Failed);
        return;
    }

    Logger::instance().info(
        tr("802.1X: launching %1 on %2 as %3").arg(bin, profile.iface, profile.username));

    startProcess(launcher, finalArgs, m_password.toUtf8());
    m_password.clear();
}

void Dot1xProtocol::startProcess(const QString& binary, const QStringList& args,
                                  const QByteArray& stdinData) {
    if (m_proc) {
        // Re-entry safety: a still-running supplicant must be stopped before
        // its QProcess object is disposed of.
        if (m_proc->state() != QProcess::NotRunning) {
            m_proc->terminate();
            if (!m_proc->waitForFinished(2000)) m_proc->kill();
        }
        m_proc->deleteLater();
        m_proc = nullptr;
    }

    m_proc = new QProcess(this);
    m_proc->setProcessChannelMode(QProcess::MergedChannels);

    connect(m_proc, &QProcess::readyRead, this, &Dot1xProtocol::onReadyRead);
    connect(m_proc, &QProcess::finished, this, &Dot1xProtocol::onFinished);
    connect(m_proc, &QProcess::errorOccurred, this, [this](QProcess::ProcessError e) {
        emit errorOccurred(tr("Process error: %1").arg(int(e)));
        setState(ConnectionState::Failed);
    });

    setState(ConnectionState::Connecting);
    m_proc->start(binary, args);

    // Write password on stdin (never in argv) and close.
    if (!stdinData.isEmpty()) {
        m_proc->write(stdinData);
        m_proc->write("\n");
        m_proc->closeWriteChannel();
    }
}

void Dot1xProtocol::onReadyRead() {
    while (m_proc && m_proc->canReadLine()) {
        const QString line = QString::fromUtf8(m_proc->readLine()).trimmed();
        if (line.isEmpty()) continue;
        emit logLine(line);

        const auto lower = line.toLower();
        if (lower.contains(QStringLiteral("success")) ||
            lower.contains(QStringLiteral("authenticated")) ||
            lower.contains(QStringLiteral("eap-success"))) {
            if (state() != ConnectionState::Connected) {
                // 802.1X only authenticates the port — it brings no address of
                // its own. Apply the profile's IP mode (DHCP / static) now,
                // asynchronously: a pkexec prompt or slow dhclient must not
                // freeze the GUI thread inside this readyRead handler.
                IpConfigurator::applyAsync(m_profile, m_iface);
                ConnectionStats s;
                s.iface = m_iface;
                s.connectedAt = QDateTime::currentDateTime();
                netutil::refreshStats(s);
                setStats(s);
                m_statsTimer->start();
            }
            setState(ConnectionState::Connected);
            m_password.clear();
        } else if (lower.contains(QStringLiteral("failure")) ||
                   lower.contains(QStringLiteral("rejected")) ||
                   lower.contains(QStringLiteral("eap-failure"))) {
            emit errorOccurred(tr("802.1X authentication rejected by the switch: %1 "
                                  "(wrong username/password, wrong auth mode, or the "
                                  "port is not 802.1X-enabled)").arg(line.trimmed()));
            setState(ConnectionState::Failed);
            m_password.clear();
        } else if (lower.contains(QStringLiteral("challenge")) ||
                   lower.contains(QStringLiteral("request"))) {
            setState(ConnectionState::Authenticating);
        }
    }
}

void Dot1xProtocol::pollStats() {
    ConnectionStats s = stats();
    if (s.iface.isEmpty()) s.iface = m_iface;
    netutil::refreshStats(s);
    setStats(s);
}

void Dot1xProtocol::onFinished(int exitCode, int /*exitStatus*/) {
    emit logLine(tr("process exited with code %1").arg(exitCode));
    m_password.clear();
    m_statsTimer->stop();
    // The link is down — undo any static address we programmed for it
    // (asynchronously: same GUI-freeze reasoning as applyAsync above).
    IpConfigurator::clearAsync(m_profile, m_iface);
    if (state() == ConnectionState::Connected && exitCode == 0) {
        setState(ConnectionState::Disconnected);
    } else if (exitCode != 0 && state() != ConnectionState::Failed) {
        emit errorOccurred(tr("802.1X supplicant exited with code %1 before "
                              "authenticating — see its output above (interface "
                              "down? cable unplugged? wrong interface selected?)")
                               .arg(exitCode));
        setState(ConnectionState::Failed);
    } else {
        setState(ConnectionState::Disconnected);
    }
}

void Dot1xProtocol::disconnect() {
    if (!m_proc) return;
    setState(ConnectionState::Disconnecting);
    m_proc->terminate();
    if (!m_proc->waitForFinished(3000)) m_proc->kill();
}

} // namespace inode
