#include "SslVpnProtocol.h"

#include "core/CredentialStore.h"
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

SslVpnProtocol::SslVpnProtocol(QObject* parent) : IProtocol(parent) {
    m_statsTimer = new QTimer(this);
    m_statsTimer->setInterval(2000);
    connect(m_statsTimer, &QTimer::timeout, this, &SslVpnProtocol::pollStats);
}

SslVpnProtocol::~SslVpnProtocol() {
    if (m_proc) {
        // Don't let a queued finished()/readyRead() reach a half-destroyed obj.
        QObject::disconnect(m_proc, nullptr, this, nullptr);
        if (m_proc->state() != QProcess::NotRunning) {
            requestStop();              // graceful logout + TUN teardown
            m_proc->waitForFinished(8000);
            if (m_proc->state() != QProcess::NotRunning) m_proc->kill();
        }
    }
}

QString SslVpnProtocol::backendDir() {
    const QString appDir = QCoreApplication::applicationDirPath();
    const QStringList cands = {
        appDir + QStringLiteral("/../backends"),                         // dev tree: build/../backends
        appDir + QStringLiteral("/backends"),
        appDir + QStringLiteral("/../libexec/iNodeClient-Qt/backends"),  // installed: bin/../libexec/...
        appDir + QStringLiteral("/../lib/iNodeClient-Qt/backends"),
        QStringLiteral("/usr/libexec/iNodeClient-Qt/backends"),
        QStringLiteral("/usr/lib/iNodeClient-Qt/backends"),
        QStringLiteral("/usr/local/libexec/iNodeClient-Qt/backends"),
    };
    for (const auto& c : cands) {
        if (QFileInfo::exists(c + QStringLiteral("/h3csvpn/__init__.py")))
            return QFileInfo(c).absoluteFilePath();
    }
    return {};
}

QString SslVpnProtocol::helperPath() {
    const QString local = QCoreApplication::applicationDirPath()
                          + QStringLiteral("/../scripts/inode-svpn-helper");
    if (QFileInfo::exists(local)) return QFileInfo(local).absoluteFilePath();
    const QString libexec = QStringLiteral("/usr/libexec/iNodeClient-Qt/inode-svpn-helper");
    if (QFileInfo::exists(libexec)) return libexec;
    return QStringLiteral("inode-svpn-helper");
}

bool SslVpnProtocol::buildHelperInvocation(const QStringList& helperArgs,
                                           QString* launcher, QStringList* full) const {
    const QString helper = helperPath();
    if (geteuid() == 0) {
        *launcher = helper;
        *full = helperArgs;
        return true;
    }
    const QString pkexec = QStandardPaths::findExecutable(QStringLiteral("pkexec"));
    if (!pkexec.isEmpty()) {
        *launcher = pkexec;
        *full = QStringList{} << helper << helperArgs;
        return true;
    }
    const QString sudo = QStandardPaths::findExecutable(QStringLiteral("sudo"));
    if (!sudo.isEmpty()) {
        *launcher = sudo;
        *full = QStringList{} << QStringLiteral("-n") << helper << helperArgs;
        return true;
    }
    return false;
}

void SslVpnProtocol::connectWith(const Profile& profile) {
    QString gateway = profile.serverHost.trimmed();
    if (gateway.isEmpty()) gateway = profile.sslvpnUrl.trimmed();
    if (gateway.isEmpty()) {
        emit errorOccurred(tr("SSL VPN profile has no gateway host."));
        setState(ConnectionState::Failed);
        return;
    }
    if (profile.username.isEmpty()) {
        emit errorOccurred(tr("Username is required."));
        setState(ConnectionState::Failed);
        return;
    }

    const QString backend = backendDir();
    if (backend.isEmpty()) {
        emit errorOccurred(tr(
            "Bundled SSL VPN backend (h3csvpn) not found. Expected it next to "
            "the executable under ../backends or in "
            "/usr/libexec/iNodeClient-Qt/backends."));
        setState(ConnectionState::Failed);
        return;
    }

    QString python = QStandardPaths::findExecutable(QStringLiteral("python3"));
    if (python.isEmpty()) python = QStandardPaths::findExecutable(QStringLiteral("python"));
    if (python.isEmpty()) {
        emit errorOccurred(tr("python3 is required to run the SSL VPN backend."));
        setState(ConnectionState::Failed);
        return;
    }

    CredentialStore::instance().retrieve(profile.id, &m_password);
    if (m_password.isEmpty()) {
        emit errorOccurred(tr("No stored password for profile."));
        setState(ConnectionState::Failed);
        return;
    }

    m_connName = QStringLiteral("svpn-%1").arg(profile.id.toString(QUuid::WithoutBraces).left(8));
    m_iface.clear();
    m_lastError.clear();
    m_userDisconnect = false;

    // --- Build the h3csvpn backend command line from the profile ---
    QStringList py;
    py << gateway << QStringLiteral("-u") << profile.username;
    if (!profile.domain.isEmpty())
        py << QStringLiteral("-d") << profile.domain;
    if (profile.serverPort > 0)
        py << QStringLiteral("--port") << QString::number(profile.serverPort);

    // TLS trust. Many H3C gateways ship a self-signed cert whose CN doesn't even
    // match the host, so a CA bundle can't validate it. A SHA-256 certificate
    // pin is the secure way to trust such a gateway — it binds to the exact cert
    // and skips the (useless) hostname/CA check. When set it overrides the trust
    // mode below.
    if (!profile.sslvpnPinSha256.isEmpty()) {
        py << QStringLiteral("--pin-sha256") << profile.sslvpnPinSha256;
    } else {
        switch (profile.trustMode) {
            case TrustMode::None:
                py << QStringLiteral("--insecure");
                break;
            case TrustMode::Pinned:
                if (!profile.caCertPath.isEmpty())
                    py << QStringLiteral("--cafile") << profile.caCertPath;
                break;
            case TrustMode::System:
            default:
                break;   // verify against the system CA store
        }
    }
    if (!profile.userCertPath.isEmpty())   // mutual TLS
        py << QStringLiteral("--client-cert") << profile.userCertPath;

    // Enterprise split tunnel: only the gateway's own subnets go through the
    // VPN; the default route and system DNS are left alone so general internet
    // traffic is unaffected.
    if (profile.sslvpnSplitTunnel)
        py << QStringLiteral("--split-tunnel");

    // EAD posture: send the host-check acknowledgement after login.
    if (profile.sslvpnEadHostcheck)
        py << QStringLiteral("--ead");

    // Zero-Trust / SDP single-packet-authorization knock before connecting.
    if (!profile.sslvpnSpaKey.isEmpty()) {
        py << QStringLiteral("--spa-key") << profile.sslvpnSpaKey;
        if (!profile.sslvpnSpaAid.isEmpty())
            py << QStringLiteral("--spa-aid") << profile.sslvpnSpaAid;
        if (!profile.sslvpnSpaPorts.isEmpty())
            py << QStringLiteral("--spa-ports") << profile.sslvpnSpaPorts;
    }

    // CAPTCHA: the gateways that use one ship a weak (but noisy) image; the
    // backend OCR-solves and auto-retries against the server's reply oracle.
    // A generous retry budget makes success near-certain since each attempt is
    // cheap; harmless when no captcha is required.
    py << QStringLiteral("--auto-captcha")
       << QStringLiteral("--captcha-retries") << QStringLiteral("40");
    if (profile.logLevel >= 2)
        py << QStringLiteral("-v");

    // --- Wrap in the privileged helper (TUN needs CAP_NET_ADMIN) ---
    QStringList helperArgs;
    helperArgs << QStringLiteral("connect")
               << QStringLiteral("--name")    << m_connName
               << QStringLiteral("--backend") << backend
               << QStringLiteral("--with-password")
               << QStringLiteral("--");
    helperArgs += py;

    QString launcher;
    QStringList full;
    if (!buildHelperInvocation(helperArgs, &launcher, &full)) {
        emit errorOccurred(tr(
            "Need root to create the VPN tunnel device, but neither pkexec nor "
            "sudo is available. Install polkit, or run the client as root."));
        m_password.clear();
        setState(ConnectionState::Failed);
        return;
    }

    Logger::instance().info(
        tr("SSL VPN: connecting to %1 as %2").arg(gateway, profile.username));

    if (m_proc) { m_proc->deleteLater(); m_proc = nullptr; }
    m_proc = new QProcess(this);
    m_proc->setProcessChannelMode(QProcess::MergedChannels);
    connect(m_proc, &QProcess::readyRead, this, &SslVpnProtocol::onReadyRead);
    connect(m_proc, &QProcess::finished, this, &SslVpnProtocol::onFinished);
    connect(m_proc, &QProcess::errorOccurred, this, [this](QProcess::ProcessError e) {
        if (e == QProcess::FailedToStart) {
            emit errorOccurred(tr("Could not launch the SSL VPN helper."));
            m_password.clear();
            setState(ConnectionState::Failed);
        }
    });

    setState(ConnectionState::Connecting);
    m_proc->start(launcher, full);
    if (!m_proc->waitForStarted(8000)) {
        emit errorOccurred(tr("SSL VPN helper did not start."));
        m_password.clear();
        setState(ConnectionState::Failed);
        return;
    }

    // Stream the password to the helper's stdin so it never lands in argv/ps.
    m_proc->write(m_password.toUtf8());
    m_proc->write("\n");
    m_proc->closeWriteChannel();
    m_password.clear();
}

void SslVpnProtocol::onReadyRead() {
    while (m_proc && m_proc->canReadLine()) {
        const QString line = QString::fromUtf8(m_proc->readLine()).trimmed();
        if (line.isEmpty()) continue;
        emit logLine(line);

        if (line.startsWith(QStringLiteral("[x]"))) {
            m_lastError = line.mid(3).trimmed();
            continue;
        }

        const QString l = line.toLower();
        // The backend announces a live tunnel as:
        //   "[+] Connected. interface=inode0 ip=10.x dns=... Ctrl-C ..."
        if (l.contains(QStringLiteral("connected. interface=")) ||
            l.contains(QStringLiteral("authentication succeeded"))) {
            QString reportedIp;
            for (const auto& tok : line.split(QLatin1Char(' '), Qt::SkipEmptyParts)) {
                if (tok.startsWith(QStringLiteral("interface=")))
                    m_iface = tok.mid(QStringLiteral("interface=").size());
                else if (tok.startsWith(QStringLiteral("ip=")))
                    reportedIp = tok.mid(3);
            }
            if (state() != ConnectionState::Connected) {
                ConnectionStats s;
                s.iface = m_iface;
                s.connectedAt = QDateTime::currentDateTime();
                netutil::refreshStats(s);
                if (s.localIp.isEmpty()) s.localIp = reportedIp;
                setStats(s);
                m_statsTimer->start();
            }
            setState(ConnectionState::Connected);
        } else if (l.contains(QStringLiteral("captcha")) ||
                   l.contains(QStringLiteral("verify code")) ||
                   l.contains(QStringLiteral("challenge")) ||
                   l.contains(QStringLiteral("2nd")) ||
                   l.contains(QStringLiteral("login")) ||
                   l.contains(QStringLiteral("authentic"))) {
            if (state() != ConnectionState::Connected)
                setState(ConnectionState::Authenticating);
        } else if (l.contains(QStringLiteral("gateway")) ||
                   l.contains(QStringLiteral("discover")) ||
                   l.contains(QStringLiteral("handshake")) ||
                   l.contains(QStringLiteral("net_extend")) ||
                   l.contains(QStringLiteral("tunnel"))) {
            if (state() != ConnectionState::Connected &&
                state() != ConnectionState::Authenticating)
                setState(ConnectionState::Connecting);
        }
    }
}

void SslVpnProtocol::pollStats() {
    ConnectionStats s = stats();
    if (s.iface.isEmpty()) s.iface = m_iface;
    netutil::refreshStats(s);
    setStats(s);
}

void SslVpnProtocol::onFinished(int exitCode, int /*exitStatus*/) {
    emit logLine(tr("SSL VPN backend exited with code %1").arg(exitCode));
    m_password.clear();
    m_statsTimer->stop();

    if (m_userDisconnect || exitCode == 0) {
        setState(ConnectionState::Disconnected);
        return;
    }

    // Non-zero, not user-initiated: report the most specific reason we have.
    QString reason = m_lastError;
    if (reason.isEmpty()) {
        switch (exitCode) {
            case 2:   reason = tr("authentication or connection failed "
                                  "(check username, password, domain and gateway)"); break;
            case 3:   reason = tr("tunnel setup failed after a successful login"); break;
            case 4:   reason = tr("the tunnel needs root privileges"); break;
            case 126:
            case 127: reason = tr("could not gain privileges "
                                  "(pkexec/sudo denied or no polkit agent running)"); break;
            default:  reason = tr("backend exited with code %1").arg(exitCode); break;
        }
    }
    emit errorOccurred(tr("SSL VPN: %1").arg(reason));
    setState(ConnectionState::Failed);
}

void SslVpnProtocol::requestStop() {
    if (m_connName.isEmpty()) return;
    QStringList helperArgs;
    helperArgs << QStringLiteral("stop") << QStringLiteral("--name") << m_connName;
    QString launcher;
    QStringList full;
    if (!buildHelperInvocation(helperArgs, &launcher, &full)) return;

    QProcess stop;
    stop.setProcessChannelMode(QProcess::MergedChannels);
    stop.start(launcher, full);
    if (!stop.waitForStarted(5000)) return;
    stop.waitForFinished(15000);
    const QByteArray out = stop.readAll();
    for (const auto& ln : out.split('\n'))
        if (!ln.trimmed().isEmpty()) emit logLine(QString::fromUtf8(ln));
}

void SslVpnProtocol::disconnect() {
    if (!m_proc && m_connName.isEmpty()) return;
    m_userDisconnect = true;
    setState(ConnectionState::Disconnecting);
    m_statsTimer->stop();

    // SIGINT the (root) backend via the helper so it logs out + tears down TUN.
    // We can't signal the privileged process from the GUI directly.
    requestStop();

    if (m_proc && m_proc->state() != QProcess::NotRunning) {
        if (!m_proc->waitForFinished(8000)) {
            m_proc->kill();                 // best effort
            m_proc->waitForFinished(2000);
        }
    } else {
        setState(ConnectionState::Disconnected);
    }
    m_connName.clear();
}

} // namespace inode
