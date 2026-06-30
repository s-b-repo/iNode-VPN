#include "WlanProtocol.h"

#include "core/CredentialStore.h"
#include "core/Logger.h"

#include <QProcess>
#include <QStandardPaths>

namespace inode {

WlanProtocol::WlanProtocol(QObject* parent) : IProtocol(parent) {
    m_inner = new Dot1xProtocol(this);
    connect(m_inner, &IProtocol::stateChanged, this, [this](ConnectionState s) { setState(s); });
    connect(m_inner, &IProtocol::logLine,      this, &IProtocol::logLine);
    connect(m_inner, &IProtocol::errorOccurred, this, &IProtocol::errorOccurred);
    connect(m_inner, &IProtocol::statsUpdated, this, [this](const ConnectionStats& s) { setStats(s); });
}

WlanProtocol::~WlanProtocol() = default;

void WlanProtocol::connectWith(const Profile& profile) {
    m_iface = profile.iface;
    m_ssid  = profile.wlanSsid;

    if (m_ssid.isEmpty()) {
        Logger::instance().info(QStringLiteral("WLAN: no SSID set, running plain 802.1X on %1").arg(m_iface));
        runDot1x(profile);
        return;
    }
    associate(profile);
}

void WlanProtocol::associate(const Profile& profile) {
    const QString nmcli = QStandardPaths::findExecutable(QStringLiteral("nmcli"));
    if (nmcli.isEmpty()) {
        emit errorOccurred(tr("WLAN requires nmcli (NetworkManager) to associate with SSIDs."));
        setState(ConnectionState::Failed);
        return;
    }

    QString pw;
    CredentialStore::instance().retrieve(profile.id, &pw);

    setState(ConnectionState::Connecting);
    Logger::instance().info(tr("WLAN: associating with SSID '%1' on %2").arg(m_ssid, m_iface));

    QStringList args{QStringLiteral("device"), QStringLiteral("wifi"),
                     QStringLiteral("connect"), m_ssid};
    if (!pw.isEmpty()) { args << QStringLiteral("password") << pw; }
    if (!m_iface.isEmpty()) { args << QStringLiteral("ifname") << m_iface; }
    if (profile.wlanHiddenSsid) { args << QStringLiteral("hidden") << QStringLiteral("yes"); }

    auto* p = new QProcess(this);
    p->setProcessChannelMode(QProcess::MergedChannels);
    connect(p, &QProcess::readyRead, this, [this, p] {
        while (p->canReadLine()) {
            const QString line = QString::fromUtf8(p->readLine()).trimmed();
            if (!line.isEmpty()) emit logLine(line);
        }
    });
    connect(p, &QProcess::finished, this,
            [this, p, profile](int exitCode, QProcess::ExitStatus) {
        p->deleteLater();
        if (exitCode != 0) {
            setState(ConnectionState::Failed);
            return;
        }
        runDot1x(profile);
    });

    p->start(QStandardPaths::findExecutable(QStringLiteral("nmcli")), args);
}

void WlanProtocol::runDot1x(const Profile& profile) {
    m_inner->connectWith(profile);
}

void WlanProtocol::disconnect() {
    if (m_inner) m_inner->disconnect();
    if (!m_ssid.isEmpty()) {
        const QString nmcli = QStandardPaths::findExecutable(QStringLiteral("nmcli"));
        if (!nmcli.isEmpty()) {
            QProcess::startDetached(nmcli,
                {QStringLiteral("connection"), QStringLiteral("down"), m_ssid});
        }
    }
}

} // namespace inode
