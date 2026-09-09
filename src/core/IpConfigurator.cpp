#include "IpConfigurator.h"

#include "Dhcp.h"
#include "Logger.h"
#include "Profile.h"

#include <QCoreApplication>
#include <QFileInfo>
#include <QProcess>
#include <QStandardPaths>
#include <QStringList>
#include <QTimer>

#include <unistd.h>

namespace inode {

QString IpConfigurator::helperPath() {
    const QString local = QCoreApplication::applicationDirPath()
                          + QStringLiteral("/../scripts/inode-ipcfg-helper");
    if (QFileInfo::exists(local)) return QFileInfo(local).absoluteFilePath();
    const QString libexec =
        QStringLiteral("/usr/libexec/iNodeClient-Qt/inode-ipcfg-helper");
    if (QFileInfo::exists(libexec)) return libexec;
    return QStringLiteral("inode-ipcfg-helper");
}

int IpConfigurator::maskToPrefix(const QString& mask) {
    const QString m = mask.trimmed();
    if (m.isEmpty()) return 24;   // sane default when the user left it blank
    // Already a prefix length?
    if (!m.contains(QLatin1Char('.'))) {
        bool ok = false;
        const int n = m.toInt(&ok);
        return ok ? qBound(0, n, 32) : 24;
    }
    // Dotted decimal -> count the set bits.
    int bits = 0;
    const auto octets = m.split(QLatin1Char('.'));
    if (octets.size() != 4) return 24;
    for (const auto& part : octets) {
        bool ok = false;
        const int v = part.toInt(&ok);
        if (!ok || v < 0 || v > 255) return 24;
        bits += __builtin_popcount(static_cast<unsigned>(v));
    }
    return qBound(0, bits, 32);
}

bool IpConfigurator::runHelper(const QStringList& args) {
    const QString helper = helperPath();
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
        Logger::instance().error(
            QStringLiteral("static IP: need root but neither pkexec nor sudo is available"));
        return false;
    }

    QProcess proc;
    proc.setProcessChannelMode(QProcess::MergedChannels);
    proc.start(launcher, full);
    if (!proc.waitForStarted(5000)) {
        Logger::instance().error(QStringLiteral("static IP: helper failed to start (%1)").arg(launcher));
        return false;
    }
    proc.closeWriteChannel();
    if (!proc.waitForFinished(30000)) {
        proc.kill();
        proc.waitForFinished(2000);
        Logger::instance().error(QStringLiteral("static IP: helper timed out"));
        return false;
    }
    const QString out = QString::fromUtf8(proc.readAll()).trimmed();
    if (!out.isEmpty()) Logger::instance().info(out);
    return proc.exitCode() == 0;
}

void IpConfigurator::runHelperAsync(const QStringList& args,
                                    std::function<void(bool)> onDone) {
    const QString helper = helperPath();
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
        Logger::instance().error(
            QStringLiteral("static IP: need root but neither pkexec nor sudo is available"));
        if (onDone) onDone(false);
        return;
    }

    auto* proc = new QProcess(qApp);
    proc->setProcessChannelMode(QProcess::MergedChannels);
    QObject::connect(proc, &QProcess::finished, qApp,
        [proc, cb = std::move(onDone)](int exitCode, QProcess::ExitStatus) {
            const QString out = QString::fromUtf8(proc->readAll()).trimmed();
            if (!out.isEmpty()) Logger::instance().info(out);
            proc->deleteLater();
            if (cb) cb(exitCode == 0);
        });
    proc->start(launcher, full);
    proc->closeWriteChannel();
    // Hard bound: the helper is a quick `ip addr/route` batch; a stuck run
    // must not leak a pkexec prompt forever.
    QTimer::singleShot(30000, proc, [proc] {
        if (proc->state() != QProcess::NotRunning) proc->kill();
    });
}

bool IpConfigurator::staticArgs(const Profile& p, const QString& iface,
                                bool applyMode, QStringList* out) {
    if (iface.isEmpty() || p.ipMode != IpMode::Static || p.staticIp.isEmpty())
        return false;
    const int prefix = maskToPrefix(p.staticNetmask);
    *out = QStringList{applyMode ? QStringLiteral("apply") : QStringLiteral("clear"),
                       QStringLiteral("--iface"),  iface,
                       QStringLiteral("--ip"),     p.staticIp,
                       QStringLiteral("--prefix"), QString::number(prefix)};
    if (!p.staticGateway.isEmpty()) out->append(QStringLiteral("--gw")), out->append(p.staticGateway);
    if (applyMode && !p.staticDns.isEmpty())
        out->append(QStringLiteral("--dns")), out->append(p.staticDns);
    return true;
}

bool IpConfigurator::apply(const Profile& p, const QString& iface) {
    if (iface.isEmpty()) {
        Logger::instance().warn(QStringLiteral("IP config: no interface; skipping"));
        return false;
    }
    switch (p.ipMode) {
        case IpMode::Inherit:
            return true;   // leave whatever the OS already has
        case IpMode::Dhcp:
            Logger::instance().info(QStringLiteral("IP config: DHCP on %1").arg(iface));
            return dhcp::renew(iface);
        case IpMode::Static:
            break;
    }

    QStringList args;
    if (!staticArgs(p, iface, true, &args)) {
        Logger::instance().warn(
            QStringLiteral("IP config: Static mode but no address set; skipping"));
        return false;
    }

    Logger::instance().info(
        QStringLiteral("IP config: static %1/%2 on %3").arg(p.staticIp).arg(
            maskToPrefix(p.staticNetmask)).arg(iface));
    return runHelper(args);
}

void IpConfigurator::applyAsync(const Profile& p, const QString& iface,
                                std::function<void(bool)> onDone) {
    if (iface.isEmpty()) {
        Logger::instance().warn(QStringLiteral("IP config: no interface; skipping"));
        if (onDone) onDone(false);
        return;
    }
    switch (p.ipMode) {
        case IpMode::Inherit:
            if (onDone) onDone(true);
            return;
        case IpMode::Dhcp:
            Logger::instance().info(QStringLiteral("IP config: DHCP on %1 (background)").arg(iface));
            dhcp::renewAsync(iface, std::move(onDone));
            return;
        case IpMode::Static:
            break;
    }

    QStringList args;
    if (!staticArgs(p, iface, true, &args)) {
        Logger::instance().warn(
            QStringLiteral("IP config: Static mode but no address set; skipping"));
        if (onDone) onDone(false);
        return;
    }
    Logger::instance().info(
        QStringLiteral("IP config: static %1/%2 on %3").arg(p.staticIp).arg(
            maskToPrefix(p.staticNetmask)).arg(iface));
    runHelperAsync(args, std::move(onDone));
}

void IpConfigurator::clear(const Profile& p, const QString& iface) {
    QStringList args;
    if (!staticArgs(p, iface, false, &args))
        return;
    runHelper(args);
}

void IpConfigurator::clearAsync(const Profile& p, const QString& iface) {
    QStringList args;
    if (!staticArgs(p, iface, false, &args))
        return;
    runHelperAsync(args);
}

} // namespace inode
