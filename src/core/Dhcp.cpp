#include "Dhcp.h"

#include "Logger.h"

#include <QProcess>
#include <QStandardPaths>
#include <QStringList>

namespace inode::dhcp {

namespace {
int run(const QString& bin, const QStringList& args, QString* out = nullptr) {
    QProcess p;
    p.setProcessChannelMode(QProcess::MergedChannels);
    p.start(bin, args);
    if (!p.waitForStarted(3000)) return -1;
    if (!p.waitForFinished(15000)) {
        // Timeout must not be reported as success: the exit code of a
        // still-running process is meaningless (and would read as 0).
        p.kill();
        p.waitForFinished(2000);
        Logger::instance().warn(QStringLiteral("dhcp: %1 timed out").arg(bin));
        return -1;
    }
    const auto s = QString::fromUtf8(p.readAll()).trimmed();
    if (out) *out = s;
    if (!s.isEmpty()) Logger::instance().info(s);
    return p.exitCode();
}
} // namespace

bool renew(const QString& iface) {
    if (iface.isEmpty()) {
        Logger::instance().warn(QStringLiteral("dhcp: no interface given"));
        return false;
    }

    const QString nmcli = QStandardPaths::findExecutable(QStringLiteral("nmcli"));
    if (!nmcli.isEmpty()) {
        Logger::instance().info(QStringLiteral("dhcp: nmcli reapply on %1").arg(iface));
        if (run(nmcli, {QStringLiteral("device"), QStringLiteral("reapply"), iface}) == 0)
            return true;
        Logger::instance().warn(QStringLiteral("dhcp: nmcli reapply failed; falling back"));
    }

    const QString dhclient = QStandardPaths::findExecutable(QStringLiteral("dhclient"));
    const QString pkexec   = QStandardPaths::findExecutable(QStringLiteral("pkexec"));
    if (dhclient.isEmpty()) {
        Logger::instance().error(QStringLiteral("dhcp: no nmcli or dhclient found"));
        return false;
    }

    const QString launcher = pkexec.isEmpty() ? dhclient : pkexec;
    QStringList release = pkexec.isEmpty()
        ? QStringList{QStringLiteral("-r"), iface}
        : QStringList{dhclient, QStringLiteral("-r"), iface};
    QStringList bind    = pkexec.isEmpty()
        ? QStringList{iface}
        : QStringList{dhclient, iface};

    Logger::instance().info(QStringLiteral("dhcp: dhclient -r %1").arg(iface));
    run(launcher, release);
    Logger::instance().info(QStringLiteral("dhcp: dhclient %1").arg(iface));
    return run(launcher, bind) == 0;
}

void renewAsync(const QString& iface, std::function<void(bool)> onDone) {
    if (iface.isEmpty()) {
        Logger::instance().warn(QStringLiteral("dhcp: no interface given"));
        if (onDone) onDone(false);
        return;
    }

    const QString nmcli = QStandardPaths::findExecutable(QStringLiteral("nmcli"));
    if (!nmcli.isEmpty()) {
        Logger::instance().info(QStringLiteral("dhcp: nmcli reapply on %1 (background)").arg(iface));
        // nmcli reapply is quick; run detached and report success.
        const bool started = QProcess::startDetached(
            nmcli, {QStringLiteral("device"), QStringLiteral("reapply"), iface});
        if (started) {
            if (onDone) onDone(true);
            return;
        }
        Logger::instance().warn(QStringLiteral("dhcp: nmcli reapply failed to start; falling back"));
    }

    const QString dhclient = QStandardPaths::findExecutable(QStringLiteral("dhclient"));
    const QString pkexec   = QStandardPaths::findExecutable(QStringLiteral("pkexec"));
    if (dhclient.isEmpty()) {
        Logger::instance().error(QStringLiteral("dhcp: no nmcli or dhclient found"));
        if (onDone) onDone(false);
        return;
    }

    const QString launcher = pkexec.isEmpty() ? dhclient : pkexec;
    QStringList release = pkexec.isEmpty()
        ? QStringList{QStringLiteral("-r"), iface}
        : QStringList{dhclient, QStringLiteral("-r"), iface};
    QStringList bind    = pkexec.isEmpty()
        ? QStringList{iface}
        : QStringList{dhclient, iface};

    Logger::instance().info(QStringLiteral("dhcp: dhclient -r %1 (background)").arg(iface));
    QProcess::startDetached(launcher, release);
    Logger::instance().info(QStringLiteral("dhcp: dhclient %1 (background)").arg(iface));
    const bool ok = QProcess::startDetached(launcher, bind);
    if (onDone) onDone(ok);
}

} // namespace inode::dhcp
