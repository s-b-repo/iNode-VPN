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
    p.waitForFinished(15000);
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

} // namespace inode::dhcp
