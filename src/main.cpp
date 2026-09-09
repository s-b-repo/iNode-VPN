#include "MainWindow.h"
#include "core/ConnectionStats.h"
#include "core/ControlChannel.h"
#include "core/CredentialStore.h"
#include "core/EncryptedFileStore.h"
#include "core/Logger.h"
#include "core/Protocol.h"
#include "core/ProfileStore.h"
#include "core/SecretServiceStore.h"
#include "core/Settings.h"
#include "ui/ThemeManager.h"

#include <QApplication>
#include <QCommandLineParser>
#include <QFileInfo>
#include <QIcon>
#include <QInputDialog>
#include <QLibraryInfo>
#include <QLineEdit>
#include <QLocale>
#include <QMessageBox>
#include <QStandardPaths>
#include <QSystemTrayIcon>
#include <QTextStream>
#include <QTimer>
#include <QTranslator>

using inode::CredentialStore;

using inode::Logger;
using inode::MainWindow;
using inode::ProfileStore;
using inode::Settings;
using inode::ThemeManager;

namespace {

// --doctor: probe the runtime environment and report what the app will
// actually use on this machine. Purely read-only.
int runDoctor(QTextStream& out) {
    auto line = [&out](const QString& status, const QString& what) {
        out << QStringLiteral("  [%1] %2").arg(status, what) << '\n';
    };
    auto ok    = [](bool b) { return b ? QStringLiteral("ok") : QStringLiteral("MISSING"); };
    auto which = [](const char* exe) {
        return QStandardPaths::findExecutable(QLatin1String(exe));
    };

    out << "iNode Client (Qt) — environment doctor\n";

    out << "\nBuild / platform:\n";
    line(ok(true), QStringLiteral("Qt %1 (%2-bit, %3)")
             .arg(QT_VERSION_STR)
             .arg(QSysInfo::buildCpuArchitecture(), QSysInfo::currentCpuArchitecture()));
#ifdef HAVE_KF6
    line(ok(true), QStringLiteral("KDE Frameworks 6 (KWallet/KConfig linked)"));
#else
    line(ok(false), QStringLiteral("KDE Frameworks 6 (not linked — KWallet unavailable)"));
#endif

    out << "\nCredential backends (in priority order):\n";
#ifdef HAVE_KF6
    line(ok(true), QStringLiteral("KWallet (KF6)"));
#else
    line(ok(false), QStringLiteral("KWallet (build without KF6)"));
#endif
    line(ok(inode::secretservice::available()), QStringLiteral("freedesktop Secret Service"));
    line(ok(inode::encfilestore::haveCrypto()), QStringLiteral("AES-256-GCM file (libcrypto via dlopen)"));
    out << "  active: " << inode::CredentialStore::instance().backendDescription() << '\n';
    // The system-GnuPG backend was removed in v0.3; a leftover store is
    // migrated transparently on first use.
    const QString legacyGpg =
        QStandardPaths::writableLocation(QStandardPaths::AppConfigLocation)
        + QStringLiteral("/secrets.gpg");
    if (QFileInfo::exists(legacyGpg)) {
        out << "  note: legacy GPG credential store found ("
            << legacyGpg << ") — migrated to the active backend on first use\n";
    }

    out << "\nExternal tools:\n";
    line(ok(!which("python3").isEmpty()), QStringLiteral("python3 (SSL VPN backend runtime)"));
    line(ok(!which("pkexec").isEmpty()), QStringLiteral("pkexec (privileged helpers)"));
    line(ok(!which("tesseract").isEmpty()), QStringLiteral("tesseract (CAPTCHA OCR)"));
    line(ok(!which("minieap").isEmpty() || !which("mentohust").isEmpty()),
         QStringLiteral("minieap or mentohust (802.1X)"));
    line(ok(!which("ipsec").isEmpty()), QStringLiteral("strongSwan ipsec (L2TP/IPSec)"));
    line(ok(!which("xl2tpd").isEmpty()), QStringLiteral("xl2tpd (L2TP tunnel)"));
    line(ok(!which("nmcli").isEmpty()), QStringLiteral("NetworkManager nmcli (WLAN)"));

    out << "\nPrivileged helpers + polkit:\n";
    const QString libexec = QStringLiteral("/usr/libexec/iNodeClient-Qt");
    for (const char* helper : {"inode-svpn-helper", "inode-l2tp-helper",
                               "inode-dot1x-helper", "inode-ipcfg-helper"}) {
        const QString installed = libexec + QLatin1Char('/') + QLatin1String(helper);
        // Local (uninstalled) tree fallback, relative to the binary.
        const QString local = QCoreApplication::applicationDirPath()
            + QStringLiteral("/../scripts/") + QLatin1String(helper);
        const bool found = QFileInfo::exists(installed) || QFileInfo::exists(local);
        line(ok(found), QStringLiteral("%1").arg(QLatin1String(helper)));
    }
    // polkit only scans /usr/share/polkit-1/actions (its compile-time datadir).
    // A PREFIX=/usr/local install puts the file under /usr/local/share, which
    // polkit never reads — deploy.sh mirrors it; warn if that didn't happen.
    const bool policyCanonical =
        QFileInfo::exists(QStringLiteral("/usr/share/polkit-1/actions/org.inode.ClientQt.policy"));
    const bool policyPrefixOnly = !policyCanonical &&
        QFileInfo::exists(QStringLiteral("/usr/local/share/polkit-1/actions/org.inode.ClientQt.policy"));
    line(ok(policyCanonical), QStringLiteral("polkit action org.inode.ClientQt.* "
                                             "(/usr/share/polkit-1/actions)"));
    if (policyPrefixOnly) {
        out << "  note: policy only found under /usr/local/share — polkit will not see it;\n"
               "        run ./deploy.sh (it mirrors the file into /usr/share/polkit-1/actions)\n";
    } else if (!policyCanonical) {
        out << "  note: not installed system-wide — pkexec will still prompt, just without\n"
               "        the per-action descriptions (./deploy.sh registers the policy)\n";
    }

    out << "\nSSL VPN backend module:\n";
    {
        const QString vendored = QCoreApplication::applicationDirPath()
            + QStringLiteral("/../backends/h3csvpn/__init__.py");
        const QString installed = libexec + QStringLiteral("/backends/h3csvpn/__init__.py");
        const bool found = QFileInfo::exists(installed) || QFileInfo::exists(vendored);
        line(ok(found), QStringLiteral("h3csvpn python package"));
    }

    out.flush();
    return 0;
}

} // namespace

// Text-only entry points (--doctor, --version, --help, --list-profiles) must
// work on a headless box / over SSH / from deploy.sh in a TTY. QApplication
// aborts when no platform plugin can start, so when no display is reachable
// and the caller only asked for text output, fall back to the offscreen QPA.
static void selectHeadlessPlatformIfNeeded(int argc, char** argv) {
    if (qEnvironmentVariableIsSet("QT_QPA_PLATFORM")) return;
    bool textOnly = false;
    for (int i = 1; i < argc; ++i) {
        const QByteArray a(argv[i]);
        if (a == "--doctor" || a == "--version" || a == "-v"
                || a == "--help" || a == "-h" || a == "--list-profiles"
                || a == "--status" || a == "--disconnect") {
            textOnly = true;
            break;
        }
    }
    if (!textOnly) return;
    if (qEnvironmentVariableIsEmpty("DISPLAY")
            && qEnvironmentVariableIsEmpty("WAYLAND_DISPLAY")) {
        qputenv("QT_QPA_PLATFORM", QByteArrayLiteral("offscreen"));
    }
}

#ifndef INODE_VERSION
#define INODE_VERSION "0.3.0"
#endif

int main(int argc, char** argv) {
    selectHeadlessPlatformIfNeeded(argc, argv);
    QApplication app(argc, argv);
    QApplication::setOrganizationName(QStringLiteral("iNodeClient-Qt"));
    QApplication::setApplicationName(QStringLiteral("iNodeClient-Qt"));
    QApplication::setApplicationVersion(QStringLiteral(INODE_VERSION));
    QApplication::setApplicationDisplayName(QStringLiteral("iNode Client (Qt)"));
    // Only stay alive on window close when we actually have somewhere to go
    // (i.e. a usable system tray). Otherwise closing the window means quit.
    QApplication::setQuitOnLastWindowClosed(!QSystemTrayIcon::isSystemTrayAvailable());

    qRegisterMetaType<inode::ConnectionStats>("inode::ConnectionStats");
    qRegisterMetaType<inode::ConnectionState>("inode::ConnectionState");

    QCommandLineParser parser;
    parser.setApplicationDescription(QObject::tr(
        "Qt/KF6 reimplementation of the H3C iNode authentication client."));
    parser.addHelpOption();
    parser.addVersionOption();
    QCommandLineOption optMin({QStringLiteral("m"), QStringLiteral("minimized")},
                              QObject::tr("Start hidden in the system tray."));
    QCommandLineOption optConnect(QStringLiteral("connect"),
                                  QObject::tr("Connect to the named profile at launch."),
                                  QStringLiteral("profile"));
    QCommandLineOption optDisconnect(QStringLiteral("disconnect"),
                                     QObject::tr("Disconnect any running session and exit."));
    QCommandLineOption optList(QStringLiteral("list-profiles"),
                               QObject::tr("Print known profiles to stdout and exit."));
    QCommandLineOption optStatus(QStringLiteral("status"),
                                 QObject::tr("Print the connection state to stdout and exit."));
    QCommandLineOption optDoctor(QStringLiteral("doctor"),
                                 QObject::tr("Probe the runtime environment (backends, tools, helpers) and exit."));
    parser.addOption(optMin);
    parser.addOption(optConnect);
    parser.addOption(optDisconnect);
    parser.addOption(optList);
    parser.addOption(optStatus);
    parser.addOption(optDoctor);
    parser.process(app);

    // --doctor never touches the GUI, profile store, or tray: report and exit.
    if (parser.isSet(optDoctor)) {
        QTextStream out(stdout);
        return runDoctor(out);
    }

    // Translations
    QTranslator qtTranslator;
    QTranslator appTranslator;
    QString locale = Settings::instance().language();
    if (locale.isEmpty()) locale = QLocale::system().name();
    if (qtTranslator.load(QStringLiteral("qtbase_") + locale,
                          QLibraryInfo::path(QLibraryInfo::TranslationsPath))) {
        app.installTranslator(&qtTranslator);
    }
    if (appTranslator.load(QStringLiteral(":/i18n/iNodeClient-Qt_") + locale)) {
        app.installTranslator(&appTranslator);
    }

    QApplication::setWindowIcon(QIcon::fromTheme(QStringLiteral("network-vpn"),
                                                  QIcon(QStringLiteral(":/icons/app.svg"))));

    ThemeManager::instance().start();

    // Master-password prompt for the local AES-256-GCM fallback. Only fires
    // when neither KWallet nor a Secret Service daemon is available AND
    // there is at least one secret to unlock; KDE / GNOME users never see
    // it. The typed password derives an AES-256 key via PBKDF2 and lives
    // only in memory for the process's lifetime.
    CredentialStore::instance().setPasswordPrompt(
        [](const QString& reason, bool confirm) -> QString {
            const QString title = QObject::tr("iNode Client — encrypted credentials");
            const QString body = confirm
                ? QObject::tr("No system keyring (KWallet/gnome-keyring) is available.\n"
                              "Set a master password to encrypt your saved credentials.\n"
                              "It is never stored on disk and is required to unlock the\n"
                              "file each time the app starts.")
                : QObject::tr("Enter your master password to unlock saved credentials.\n"
                              "(%1)").arg(reason);
            bool ok = false;
            const QString first = QInputDialog::getText(
                nullptr, title, body, QLineEdit::Password, QString(), &ok);
            if (!ok || first.isEmpty()) return {};
            if (!confirm) return first;
            const QString second = QInputDialog::getText(
                nullptr, title, QObject::tr("Confirm master password:"),
                QLineEdit::Password, QString(), &ok);
            if (!ok || first != second) {
                QMessageBox::warning(nullptr, title,
                    QObject::tr("Passwords did not match — no password set."));
                return {};
            }
            return first;
        });

    ProfileStore store;
    store.load();

    // --list-profiles / --status / --disconnect short-circuit the UI.
    if (parser.isSet(optList)) {
        QTextStream out(stdout);
        for (const auto& p : store.profiles())
            out << p.name << '\t' << inode::protocolName(p.kind) << '\n';
        return 0;
    }
    // Talk to the instance that is already running (if any) over the local
    // control socket instead of starting a second GUI.
    //   --status      exit 0 connected, 2 running but not connected, 3 not running
    //   --disconnect  exit 0 sent, 3 not running
    //   --connect     forwarded when an instance runs; otherwise starts the GUI
    //   (no flags)    raises the running window instead of opening a second one
    if (parser.isSet(optStatus)) {
        QTextStream out(stdout);
        QString reply;
        if (!inode::sendControlCommand(QStringLiteral("status"), &reply)) {
            out << "not running\n";
            return 3;
        }
        out << reply << '\n';
        return reply.startsWith(QLatin1String("connected")) ? 0 : 2;
    }
    if (parser.isSet(optDisconnect)) {
        QTextStream out(stdout);
        QString reply;
        if (!inode::sendControlCommand(QStringLiteral("disconnect"), &reply)) {
            out << "not running — nothing to disconnect\n";
            return 3;
        }
        out << reply << '\n';
        return 0;
    }
    {
        QString reply;
        const QString cmd = parser.isSet(optConnect)
            ? QStringLiteral("connect ") + parser.value(optConnect)
            : QStringLiteral("show");
        if (inode::sendControlCommand(cmd, &reply)) {
            QTextStream out(stdout);
            out << reply << '\n';
            return reply.startsWith(QLatin1String("error")) ? 1 : 0;
        }
    }

    MainWindow w(&store);
    const bool startHidden = parser.isSet(optMin) || Settings::instance().startMinimized();
    if (!startHidden) w.show();

    // --connect <name>
    if (parser.isSet(optConnect)) {
        const QString name = parser.value(optConnect);
        const auto* p = store.findByName(name);
        if (!p) {
            Logger::instance().error(QObject::tr("no profile named '%1'").arg(name));
        } else {
            QTimer::singleShot(0, &w, [&w, p] { w.connectByProfile(*p); });
        }
    } else if (const auto* p = store.autoConnectProfile()) {
        QTimer::singleShot(0, &w, [&w, p] { w.connectByProfile(*p); });
    }

    return app.exec();
}
