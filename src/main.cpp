#include "MainWindow.h"
#include "core/ConnectionStats.h"
#include "core/Logger.h"
#include "core/Protocol.h"
#include "core/ProfileStore.h"
#include "core/Settings.h"
#include "ui/ThemeManager.h"

#include <QApplication>
#include <QCommandLineParser>
#include <QIcon>
#include <QLibraryInfo>
#include <QLocale>
#include <QSystemTrayIcon>
#include <QTextStream>
#include <QTimer>
#include <QTranslator>

using inode::Logger;
using inode::MainWindow;
using inode::ProfileStore;
using inode::Settings;
using inode::ThemeManager;

int main(int argc, char** argv) {
    QApplication app(argc, argv);
    QApplication::setOrganizationName(QStringLiteral("iNodeClient-Qt"));
    QApplication::setApplicationName(QStringLiteral("iNodeClient-Qt"));
    QApplication::setApplicationVersion(QStringLiteral("0.2.0"));
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
    parser.addOption(optMin);
    parser.addOption(optConnect);
    parser.addOption(optDisconnect);
    parser.addOption(optList);
    parser.addOption(optStatus);
    parser.process(app);

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

    ProfileStore store;
    store.load();

    // --list-profiles / --status short-circuit the UI
    if (parser.isSet(optList)) {
        QTextStream out(stdout);
        for (const auto& p : store.profiles())
            out << p.name << '\t' << inode::protocolName(p.kind) << '\n';
        return 0;
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
    } else if (parser.isSet(optDisconnect)) {
        QTimer::singleShot(0, &w, [&w] { w.disconnectActive(); QCoreApplication::quit(); });
    } else if (const auto* p = store.autoConnectProfile()) {
        QTimer::singleShot(0, &w, [&w, p] { w.connectByProfile(*p); });
    }

    return app.exec();
}
