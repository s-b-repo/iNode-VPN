#include "TrayIcon.h"

#include <QAction>
#include <QApplication>
#include <QIcon>
#include <QMenu>
#include <QSystemTrayIcon>
#include <QWidget>

namespace inode {

TrayIcon::TrayIcon(QWidget* mainWindow) : QObject(mainWindow), m_parent(mainWindow) {
    if (!QSystemTrayIcon::isSystemTrayAvailable()) return;

    m_tray = new QSystemTrayIcon(this);
    m_tray->setIcon(QIcon::fromTheme(QStringLiteral("network-vpn-disconnected"),
                                     QIcon(QStringLiteral(":/icons/app.svg"))));
    m_tray->setToolTip(tr("iNode Client (Qt) — Disconnected"));

    m_menu = new QMenu(mainWindow);
    m_actShow       = m_menu->addAction(tr("Show &window"));
    m_menu->addSeparator();
    m_actConnect    = m_menu->addAction(tr("&Connect"));
    m_actDisconnect = m_menu->addAction(tr("&Disconnect"));
    m_menu->addSeparator();
    m_actQuit       = m_menu->addAction(tr("&Quit"));

    m_tray->setContextMenu(m_menu);

    connect(m_actShow,       &QAction::triggered, this, &TrayIcon::showRequested);
    connect(m_actConnect,    &QAction::triggered, this, &TrayIcon::connectRequested);
    connect(m_actDisconnect, &QAction::triggered, this, &TrayIcon::disconnectRequested);
    connect(m_actQuit,       &QAction::triggered, this, &TrayIcon::quitRequested);

    connect(m_tray, &QSystemTrayIcon::activated, this,
            [this](QSystemTrayIcon::ActivationReason r) {
        if (r == QSystemTrayIcon::Trigger) emit showRequested();
    });

    rebuildMenu();
    m_tray->show();
}

bool TrayIcon::isAvailable() const { return m_tray != nullptr; }

void TrayIcon::setState(ConnectionState state) {
    m_state = state;
    if (!m_tray) return;

    QString iconName;
    switch (state) {
        case ConnectionState::Connected:      iconName = QStringLiteral("network-vpn"); break;
        case ConnectionState::Connecting:
        case ConnectionState::Authenticating:
        case ConnectionState::Disconnecting:  iconName = QStringLiteral("network-vpn-acquiring"); break;
        case ConnectionState::Failed:         iconName = QStringLiteral("network-vpn-no-route"); break;
        case ConnectionState::Disconnected:
        default:                              iconName = QStringLiteral("network-vpn-disconnected"); break;
    }
    m_tray->setIcon(QIcon::fromTheme(iconName, QIcon(QStringLiteral(":/icons/app.svg"))));

    const QString prefix = m_profileName.isEmpty()
        ? tr("iNode Client (Qt)")
        : tr("iNode Client (Qt) — %1").arg(m_profileName);
    m_tray->setToolTip(QStringLiteral("%1 — %2").arg(prefix, stateName(state)));

    rebuildMenu();
}

void TrayIcon::setProfileName(const QString& name) {
    m_profileName = name;
    setState(m_state);  // re-applies tooltip
}

void TrayIcon::notify(const QString& title, const QString& body) {
    if (m_tray) m_tray->showMessage(title, body);
}

void TrayIcon::rebuildMenu() {
    const bool busy = m_state != ConnectionState::Disconnected
                      && m_state != ConnectionState::Failed;
    if (m_actConnect)    m_actConnect->setEnabled(!busy);
    if (m_actDisconnect) m_actDisconnect->setEnabled(busy);
}

} // namespace inode
