#pragma once

#include "core/Protocol.h"
#include <QObject>

class QAction;
class QMenu;
class QSystemTrayIcon;
class QWidget;

namespace inode {

// Thin wrapper around QSystemTrayIcon. Exposes high-level signals the main
// window can connect to; the tray itself doesn't know about profiles or
// the profile store.
class TrayIcon : public QObject {
    Q_OBJECT
public:
    explicit TrayIcon(QWidget* mainWindow);

    void setState(ConnectionState state);
    void setProfileName(const QString& name);
    void notify(const QString& title, const QString& body);

    bool isAvailable() const;

signals:
    void connectRequested();
    void disconnectRequested();
    void showRequested();
    void quitRequested();

private:
    void rebuildMenu();

    QWidget*          m_parent = nullptr;
    QSystemTrayIcon*  m_tray   = nullptr;
    QMenu*            m_menu   = nullptr;
    QAction*          m_actConnect = nullptr;
    QAction*          m_actDisconnect = nullptr;
    QAction*          m_actShow = nullptr;
    QAction*          m_actQuit = nullptr;
    QString           m_profileName;
    ConnectionState   m_state = ConnectionState::Disconnected;
};

} // namespace inode
