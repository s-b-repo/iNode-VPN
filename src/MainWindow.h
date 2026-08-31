#pragma once

#include "core/Profile.h"
#include "core/Protocol.h"
#include <QMainWindow>
#include <memory>

class QListWidget;
class QPushButton;
class QLabel;
class QCloseEvent;

namespace inode {

class ProfileStore;
class ProfileEditor;
class LogPane;
class TrayIcon;
class ConnectionPanel;
class AutoReconnect;
class LogFile;

class MainWindow : public QMainWindow {
    Q_OBJECT
public:
    explicit MainWindow(ProfileStore* store, QWidget* parent = nullptr);
    ~MainWindow() override;

    // CLI / auto-connect helpers
    void connectByProfile(const Profile& p);
    void disconnectActive();
    bool isConnected() const;

protected:
    void closeEvent(QCloseEvent* ev) override;

private slots:
    void onAddProfile();
    void onEditProfile();
    void onRemoveProfile();
    void onImportFromInstall();
    void onConnect();
    void onDisconnect();
    void onPrimaryAction();
    void onDhcpRenew();
    void onShowSettings();
    void onStateChanged(inode::ConnectionState state);
    void onStatsUpdated(const inode::ConnectionStats& stats);
    void onListContextMenu(const QPoint& pos);
    void onDuplicateProfile();
    void refreshList();

private:
    void buildMenus();
    void applyStateToUi();
    const Profile* selectedProfile() const;
    void destroyActiveSoon();
    void persistPassword(const ProfileEditor& dlg);
    static bool isPermanentError(const QString& msg);

    QString m_lastError;   // last errorOccurred message (drives reconnect policy)

    ProfileStore*               m_store = nullptr;
    std::unique_ptr<IProtocol>  m_active;
    Profile                     m_activeProfile;

    QListWidget* m_list       = nullptr;
    QPushButton* m_btnAdd     = nullptr;
    QPushButton* m_btnEdit    = nullptr;
    QPushButton* m_btnRemove  = nullptr;
    QPushButton* m_btnImport  = nullptr;
    QPushButton* m_btnPrimary = nullptr;   // morphs Connect <-> Disconnect
    QPushButton* m_btnRenew   = nullptr;
    ConnectionPanel* m_panel  = nullptr;
    LogPane*     m_log        = nullptr;
    TrayIcon*    m_tray       = nullptr;
    AutoReconnect* m_reconnect = nullptr;
    LogFile*     m_logFile    = nullptr;
};

} // namespace inode
