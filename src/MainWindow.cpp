#include "MainWindow.h"

#include "core/AutoReconnect.h"
#include "core/CredentialStore.h"
#include "core/CustomXmlImporter.h"
#include "core/Dhcp.h"
#include "core/LogFile.h"
#include "core/Logger.h"
#include "core/ProfileStore.h"
#include "core/ProtocolFactory.h"
#include "core/Settings.h"
#include "ui/ConnectionPanel.h"
#include "ui/LogPane.h"
#include "ui/ProfileEditor.h"
#include "ui/ProfileListDelegate.h"
#include "ui/SettingsDialog.h"
#include "ui/TrayIcon.h"

#include <QAction>
#include <QApplication>
#include <QCloseEvent>
#include <QColor>
#include <QFileDialog>
#include <QFont>
#include <QHBoxLayout>
#include <QIcon>
#include <QLabel>
#include <QListWidget>
#include <QListWidgetItem>
#include <QMenu>
#include <QMenuBar>
#include <QMessageBox>
#include <QPushButton>
#include <QShortcut>
#include <QSplitter>
#include <QStatusBar>
#include <QStyle>
#include <QVBoxLayout>

namespace inode {

MainWindow::MainWindow(ProfileStore* store, QWidget* parent)
    : QMainWindow(parent), m_store(store) {
    setWindowTitle(tr("iNode Client — Qt Edition"));
    resize(960, 640);

    buildMenus();

    // Central widget
    auto* root = new QWidget(this);
    auto* rootLayout = new QVBoxLayout(root);

    // Connection panel: status + (when connected) IP/gateway/uptime/throughput.
    m_panel = new ConnectionPanel(root);
    rootLayout->addWidget(m_panel);

    auto* splitter = new QSplitter(Qt::Vertical, root);
    rootLayout->addWidget(splitter, 1);

    // Top: profile list + buttons
    auto* top = new QWidget(splitter);
    auto* topLayout = new QHBoxLayout(top);

    m_list = new QListWidget(top);
    m_list->setContextMenuPolicy(Qt::CustomContextMenu);
    m_list->setItemDelegate(new ProfileListDelegate(m_list));
    m_list->setSelectionMode(QAbstractItemView::SingleSelection);
    topLayout->addWidget(m_list, 1);

    auto* btns = new QVBoxLayout;
    m_btnAdd     = new QPushButton(tr("Add…"), top);
    m_btnEdit    = new QPushButton(tr("Edit…"), top);
    m_btnRemove  = new QPushButton(tr("Remove"), top);
    m_btnImport  = new QPushButton(tr("Import…"), top);
    m_btnPrimary = new QPushButton(tr("Connect"), top);   // morphs to Disconnect
    m_btnPrimary->setObjectName(QStringLiteral("ctaConnect"));
    m_btnRenew   = new QPushButton(tr("Renew DHCP"), top);

    btns->addWidget(m_btnAdd);
    btns->addWidget(m_btnEdit);
    btns->addWidget(m_btnRemove);
    btns->addWidget(m_btnImport);
    btns->addSpacing(20);
    btns->addWidget(m_btnPrimary);
    btns->addSpacing(20);
    btns->addWidget(m_btnRenew);
    btns->addStretch();
    topLayout->addLayout(btns);

    splitter->addWidget(top);

    // Bottom: log pane
    m_log = new LogPane(splitter);
    splitter->addWidget(m_log);
    splitter->setStretchFactor(0, 3);
    splitter->setStretchFactor(1, 2);

    setCentralWidget(root);

    // Status bar (the connection panel above shows live state/stats now).
    if (!CredentialStore::instance().isSecureBackend()) {
        auto* warn = new QLabel(tr("⚠ Credentials in fallback storage (install kwallet for secure storage)"), this);
        warn->setStyleSheet(QStringLiteral("color: #c0a000;"));
        statusBar()->addPermanentWidget(warn);
    }

    // Optional file logger
    m_logFile = new LogFile(this);
    m_logFile->setPath(Settings::instance().logFilePath());
    m_logFile->setMaxBytes(Settings::instance().logMaxBytes());
    m_logFile->setEnabled(Settings::instance().logToFile());
    connect(&Logger::instance(), &Logger::line, m_logFile, &LogFile::append);

    // Tray
    m_tray = new TrayIcon(this);
    if (m_tray->isAvailable()) {
        connect(m_tray, &TrayIcon::connectRequested,    this, &MainWindow::onConnect);
        connect(m_tray, &TrayIcon::disconnectRequested, this, &MainWindow::onDisconnect);
        connect(m_tray, &TrayIcon::showRequested, this, [this] {
            showNormal(); raise(); activateWindow();
        });
        connect(m_tray, &TrayIcon::quitRequested, qApp, &QCoreApplication::quit);
    }

    // Auto-reconnect orchestrator
    m_reconnect = new AutoReconnect(this);
    connect(m_reconnect, &AutoReconnect::retry, this, [this] {
        if (!m_activeProfile.id.isNull()) {
            Logger::instance().info(tr("auto-reconnect: attempting %1").arg(m_activeProfile.name));
            connectByProfile(m_activeProfile);
        }
    });

    // Signals
    connect(m_btnAdd,    &QPushButton::clicked, this, &MainWindow::onAddProfile);
    connect(m_btnEdit,   &QPushButton::clicked, this, &MainWindow::onEditProfile);
    connect(m_btnRemove, &QPushButton::clicked, this, &MainWindow::onRemoveProfile);
    connect(m_btnImport, &QPushButton::clicked, this, &MainWindow::onImportFromInstall);
    connect(m_btnPrimary, &QPushButton::clicked, this, &MainWindow::onPrimaryAction);
    connect(m_btnRenew, &QPushButton::clicked, this, &MainWindow::onDhcpRenew);
    connect(m_list, &QListWidget::itemDoubleClicked, this, &MainWindow::onEditProfile);
    connect(m_list, &QListWidget::customContextMenuRequested, this, &MainWindow::onListContextMenu);

    // Keyboard shortcuts on the profile list: Enter = connect, Delete = remove.
    auto* scConnect = new QShortcut(QKeySequence(Qt::Key_Return), m_list);
    scConnect->setContext(Qt::WidgetShortcut);
    connect(scConnect, &QShortcut::activated, this, &MainWindow::onConnect);
    auto* scEnter = new QShortcut(QKeySequence(Qt::Key_Enter), m_list);
    scEnter->setContext(Qt::WidgetShortcut);
    connect(scEnter, &QShortcut::activated, this, &MainWindow::onConnect);
    auto* scRemove = new QShortcut(QKeySequence(Qt::Key_Delete), m_list);
    scRemove->setContext(Qt::WidgetShortcut);
    connect(scRemove, &QShortcut::activated, this, &MainWindow::onRemoveProfile);

    connect(m_store, &ProfileStore::changed, this, &MainWindow::refreshList);
    connect(&Logger::instance(), &Logger::line, m_log, &LogPane::appendLine);

    refreshList();
    applyStateToUi();
}

MainWindow::~MainWindow() = default;

void MainWindow::buildMenus() {
    auto* fileMenu = menuBar()->addMenu(tr("&File"));
    fileMenu->addAction(tr("&Import from iNode install…"), this, &MainWindow::onImportFromInstall);
    fileMenu->addSeparator();
    fileMenu->addAction(tr("&Preferences…"), QKeySequence::Preferences, this, &MainWindow::onShowSettings);
    fileMenu->addSeparator();
    fileMenu->addAction(tr("&Quit"), QKeySequence::Quit, qApp, &QCoreApplication::quit);

    auto* connMenu = menuBar()->addMenu(tr("&Connection"));
    connMenu->addAction(tr("&Connect"),    this, &MainWindow::onConnect);
    connMenu->addAction(tr("&Disconnect"), this, &MainWindow::onDisconnect);
    connMenu->addSeparator();
    connMenu->addAction(tr("Renew DHCP on interface…"), this, &MainWindow::onDhcpRenew);

    auto* helpMenu = menuBar()->addMenu(tr("&Help"));
    helpMenu->addAction(tr("&About"), this, [this] {
        QMessageBox::about(this, tr("About iNode Client Qt"),
            tr("<h3>iNode Client — Qt Edition</h3>"
               "<p>Open-source Qt6/KF6 reimplementation of the H3C iNode "
               "authentication client. Feature-compatible with the original "
               "for the protocols it supports, without the posture-agent / "
               "DLP / DAM baggage.</p>"
               "<p><b>Working:</b> 802.1X (minieap/mentohust), L2TP/IPSec, "
               "WLAN enterprise, Portal v2 (standard), SSL VPN (H3C, via the "
               "bundled h3csvpn backend).<br>"
               "<b>Experimental:</b> H3C Portal TLV dialect, SDP (SSL VPN + SPA "
               "knock), EAD host-check ack.<br>"
               "<b>Not yet built (feasible):</b> standalone iMC EAD posture — "
               "reverse-engineered as forgeable (hardcoded keyed-MD5 + static "
               "XTEA, both recovered); needs the SEC schema/state-machine.</p>"
               "<p>See the project README for the full protocol matrix.</p>"));
    });
}

// One-line detail for a profile (username / server), shown under the name.
static QString profileDetail(const Profile& p) {
    QString who = p.username;
    if (!p.domain.isEmpty()) who += QStringLiteral("@%1").arg(p.domain);
    QString where = p.serverHost.isEmpty() ? p.sslvpnUrl : p.serverHost;
    if (where.isEmpty() && p.kind == ProtocolKind::Dot1x) where = p.iface;
    QStringList bits;
    if (!who.isEmpty())   bits << who;
    if (!where.isEmpty()) bits << where;
    return bits.join(QStringLiteral("  ·  "));
}

void MainWindow::refreshList() {
    QUuid selectedId;
    if (auto* it = m_list->currentItem())
        selectedId = it->data(ProfileListDelegate::IdRole).toUuid();

    m_list->clear();

    if (m_store->profiles().isEmpty()) {
        auto* hint = new QListWidgetItem(
            tr("No profiles yet — click “Add…” to create one."));
        hint->setFlags(Qt::NoItemFlags);
        m_list->addItem(hint);
        return;
    }

    int activeState = 0;   // 0 none, 1 connected, 2 connecting, 3 failed
    if (m_active) {
        switch (m_active->state()) {
            case ConnectionState::Connected:      activeState = 1; break;
            case ConnectionState::Connecting:
            case ConnectionState::Authenticating: activeState = 2; break;
            case ConnectionState::Failed:         activeState = 3; break;
            default:                              activeState = 0; break;
        }
    }

    for (const auto& p : m_store->profiles()) {
        const QString name = p.name.isEmpty() ? tr("(unnamed)") : p.name;
        const QString detail = profileDetail(p);
        const bool isActive = activeState != 0 && p.id == m_activeProfile.id;

        auto* item = new QListWidgetItem;
        item->setData(ProfileListDelegate::IdRole,       p.id);
        item->setData(ProfileListDelegate::NameRole,     name);
        item->setData(ProfileListDelegate::SubtitleRole, detail);
        item->setData(ProfileListDelegate::ProtocolRole, protocolName(p.kind));
        item->setData(ProfileListDelegate::StateRole,    isActive ? activeState : 0);
        item->setToolTip(detail.isEmpty() ? protocolName(p.kind)
                                          : QStringLiteral("%1 — %2").arg(protocolName(p.kind), detail));
        m_list->addItem(item);
        if (p.id == selectedId) m_list->setCurrentItem(item);
    }
    if (m_list->currentRow() < 0 && m_list->count() > 0)
        m_list->setCurrentRow(0);
}

bool MainWindow::isPermanentError(const QString& msg) {
    static const char* kPermanent[] = {
        "certificate", "pin mismatch", "authentication failed", "captcha",
        "no stored password", "username is required", "no gateway",
        "not implemented", "unsupported", "is required",
    };
    const QString m = msg.toLower();
    for (const char* k : kPermanent)
        if (m.contains(QLatin1String(k))) return true;
    return false;
}

void MainWindow::onListContextMenu(const QPoint& pos) {
    auto* item = m_list->itemAt(pos);
    if (item && (item->flags() & Qt::ItemIsSelectable))
        m_list->setCurrentItem(item);
    const bool haveSel = selectedProfile() != nullptr;
    const bool busy = m_active && m_active->state() != ConnectionState::Disconnected
                                 && m_active->state() != ConnectionState::Failed;

    QMenu menu(this);
    QAction* aConnect = menu.addAction(tr("Connect"));
    aConnect->setEnabled(haveSel && !busy);
    QAction* aDisconnect = menu.addAction(tr("Disconnect"));
    aDisconnect->setEnabled(busy);
    menu.addSeparator();
    QAction* aEdit = menu.addAction(tr("Edit…"));
    aEdit->setEnabled(haveSel && !busy);
    QAction* aDup = menu.addAction(tr("Duplicate"));
    aDup->setEnabled(haveSel);
    QAction* aRemove = menu.addAction(tr("Remove"));
    aRemove->setEnabled(haveSel && !busy);

    QAction* chosen = menu.exec(m_list->viewport()->mapToGlobal(pos));
    if (chosen == aConnect)         onConnect();
    else if (chosen == aDisconnect) onDisconnect();
    else if (chosen == aEdit)       onEditProfile();
    else if (chosen == aDup)        onDuplicateProfile();
    else if (chosen == aRemove)     onRemoveProfile();
}

void MainWindow::onDuplicateProfile() {
    auto* p = selectedProfile();
    if (!p) return;
    Profile copy = *p;
    copy.id = QUuid::createUuid();
    copy.name = tr("%1 (copy)").arg(p->name);
    copy.autoConnect = false;          // don't auto-launch a duplicate
    m_store->upsert(copy);             // credentials are intentionally not copied
}

const Profile* MainWindow::selectedProfile() const {
    auto* it = m_list->currentItem();
    if (!it) return nullptr;
    return m_store->find(it->data(Qt::UserRole).toUuid());
}

void MainWindow::onAddProfile() {
    Profile p = Profile::makeNew();
    p.name = tr("New profile");
    ProfileEditor dlg(p, this);
    if (dlg.exec() == QDialog::Accepted) {
        m_store->upsert(dlg.profile());
        persistPassword(dlg);
    }
}

void MainWindow::onEditProfile() {
    auto* p = selectedProfile();
    if (!p) return;
    ProfileEditor dlg(*p, this);
    if (dlg.exec() == QDialog::Accepted) {
        m_store->upsert(dlg.profile());
        persistPassword(dlg);
    }
}

void MainWindow::persistPassword(const ProfileEditor& dlg) {
    // Honor the "Store password" checkbox. When it is off, make sure nothing is
    // left behind in the credential store. When it is on, only overwrite if the
    // user actually typed something (an empty field on edit means "unchanged").
    const Profile saved = dlg.profile();
    if (saved.savePassword) {
        if (!dlg.password().isEmpty())
            CredentialStore::instance().store(saved.id, dlg.password());
    } else {
        CredentialStore::instance().forget(saved.id);
    }
}

void MainWindow::onRemoveProfile() {
    auto* p = selectedProfile();
    if (!p) return;
    if (QMessageBox::question(this, tr("Remove profile"),
                              tr("Remove profile '%1'?").arg(p->name)) != QMessageBox::Yes)
        return;
    CredentialStore::instance().forget(p->id);
    m_store->remove(p->id);
}

void MainWindow::onImportFromInstall() {
    const QString dir = QFileDialog::getExistingDirectory(
        this, tr("Select iNode install directory"),
        QStringLiteral("/opt/apps/com.client.inode.amd/files"));
    if (dir.isEmpty()) return;
    const auto imported = CustomXmlImporter::importFromInstall(dir);
    if (imported.isEmpty()) {
        QMessageBox::information(this, tr("Import"),
                                 tr("No profiles were imported from %1.").arg(dir));
        return;
    }
    for (const auto& p : imported) m_store->upsert(p);
    QMessageBox::information(this, tr("Import"),
                             tr("Imported %1 profile(s). Edit each to set credentials.").arg(imported.size()));
}

void MainWindow::onConnect() {
    if (m_active && m_active->state() == ConnectionState::Connected) {
        QMessageBox::information(this, tr("Already connected"),
                                 tr("Disconnect the current session first."));
        return;
    }
    auto* p = selectedProfile();
    if (!p) return;
    connectByProfile(*p);
}

void MainWindow::connectByProfile(const Profile& p) {
    if (m_active && m_active->state() == ConnectionState::Connected) return;

    m_active = ProtocolFactory::create(p.kind, this);
    if (!m_active) {
        QMessageBox::warning(this, tr("Unsupported"),
                             tr("Protocol %1 is not handled by this build.")
                                 .arg(protocolName(p.kind)));
        return;
    }

    m_activeProfile = p;
    m_lastError.clear();
    m_reconnect->armFor(p);

    if (!m_active->isImplemented()) {
        Logger::instance().warn(
            tr("Protocol %1 is a stub — expect a friendly error.").arg(protocolName(p.kind)));
    }

    connect(m_active.get(), &IProtocol::stateChanged, this, &MainWindow::onStateChanged);
    connect(m_active.get(), &IProtocol::statsUpdated, this, &MainWindow::onStatsUpdated);
    connect(m_active.get(), &IProtocol::logLine, &Logger::instance(), &Logger::info);
    connect(m_active.get(), &IProtocol::errorOccurred, this, [this](const QString& msg) {
        m_lastError = msg;   // remembered so onStateChanged can pick a reconnect policy
        Logger::instance().error(msg);
        if (m_tray && Settings::instance().notifyOnStateChange())
            m_tray->notify(tr("iNode: connection error"), msg);
        else
            QMessageBox::warning(this, tr("Connection error"), msg);
    });

    if (m_tray) m_tray->setProfileName(p.name);

    Logger::instance().info(tr("connecting profile '%1' (%2)").arg(p.name, protocolName(p.kind)));
    m_active->connectWith(p);
}

void MainWindow::onDisconnect() { disconnectActive(); }

void MainWindow::disconnectActive() {
    m_reconnect->cancel();
    if (m_active) m_active->disconnect();
}

bool MainWindow::isConnected() const {
    return m_active && m_active->state() == ConnectionState::Connected;
}

void MainWindow::onDhcpRenew() {
    auto* p = selectedProfile();
    QString iface = p ? p->iface : QString();
    if (iface.isEmpty() && m_active) iface = m_active->stats().iface;
    if (iface.isEmpty()) {
        QMessageBox::information(this, tr("Renew DHCP"),
            tr("Select a profile with a configured interface, or connect first."));
        return;
    }
    Logger::instance().info(tr("DHCP renew requested on %1").arg(iface));
    dhcp::renew(iface);
}

void MainWindow::onShowSettings() {
    SettingsDialog dlg(this);
    if (dlg.exec() == QDialog::Accepted) {
        // Re-apply log-to-file in case it changed
        m_logFile->setEnabled(Settings::instance().logToFile());
    }
}

void MainWindow::onPrimaryAction() {
    const bool busy = m_active && m_active->state() != ConnectionState::Disconnected
                                 && m_active->state() != ConnectionState::Failed;
    if (busy) onDisconnect();
    else      onConnect();
}

void MainWindow::onStateChanged(ConnectionState state) {
    m_panel->setState(state, m_activeProfile.name);
    refreshList();        // reflect the active-connection marker on the list
    applyStateToUi();

    if (m_tray) m_tray->setState(state);
    if (m_tray && Settings::instance().notifyOnStateChange()) {
        switch (state) {
            case ConnectionState::Connected:
                m_tray->notify(tr("iNode connected"),
                               tr("Profile '%1' is up.").arg(m_activeProfile.name));
                break;
            case ConnectionState::Failed:
                m_tray->notify(tr("iNode failed"),
                               tr("Profile '%1' failed to connect.").arg(m_activeProfile.name));
                break;
            case ConnectionState::Disconnected:
                m_tray->notify(tr("iNode disconnected"),
                               tr("Profile '%1' is down.").arg(m_activeProfile.name));
                break;
            default: break;
        }
    }

    if (state == ConnectionState::Connected) {
        m_reconnect->noteSuccess();
    } else if (state == ConnectionState::Failed) {
        // Don't hammer the gateway retrying a failure that won't fix itself
        // (bad cert, wrong credentials, exhausted CAPTCHA, unsupported protocol).
        if (isPermanentError(m_lastError)) {
            Logger::instance().warn(
                tr("not auto-reconnecting — this looks like a permanent error: %1")
                    .arg(m_lastError));
            m_reconnect->cancel();
        } else {
            m_reconnect->noteFailure();
        }
        destroyActiveSoon();
    } else if (state == ConnectionState::Disconnected) {
        // If the user explicitly disconnected m_reconnect was already cancelled.
        // If it drops mid-session, rearm.
        if (m_reconnect->isArmed()) m_reconnect->noteFailure();
        destroyActiveSoon();
    }
}

void MainWindow::destroyActiveSoon() {
    QMetaObject::invokeMethod(this, [this] { m_active.reset(); }, Qt::QueuedConnection);
}

void MainWindow::onStatsUpdated(const ConnectionStats& stats) {
    m_panel->updateStats(stats);
}

void MainWindow::applyStateToUi() {
    const bool busy = m_active && m_active->state() != ConnectionState::Disconnected
                                 && m_active->state() != ConnectionState::Failed;
    // Single primary button morphs Connect (green) <-> Disconnect (red).
    m_btnPrimary->setText(busy ? tr("Disconnect") : tr("Connect"));
    m_btnPrimary->setObjectName(busy ? QStringLiteral("ctaDisconnect")
                                     : QStringLiteral("ctaConnect"));
    m_btnPrimary->style()->unpolish(m_btnPrimary);
    m_btnPrimary->style()->polish(m_btnPrimary);
    m_btnPrimary->setEnabled(true);
    m_btnEdit->setEnabled(!busy);
    m_btnRemove->setEnabled(!busy);
}

void MainWindow::closeEvent(QCloseEvent* ev) {
    if (m_tray && m_tray->isAvailable() && Settings::instance().minimizeToTray()) {
        hide();
        ev->ignore();
        return;
    }
    QMainWindow::closeEvent(ev);
}

} // namespace inode
