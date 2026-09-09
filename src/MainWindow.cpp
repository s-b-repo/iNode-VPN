#include "MainWindow.h"

#include "core/AutoReconnect.h"
#include "core/ControlChannel.h"
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
#include <QCheckBox>
#include <QCloseEvent>
#include <QColor>
#include <QDialog>
#include <QDialogButtonBox>
#include <QFormLayout>
#include <QLineEdit>
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
#include <QTimer>
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
    // Every backend the app now supports is encrypted; only report a status
    // when there is genuinely no way to store secrets at all.
    {
        auto& cs = CredentialStore::instance();
        auto* label = new QLabel(this);
        if (!cs.isSecureBackend()) {
            label->setText(tr("⚠ Credentials cannot be saved: no keyring, and libcrypto is missing"));
            label->setStyleSheet(QStringLiteral("color: #c04040;"));
        } else {
            label->setText(tr("🔒 Credentials: %1").arg(cs.backendDescription()));
            label->setStyleSheet(QStringLiteral("color: gray;"));
        }
        statusBar()->addPermanentWidget(label);
    }

    // Control socket for `iNodeClient-Qt --status / --disconnect / --connect`
    // issued from another terminal while this instance runs.
    m_control = new ControlServer([this](const QString& cmd) {
        return handleControlCommand(cmd);
    }, this);
    m_control->listen();

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
        // TLS / trust
        "certificate", "pin mismatch",
        // credentials / gateway verdicts
        "authentication failed", "auth rejected", "login rejected",
        "posture rejected", "check username", "captcha",
        // profile problems — retrying cannot fix these
        "no stored password", "username is required", "is required",
        "requires", "no gateway", "no interface", "not implemented",
        "unsupported", "not supported",
        // missing pieces / privileges
        "not found", "not installed", "need root", "needs root",
        "could not gain privileges", "is not available",
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
    auto& cs = CredentialStore::instance();
    if (saved.savePassword) {
        if (dlg.password().isEmpty()) return;
        if (cs.store(saved.id, dlg.password())) return;
        // Storing failed (keyring locked/refused, no backend). Don't lose what
        // the user typed: keep it for this session and say so.
        cs.setSessionSecret(saved.id, dlg.password());
        QMessageBox::warning(this, tr("Password not saved"),
            tr("The password could not be stored in %1.\n\n"
               "It will be used for this session only; you will be asked for it "
               "again next time. Run 'iNodeClient-Qt --doctor' to check the "
               "credential backends.").arg(cs.backendDescription()));
    } else {
        cs.forget(saved.id);
        // Not stored — but if the user typed one just now, use it for this
        // session instead of failing the very next Connect.
        if (!dlg.password().isEmpty()) cs.setSessionSecret(saved.id, dlg.password());
    }
}

QString MainWindow::handleControlCommand(const QString& command) {
    const QString cmd = command.section(QLatin1Char(' '), 0, 0);
    const QString arg = command.section(QLatin1Char(' '), 1).trimmed();
    if (cmd == QLatin1String("status")) {
        if (!m_active) return QStringLiteral("disconnected");
        const QString state = stateName(m_active->state()).toLower();
        const auto stats = m_active->stats();
        QString line = state + QLatin1Char('\t') + m_activeProfile.name;
        if (m_active->state() == ConnectionState::Connected && !stats.iface.isEmpty())
            line += QLatin1Char('\t') + stats.iface
                  + (stats.localIp.isEmpty() ? QString() : QLatin1Char(' ') + stats.localIp);
        return line;
    }
    if (cmd == QLatin1String("disconnect")) {
        if (!m_active || m_active->state() == ConnectionState::Disconnected)
            return QStringLiteral("not connected");
        Logger::instance().info(tr("disconnect requested from the command line"));
        disconnectActive();
        return QStringLiteral("disconnecting %1").arg(m_activeProfile.name);
    }
    if (cmd == QLatin1String("connect")) {
        const auto* p = m_store->findByName(arg);
        if (!p) return QStringLiteral("error: no profile named '%1'").arg(arg);
        if (m_active && m_active->state() == ConnectionState::Connected)
            return QStringLiteral("error: already connected to %1 — disconnect first")
                       .arg(m_activeProfile.name);
        Logger::instance().info(tr("connect '%1' requested from the command line").arg(p->name));
        const Profile copy = *p;
        QTimer::singleShot(0, this, [this, copy] { connectByProfile(copy); });
        return QStringLiteral("connecting %1").arg(copy.name);
    }
    if (cmd == QLatin1String("show")) {
        showNormal(); raise(); activateWindow();
        return QStringLiteral("ok");
    }
    return QStringLiteral("error: unknown command '%1'").arg(cmd);
}

bool MainWindow::ensurePasswordAvailable(const Profile& p) {
    switch (p.kind) {
        case ProtocolKind::SslVpn:
        case ProtocolKind::Dot1x:
        case ProtocolKind::Portal:
        case ProtocolKind::L2tpIpsec:
            break;                       // these refuse to start without one
        default:
            return true;                 // WLAN (open networks), EAD, SDP: optional
    }
    auto& cs = CredentialStore::instance();
    QString existing;
    if (cs.retrieve(p.id, &existing) && !existing.isEmpty()) return true;

    // Nothing stored: ask now instead of failing with
    // "No stored password for profile."
    QDialog dlg(this);
    dlg.setWindowTitle(tr("Password for '%1'").arg(p.name));
    auto* form = new QFormLayout(&dlg);
    auto* info = new QLabel(tr("No password is stored for this profile.\n"
                               "Enter it to connect%1.")
                                .arg(p.username.isEmpty() ? QString()
                                                          : tr(" as %1").arg(p.username)), &dlg);
    info->setWordWrap(true);
    form->addRow(info);
    auto* edit = new QLineEdit(&dlg);
    edit->setEchoMode(QLineEdit::Password);
    form->addRow(tr("Password:"), edit);
    auto* remember = new QCheckBox(tr("Remember (encrypted in %1)").arg(cs.backendDescription()), &dlg);
    remember->setEnabled(cs.isSecureBackend());
    remember->setChecked(cs.isSecureBackend());
    form->addRow(QString(), remember);
    auto* buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, &dlg);
    buttons->button(QDialogButtonBox::Ok)->setText(tr("Connect"));
    buttons->button(QDialogButtonBox::Ok)->setEnabled(false);
    connect(edit, &QLineEdit::textChanged, buttons, [buttons](const QString& t) {
        buttons->button(QDialogButtonBox::Ok)->setEnabled(!t.isEmpty());
    });
    connect(buttons, &QDialogButtonBox::accepted, &dlg, &QDialog::accept);
    connect(buttons, &QDialogButtonBox::rejected, &dlg, &QDialog::reject);
    form->addRow(buttons);
    edit->setFocus();

    if (dlg.exec() != QDialog::Accepted || edit->text().isEmpty()) {
        Logger::instance().info(tr("connect cancelled — no password entered for '%1'").arg(p.name));
        return false;
    }

    const QString pw = edit->text();
    if (remember->isChecked() && cs.store(p.id, pw)) {
        // Reflect the choice in the profile so the editor shows it ticked.
        if (auto* stored = m_store->find(p.id); stored && !stored->savePassword) {
            Profile updated = *stored;
            updated.savePassword = true;
            m_store->upsert(updated);
        }
    } else {
        if (remember->isChecked())
            Logger::instance().warn(tr("could not store the password in %1 — using it for this session only")
                                        .arg(cs.backendDescription()));
        cs.setSessionSecret(p.id, pw);
    }
    return true;
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

    // Ask for a missing password up front (modal), before any protocol object
    // or reconnect timer exists, so a cancel is a clean no-op.
    if (!ensurePasswordAvailable(p)) return;

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
    // Asynchronous: dhclient release+bind can take up to ~30 s and a pkexec
    // prompt may appear — none of that may block the GUI thread.
    dhcp::renewAsync(iface, [this, iface](bool ok) {
        if (!ok)
            QMessageBox::warning(this, tr("Renew DHCP"),
                tr("DHCP renew on %1 could not be started.").arg(iface));
    });
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
    // Destroy only the object that reported the terminal state. A queued
    // reset racing a fresh connectByProfile() (e.g. Portal emits Disconnected
    // ~1 s after the click, right as a new connect starts) must not tear down
    // the NEW session object.
    auto* stale = m_active.get();
    QMetaObject::invokeMethod(this, [this, stale] {
        if (m_active.get() == stale) m_active.reset();
    }, Qt::QueuedConnection);
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
