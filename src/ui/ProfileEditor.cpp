#include "ProfileEditor.h"

#include "core/InterfaceDiscovery.h"

#include <QCheckBox>
#include <QComboBox>
#include <QDialogButtonBox>
#include <QFileDialog>
#include <QFormLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QProcess>
#include <QPushButton>
#include <QSpinBox>
#include <QStackedWidget>
#include <QTabWidget>
#include <QToolButton>
#include <QUrl>
#include <QVBoxLayout>

namespace inode {

ProfileEditor::ProfileEditor(const Profile& initial, QWidget* parent)
    : QDialog(parent), m_profile(initial) {
    setWindowTitle(tr("Connection profile"));
    setModal(true);
    buildUi();
    loadFromProfile();
    onKindChanged(m_kind->currentIndex());
    resize(560, 620);
}

QString ProfileEditor::password() const {
    return m_password ? m_password->text() : QString();
}

static QWidget* makeFilePicker(QLineEdit*& edit, QWidget* parent) {
    auto* w = new QWidget(parent);
    auto* h = new QHBoxLayout(w);
    h->setContentsMargins(0, 0, 0, 0);
    edit = new QLineEdit(w);
    auto* btn = new QPushButton(QStringLiteral("…"), w);
    btn->setFixedWidth(32);
    h->addWidget(edit, 1);
    h->addWidget(btn);
    QObject::connect(btn, &QPushButton::clicked, edit, [edit, parent] {
        const QString p = QFileDialog::getOpenFileName(parent, QObject::tr("Pick file"));
        if (!p.isEmpty()) edit->setText(p);
    });
    return w;
}

void ProfileEditor::buildUi() {
    auto* root = new QVBoxLayout(this);
    m_tabs = new QTabWidget(this);
    root->addWidget(m_tabs, 1);

    // ============== Tab: General ==============
    {
        auto* w = new QWidget(this);
        auto* form = new QFormLayout(w);

        m_name = new QLineEdit(w);

        m_kind = new QComboBox(w);
        m_kind->addItem(tr("802.1X (wired)"),        int(ProtocolKind::Dot1x));
        m_kind->addItem(tr("WLAN (wireless 802.1X)"), int(ProtocolKind::Wlan));
        m_kind->addItem(tr("Portal"),                 int(ProtocolKind::Portal));
        m_kind->addItem(tr("L2TP / IPSec"),           int(ProtocolKind::L2tpIpsec));
        m_kind->addItem(tr("SSL VPN"),                int(ProtocolKind::SslVpn));
        m_kind->addItem(tr("SDP (SSL VPN + SPA knock)"), int(ProtocolKind::Sdp));
        m_kind->addItem(tr("EAD (stub)"),             int(ProtocolKind::Ead));

        m_username    = new QLineEdit(w);
        m_domain      = new QLineEdit(w);
        m_domain->setPlaceholderText(tr("optional — appended as user@domain"));
        m_serviceName = new QLineEdit(w);
        m_serviceName->setPlaceholderText(tr("optional — H3C 'service' field"));
        m_password    = new QLineEdit(w);
        m_password->setEchoMode(QLineEdit::Password);
        m_password->setPlaceholderText(tr("(unchanged)"));

        m_save          = new QCheckBox(tr("Store password (encrypted in KWallet when available)"), w);
        m_auto          = new QCheckBox(tr("Connect automatically on startup"), w);
        m_autoReconnect = new QCheckBox(tr("Reconnect automatically on disconnect"), w);

        // Password with a show/hide toggle.
        auto* pwRow = new QWidget(w);
        auto* pwLay = new QHBoxLayout(pwRow);
        pwLay->setContentsMargins(0, 0, 0, 0);
        auto* pwShow = new QToolButton(pwRow);
        pwShow->setText(tr("Show"));
        pwShow->setCheckable(true);
        pwShow->setToolTip(tr("Show or hide the password"));
        QObject::connect(pwShow, &QToolButton::toggled, m_password, [this, pwShow](bool on) {
            m_password->setEchoMode(on ? QLineEdit::Normal : QLineEdit::Password);
            pwShow->setText(on ? tr("Hide") : tr("Show"));
        });
        pwLay->addWidget(m_password, 1);
        pwLay->addWidget(pwShow);

        form->addRow(tr("Name:"),     m_name);
        form->addRow(tr("Protocol:"), m_kind);
        form->addRow(tr("Username:"), m_username);
        form->addRow(tr("Domain:"),   m_domain);
        form->addRow(tr("Service:"),  m_serviceName);
        form->addRow(tr("Password:"), pwRow);
        form->addRow(QString(),       m_save);
        form->addRow(QString(),       m_auto);
        form->addRow(QString(),       m_autoReconnect);

        m_tabs->addTab(w, tr("General"));
    }

    // ============== Tab: Protocol ==============
    {
        auto* w = new QWidget(this);
        auto* vbox = new QVBoxLayout(w);

        m_protoStack = new QStackedWidget(w);
        vbox->addWidget(m_protoStack, 1);

        // --- Dot1x page ---
        {
            auto* pg = new QWidget;
            auto* f = new QFormLayout(pg);
            m_iface = new QComboBox(pg);
            m_iface->setEditable(true);
            m_authMode = new QComboBox(pg);
            m_authMode->addItem(tr("Auto"),         int(AuthMode::Auto));
            m_authMode->addItem(QStringLiteral("PAP"),      int(AuthMode::Pap));
            m_authMode->addItem(QStringLiteral("CHAP"),     int(AuthMode::Chap));
            m_authMode->addItem(QStringLiteral("MSCHAPv2"), int(AuthMode::MsChapV2));
            m_authMode->addItem(QStringLiteral("EAP-MD5"),  int(AuthMode::EapMd5));
            m_authMode->addItem(QStringLiteral("EAP-PEAP"), int(AuthMode::EapPeap));
            m_authMode->addItem(QStringLiteral("HC-CHAPv2 (H3C)"), int(AuthMode::HcChapV2));

            m_useRjv3    = new QCheckBox(tr("Use rjv3 module (H3C / Ruijie)"), pg);
            m_rjvService = new QSpinBox(pg);
            m_rjvService->setRange(0, 255);
            m_rjvCarrier = new QLineEdit(pg);
            m_dot1xExtra = new QLineEdit(pg);
            m_dot1xExtra->setPlaceholderText(tr("extra minieap/mentohust CLI args"));

            f->addRow(tr("Interface:"),  m_iface);
            f->addRow(tr("Auth mode:"),  m_authMode);
            f->addRow(QString(),         m_useRjv3);
            f->addRow(tr("rjv3 service type:"), m_rjvService);
            f->addRow(tr("rjv3 carrier:"),      m_rjvCarrier);
            f->addRow(tr("Extra args:"), m_dot1xExtra);
            m_protoStack->addWidget(pg);
        }

        // --- WLAN page ---
        {
            auto* pg = new QWidget;
            auto* f = new QFormLayout(pg);
            m_wlanSsid = new QLineEdit(pg);
            m_wlanHidden = new QCheckBox(tr("Hidden SSID"), pg);
            auto* hint = new QLabel(tr(
                "Interface, auth mode, rjv3 options etc. are taken from the "
                "802.1X page — switch protocol to edit them."), pg);
            hint->setWordWrap(true);
            hint->setStyleSheet(QStringLiteral("color: gray;"));
            f->addRow(tr("SSID:"),       m_wlanSsid);
            f->addRow(QString(),         m_wlanHidden);
            f->addRow(hint);
            m_protoStack->addWidget(pg);
        }

        // --- Portal page ---
        {
            auto* pg = new QWidget;
            auto* f = new QFormLayout(pg);
            m_portalHost = new QLineEdit(pg);
            m_portalPort = new QSpinBox(pg);
            m_portalPort->setRange(1, 65535);
            m_portalPort->setValue(2000);
            m_portalSecret = new QLineEdit(pg);
            m_portalSecret->setPlaceholderText(tr("shared secret (often 'h3c' or 'huawei3com')"));
            m_portalDialect = new QComboBox(pg);
            m_portalDialect->addItem(tr("Portal v2 (standard GB/T)"),  0);
            m_portalDialect->addItem(tr("H3C TLV (experimental)"),      1);
            f->addRow(tr("Server:"),  m_portalHost);
            f->addRow(tr("Port:"),    m_portalPort);
            f->addRow(tr("Secret:"),  m_portalSecret);
            f->addRow(tr("Dialect:"), m_portalDialect);
            m_protoStack->addWidget(pg);
        }

        // --- L2TP page ---
        {
            auto* pg = new QWidget;
            auto* f = new QFormLayout(pg);
            m_l2tpHost = new QLineEdit(pg);
            m_l2tpPsk  = new QLineEdit(pg);
            m_l2tpPsk->setEchoMode(QLineEdit::Password);
            m_l2tpForceEncap = new QCheckBox(tr("Force UDP NAT-T encapsulation"), pg);
            f->addRow(tr("Server:"),         m_l2tpHost);
            f->addRow(tr("Pre-shared key:"), m_l2tpPsk);
            f->addRow(QString(),             m_l2tpForceEncap);
            m_protoStack->addWidget(pg);
        }

        // --- SSL VPN page ---
        {
            auto* pg = new QWidget;
            auto* f = new QFormLayout(pg);
            m_sslvpnUrl = new QLineEdit(pg);
            m_sslvpnUrl->setPlaceholderText(QStringLiteral("https://svpn.example.com:3000"));
            m_sslvpnSplit = new QCheckBox(
                tr("Split tunnel — route only the gateway's networks; keep "
                   "internet traffic direct (recommended for enterprise)"), pg);
            m_sslvpnSplit->setChecked(true);

            // Certificate pin (SHA-256) + a one-click fetch from the gateway.
            // The secure way to trust a self-signed gateway whose cert CN does
            // not match the host (a CA bundle can't validate those).
            m_sslvpnPin = new QLineEdit(pg);
            m_sslvpnPin->setPlaceholderText(
                tr("AA:BB:… — pin the self-signed gateway cert (leave blank to use Trust mode)"));
            auto* pinRow = new QWidget(pg);
            auto* pinLay = new QHBoxLayout(pinRow);
            pinLay->setContentsMargins(0, 0, 0, 0);
            auto* fetchBtn = new QPushButton(tr("Fetch"), pinRow);
            fetchBtn->setToolTip(tr("Read the gateway's certificate SHA-256 fingerprint"));
            pinLay->addWidget(m_sslvpnPin, 1);
            pinLay->addWidget(fetchBtn);
            connect(fetchBtn, &QPushButton::clicked, this, &ProfileEditor::fetchPin);

            m_sslvpnEad = new QCheckBox(
                tr("Send EAD host-check acknowledgement after login"), pg);

            // Zero-Trust / SDP single-packet-authorization knock.
            m_spaKey = new QLineEdit(pg);
            m_spaKey->setPlaceholderText(tr("hex HOTP key from SDP enrollment — leave blank for plain SSL VPN"));
            m_spaAid = new QLineEdit(pg);
            m_spaAid->setPlaceholderText(tr("hex client AID (optional)"));
            m_spaPorts = new QLineEdit(pg);
            m_spaPorts->setPlaceholderText(tr("ports to request, e.g. 443 (optional)"));

            f->addRow(tr("Gateway URL:"), m_sslvpnUrl);
            f->addRow(QString(), m_sslvpnSplit);
            f->addRow(tr("Cert pin (SHA-256):"), pinRow);
            f->addRow(QString(), m_sslvpnEad);
            auto* sdpHint = new QLabel(tr("Zero-Trust / SDP knock (optional):"), pg);
            sdpHint->setStyleSheet(QStringLiteral("color: gray;"));
            f->addRow(sdpHint);
            f->addRow(tr("SPA key:"),   m_spaKey);
            f->addRow(tr("SPA AID:"),   m_spaAid);
            f->addRow(tr("SPA ports:"), m_spaPorts);
            m_protoStack->addWidget(pg);
        }

        // --- EAD page ---
        {
            auto* pg = new QWidget;
            auto* f = new QFormLayout(pg);
            m_eadHost = new QLineEdit(pg);
            m_eadPort = new QSpinBox(pg);
            m_eadPort->setRange(1, 65535);
            m_eadPort->setValue(9019);
            m_eadRequired = new QCheckBox(tr("Posture check required by server"), pg);
            f->addRow(tr("EAD host:"), m_eadHost);
            f->addRow(tr("EAD port:"), m_eadPort);
            f->addRow(QString(),       m_eadRequired);
            m_protoStack->addWidget(pg);
        }

        m_tabs->addTab(w, tr("Protocol"));
    }

    // ============== Tab: Advanced ==============
    {
        auto* w = new QWidget(this);
        auto* f = new QFormLayout(w);

        m_ipMode = new QComboBox(w);
        m_ipMode->addItem(tr("Inherit (don't touch)"), int(IpMode::Inherit));
        m_ipMode->addItem(tr("DHCP"),                   int(IpMode::Dhcp));
        m_ipMode->addItem(tr("Static"),                 int(IpMode::Static));

        m_staticIp   = new QLineEdit(w);
        m_staticMask = new QLineEdit(w);
        m_staticGw   = new QLineEdit(w);
        m_staticDns  = new QLineEdit(w);

        m_trustMode = new QComboBox(w);
        m_trustMode->addItem(tr("System CA store"),        int(TrustMode::System));
        m_trustMode->addItem(tr("Pinned CA file"),          int(TrustMode::Pinned));
        m_trustMode->addItem(tr("Skip validation (unsafe)"), int(TrustMode::None));

        auto* caPicker = makeFilePicker(m_caCert, w);
        auto* userPicker = makeFilePicker(m_userCert, w);

        m_heartbeat = new QSpinBox(w);
        m_heartbeat->setRange(0, 3600);
        m_heartbeat->setSuffix(tr(" s"));

        m_reconnectTries = new QSpinBox(w);
        m_reconnectTries->setRange(0, 100);

        m_reconnectBackoff = new QSpinBox(w);
        m_reconnectBackoff->setRange(1, 600);
        m_reconnectBackoff->setSuffix(tr(" s"));

        m_logLevel = new QSpinBox(w);
        m_logLevel->setRange(0, 5);

        f->addRow(tr("IP mode:"),          m_ipMode);
        f->addRow(tr("Static IP:"),        m_staticIp);
        f->addRow(tr("Static netmask:"),   m_staticMask);
        f->addRow(tr("Static gateway:"),   m_staticGw);
        f->addRow(tr("Static DNS:"),       m_staticDns);
        f->addRow(tr("Trust mode:"),       m_trustMode);
        f->addRow(tr("CA cert:"),          caPicker);
        f->addRow(tr("Client cert:"),      userPicker);
        f->addRow(tr("Heartbeat:"),        m_heartbeat);
        f->addRow(tr("Reconnect retries:"), m_reconnectTries);
        f->addRow(tr("Reconnect backoff:"), m_reconnectBackoff);
        f->addRow(tr("Log level:"),        m_logLevel);

        m_tabs->addTab(w, tr("Advanced"));
    }

    // ---- Buttons ----
    auto* buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, this);
    root->addWidget(buttons);
    connect(buttons, &QDialogButtonBox::accepted, this, [this] { saveToProfile(); accept(); });
    connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);

    connect(m_kind, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &ProfileEditor::onKindChanged);
}

void ProfileEditor::populateInterfaces(bool wireless) {
    const QString current = m_iface->currentText();
    m_iface->clear();
    const auto list = wireless ? InterfaceDiscovery::wireless()
                               : InterfaceDiscovery::wired();
    for (const auto& i : list) {
        const QString label = QStringLiteral("%1  (%2%3)")
            .arg(i.name,
                 i.hwAddress.isEmpty() ? QStringLiteral("–") : i.hwAddress,
                 i.hasCarrier ? QStringLiteral(", up") : QString());
        m_iface->addItem(label, i.name);
    }
    if (!current.isEmpty()) {
        m_iface->setCurrentText(current);
    }
}

void ProfileEditor::fetchPin() {
    QString raw = m_sslvpnUrl->text().trimmed();
    if (raw.isEmpty()) {
        QMessageBox::information(this, tr("Fetch pin"),
                                 tr("Enter the gateway URL first."));
        return;
    }
    if (!raw.contains(QStringLiteral("://")))
        raw = QStringLiteral("https://") + raw;
    const QUrl url(raw);
    const QString host = url.host();
    const int port = url.port(443);
    if (host.isEmpty()) {
        QMessageBox::warning(this, tr("Fetch pin"),
                             tr("Could not parse a host from the gateway URL."));
        return;
    }

    // openssl s_client -connect host:port </dev/null | openssl x509 -fingerprint -sha256 -noout
    QProcess proc;
    proc.start(QStringLiteral("bash"), {QStringLiteral("-c"),
        QStringLiteral("openssl s_client -connect %1:%2 </dev/null 2>/dev/null "
                       "| openssl x509 -fingerprint -sha256 -noout")
            .arg(host).arg(port)});
    if (!proc.waitForFinished(12000)) {
        proc.kill();
        QMessageBox::warning(this, tr("Fetch pin"),
                             tr("Timed out contacting %1:%2.").arg(host).arg(port));
        return;
    }
    const QString out = QString::fromUtf8(proc.readAllStandardOutput());
    const int eq = out.indexOf(QLatin1Char('='));
    const QString pin = (eq >= 0) ? out.mid(eq + 1).trimmed() : QString();
    if (pin.isEmpty()) {
        QMessageBox::warning(this, tr("Fetch pin"),
                             tr("Could not read a certificate from %1:%2. "
                                "Is the gateway reachable and is openssl installed?")
                                 .arg(host).arg(port));
        return;
    }
    m_sslvpnPin->setText(pin);
}

void ProfileEditor::onKindChanged(int index) {
    const ProtocolKind k = protocolFromInt(m_kind->itemData(index).toInt());
    // Map protocol to stack page index (matches addWidget() order above).
    switch (k) {
        case ProtocolKind::Dot1x:     m_protoStack->setCurrentIndex(0); populateInterfaces(false); break;
        case ProtocolKind::Wlan:      m_protoStack->setCurrentIndex(1); populateInterfaces(true);  break;
        case ProtocolKind::Portal:    m_protoStack->setCurrentIndex(2); break;
        case ProtocolKind::L2tpIpsec: m_protoStack->setCurrentIndex(3); break;
        case ProtocolKind::SslVpn:    m_protoStack->setCurrentIndex(4); break;
        case ProtocolKind::Sdp:       m_protoStack->setCurrentIndex(4); break;
        case ProtocolKind::Ead:       m_protoStack->setCurrentIndex(5); break;
        default:                      m_protoStack->setCurrentIndex(0); break;
    }
}

void ProfileEditor::loadFromProfile() {
    m_name->setText(m_profile.name);
    const int kindIndex = m_kind->findData(int(m_profile.kind));
    if (kindIndex >= 0) m_kind->setCurrentIndex(kindIndex);
    m_username->setText(m_profile.username);
    m_domain->setText(m_profile.domain);
    m_serviceName->setText(m_profile.serviceName);
    m_save->setChecked(m_profile.savePassword);
    m_auto->setChecked(m_profile.autoConnect);
    m_autoReconnect->setChecked(m_profile.autoReconnect);

    populateInterfaces(m_profile.kind == ProtocolKind::Wlan);
    if (!m_profile.iface.isEmpty()) m_iface->setCurrentText(m_profile.iface);

    const int amIdx = m_authMode->findData(int(m_profile.authMode));
    if (amIdx >= 0) m_authMode->setCurrentIndex(amIdx);

    m_useRjv3->setChecked(m_profile.dot1xUseRjv3);
    m_rjvService->setValue(m_profile.dot1xServiceType);
    m_rjvCarrier->setText(m_profile.dot1xCarrier);
    m_dot1xExtra->setText(m_profile.dot1xExtraArgs);

    m_wlanSsid->setText(m_profile.wlanSsid);
    m_wlanHidden->setChecked(m_profile.wlanHiddenSsid);

    m_l2tpHost->setText(m_profile.kind == ProtocolKind::L2tpIpsec ? m_profile.serverHost : QString());
    m_l2tpPsk->setText(m_profile.psk);
    m_l2tpForceEncap->setChecked(m_profile.l2tpForceUdpEncap);

    m_portalHost->setText(m_profile.kind == ProtocolKind::Portal ? m_profile.serverHost : QString());
    m_portalPort->setValue(m_profile.serverPort ? m_profile.serverPort : 2000);
    m_portalSecret->setText(m_profile.portalSecret);
    {
        const int di = m_portalDialect->findData(m_profile.portalDialect);
        if (di >= 0) m_portalDialect->setCurrentIndex(di);
    }

    m_sslvpnUrl->setText(m_profile.sslvpnUrl);
    m_sslvpnSplit->setChecked(m_profile.sslvpnSplitTunnel);
    m_sslvpnPin->setText(m_profile.sslvpnPinSha256);
    m_sslvpnEad->setChecked(m_profile.sslvpnEadHostcheck);
    m_spaKey->setText(m_profile.sslvpnSpaKey);
    m_spaAid->setText(m_profile.sslvpnSpaAid);
    m_spaPorts->setText(m_profile.sslvpnSpaPorts);

    m_eadHost->setText(m_profile.eadServer);
    m_eadPort->setValue(m_profile.eadPort ? m_profile.eadPort : 9019);
    m_eadRequired->setChecked(m_profile.eadRequired);

    // Advanced
    {
        const int i = m_ipMode->findData(int(m_profile.ipMode));
        if (i >= 0) m_ipMode->setCurrentIndex(i);
    }
    m_staticIp->setText(m_profile.staticIp);
    m_staticMask->setText(m_profile.staticNetmask);
    m_staticGw->setText(m_profile.staticGateway);
    m_staticDns->setText(m_profile.staticDns);
    {
        const int i = m_trustMode->findData(int(m_profile.trustMode));
        if (i >= 0) m_trustMode->setCurrentIndex(i);
    }
    m_caCert->setText(m_profile.caCertPath);
    m_userCert->setText(m_profile.userCertPath);
    m_heartbeat->setValue(m_profile.heartbeatSec);
    m_reconnectTries->setValue(m_profile.reconnectMaxTries);
    m_reconnectBackoff->setValue(m_profile.reconnectBackoffSec);
    m_logLevel->setValue(m_profile.logLevel);
}

void ProfileEditor::saveToProfile() {
    m_profile.name          = m_name->text().trimmed();
    m_profile.kind          = protocolFromInt(m_kind->currentData().toInt());
    m_profile.username      = m_username->text().trimmed();
    m_profile.domain        = m_domain->text().trimmed();
    m_profile.serviceName   = m_serviceName->text().trimmed();
    m_profile.savePassword  = m_save->isChecked();
    m_profile.autoConnect   = m_auto->isChecked();
    m_profile.autoReconnect = m_autoReconnect->isChecked();

    // interface: prefer the itemData (pure iface name) over the display text.
    {
        const auto data = m_iface->currentData();
        m_profile.iface = data.isValid() ? data.toString() : m_iface->currentText().split(' ').value(0).trimmed();
    }

    m_profile.authMode         = static_cast<AuthMode>(m_authMode->currentData().toInt());
    m_profile.dot1xUseRjv3     = m_useRjv3->isChecked();
    m_profile.dot1xServiceType = m_rjvService->value();
    m_profile.dot1xCarrier     = m_rjvCarrier->text().trimmed();
    m_profile.dot1xExtraArgs   = m_dot1xExtra->text().trimmed();

    m_profile.wlanSsid       = m_wlanSsid->text().trimmed();
    m_profile.wlanHiddenSsid = m_wlanHidden->isChecked();

    // Only the "serverHost" field of the struct is shared across Portal/L2TP,
    // so map the current protocol's input into it.
    switch (m_profile.kind) {
        case ProtocolKind::L2tpIpsec:
            m_profile.serverHost        = m_l2tpHost->text().trimmed();
            m_profile.psk               = m_l2tpPsk->text();
            m_profile.l2tpForceUdpEncap = m_l2tpForceEncap->isChecked();
            break;
        case ProtocolKind::Portal:
            m_profile.serverHost    = m_portalHost->text().trimmed();
            m_profile.serverPort    = static_cast<quint16>(m_portalPort->value());
            m_profile.portalSecret  = m_portalSecret->text();
            m_profile.portalDialect = m_portalDialect->currentData().toInt();
            break;
        case ProtocolKind::Sdp:
        case ProtocolKind::SslVpn:
            m_profile.sslvpnUrl = m_sslvpnUrl->text().trimmed();
            m_profile.sslvpnSplitTunnel = m_sslvpnSplit->isChecked();
            m_profile.sslvpnPinSha256 = m_sslvpnPin->text().trimmed();
            m_profile.sslvpnEadHostcheck = m_sslvpnEad->isChecked();
            m_profile.sslvpnSpaKey = m_spaKey->text().trimmed();
            m_profile.sslvpnSpaAid = m_spaAid->text().trimmed();
            m_profile.sslvpnSpaPorts = m_spaPorts->text().trimmed();
            break;
        case ProtocolKind::Ead:
            m_profile.eadServer   = m_eadHost->text().trimmed();
            m_profile.eadPort     = static_cast<quint16>(m_eadPort->value());
            m_profile.eadRequired = m_eadRequired->isChecked();
            break;
        case ProtocolKind::Dot1x:
        case ProtocolKind::Wlan:
            break;
    }

    m_profile.ipMode         = static_cast<IpMode>(m_ipMode->currentData().toInt());
    m_profile.staticIp       = m_staticIp->text().trimmed();
    m_profile.staticNetmask  = m_staticMask->text().trimmed();
    m_profile.staticGateway  = m_staticGw->text().trimmed();
    m_profile.staticDns      = m_staticDns->text().trimmed();
    m_profile.trustMode      = static_cast<TrustMode>(m_trustMode->currentData().toInt());
    m_profile.caCertPath     = m_caCert->text().trimmed();
    m_profile.userCertPath   = m_userCert->text().trimmed();
    m_profile.heartbeatSec   = m_heartbeat->value();
    m_profile.reconnectMaxTries   = m_reconnectTries->value();
    m_profile.reconnectBackoffSec = m_reconnectBackoff->value();
    m_profile.logLevel       = m_logLevel->value();
}

} // namespace inode
