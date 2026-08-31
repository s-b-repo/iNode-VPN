#pragma once

#include "core/Profile.h"
#include <QDialog>

class QLineEdit;
class QComboBox;
class QCheckBox;
class QSpinBox;
class QStackedWidget;
class QTabWidget;

namespace inode {

class ProfileEditor : public QDialog {
    Q_OBJECT
public:
    explicit ProfileEditor(const Profile& initial, QWidget* parent = nullptr);

    const Profile& profile() const { return m_profile; }
    QString password() const;

private:
    void buildUi();
    void populateInterfaces(bool wireless);
    void loadFromProfile();
    void saveToProfile();
    void onKindChanged(int index);
    void fetchPin();   // read the gateway cert's SHA-256 fingerprint via openssl

    Profile m_profile;

    // Tabs
    QTabWidget*     m_tabs = nullptr;

    // General
    QLineEdit*      m_name = nullptr;
    QComboBox*      m_kind = nullptr;
    QLineEdit*      m_username = nullptr;
    QLineEdit*      m_domain = nullptr;
    QLineEdit*      m_serviceName = nullptr;
    QLineEdit*      m_password = nullptr;
    QCheckBox*      m_save = nullptr;
    QCheckBox*      m_auto = nullptr;
    QCheckBox*      m_autoReconnect = nullptr;

    // Protocol-specific
    QStackedWidget* m_protoStack = nullptr;

    // Dot1x / WLAN
    QComboBox*      m_iface = nullptr;
    QLineEdit*      m_wlanSsid = nullptr;
    QCheckBox*      m_wlanHidden = nullptr;
    QComboBox*      m_authMode = nullptr;
    QCheckBox*      m_useRjv3 = nullptr;
    QSpinBox*       m_rjvService = nullptr;
    QLineEdit*      m_rjvCarrier = nullptr;
    QLineEdit*      m_dot1xExtra = nullptr;

    // L2TP
    QLineEdit*      m_l2tpHost = nullptr;
    QLineEdit*      m_l2tpPsk  = nullptr;
    QCheckBox*      m_l2tpForceEncap = nullptr;

    // Portal
    QLineEdit*      m_portalHost = nullptr;
    QSpinBox*       m_portalPort = nullptr;
    QLineEdit*      m_portalSecret = nullptr;
    QComboBox*      m_portalDialect = nullptr;

    // SSL VPN
    QLineEdit*      m_sslvpnUrl = nullptr;
    QCheckBox*      m_sslvpnSplit = nullptr;
    QLineEdit*      m_sslvpnPin = nullptr;
    QCheckBox*      m_sslvpnEad = nullptr;
    QLineEdit*      m_spaKey = nullptr;
    QLineEdit*      m_spaAid = nullptr;
    QLineEdit*      m_spaPorts = nullptr;

    // EAD
    QLineEdit*      m_eadHost = nullptr;
    QSpinBox*       m_eadPort = nullptr;
    QCheckBox*      m_eadRequired = nullptr;

    // Advanced tab
    QComboBox*      m_ipMode = nullptr;
    QLineEdit*      m_staticIp = nullptr;
    QLineEdit*      m_staticMask = nullptr;
    QLineEdit*      m_staticGw = nullptr;
    QLineEdit*      m_staticDns = nullptr;
    QComboBox*      m_trustMode = nullptr;
    QLineEdit*      m_caCert = nullptr;
    QLineEdit*      m_userCert = nullptr;
    QSpinBox*       m_heartbeat = nullptr;
    QSpinBox*       m_reconnectTries = nullptr;
    QSpinBox*       m_reconnectBackoff = nullptr;
    QSpinBox*       m_logLevel = nullptr;
};

} // namespace inode
