#include "ProfileStore.h"

#include "CredentialStore.h"
#include "Logger.h"

#include <QDir>
#include <QFile>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QSaveFile>
#include <QStandardPaths>

namespace inode {

ProfileStore::ProfileStore(QObject* parent) : QObject(parent) {}

QString ProfileStore::storagePath() const {
    QString dir = QStandardPaths::writableLocation(QStandardPaths::AppConfigLocation);
    QDir().mkpath(dir);
    return dir + QStringLiteral("/profiles.json");
}

// Names of the fields we deliberately DO NOT write to profiles.json: these
// are secrets and belong in the CredentialStore backend only. If an old
// build wrote one of these keys, ProfileStore::load() migrates it into the
// keyring and drops it from the JSON. Keep in sync with the migration in
// fromJson() below.
static void serializeNonSecret(const Profile& p, QJsonObject& o) {
    o[QStringLiteral("id")]                = p.id.toString(QUuid::WithoutBraces);
    o[QStringLiteral("name")]              = p.name;
    o[QStringLiteral("kind")]              = static_cast<int>(p.kind);

    o[QStringLiteral("username")]          = p.username;
    o[QStringLiteral("domain")]            = p.domain;
    o[QStringLiteral("serviceName")]       = p.serviceName;
    o[QStringLiteral("serverHost")]        = p.serverHost;
    o[QStringLiteral("serverPort")]        = p.serverPort;
    o[QStringLiteral("iface")]             = p.iface;

    o[QStringLiteral("savePassword")]      = p.savePassword;
    o[QStringLiteral("autoConnect")]       = p.autoConnect;
    o[QStringLiteral("autoReconnect")]     = p.autoReconnect;
    o[QStringLiteral("reconnectMaxTries")] = p.reconnectMaxTries;
    o[QStringLiteral("reconnectBackoff")]  = p.reconnectBackoffSec;
    o[QStringLiteral("heartbeatSec")]      = p.heartbeatSec;
    o[QStringLiteral("logLevel")]          = p.logLevel;

    o[QStringLiteral("ipMode")]            = ipModeToString(p.ipMode);
    o[QStringLiteral("staticIp")]          = p.staticIp;
    o[QStringLiteral("staticNetmask")]     = p.staticNetmask;
    o[QStringLiteral("staticGateway")]     = p.staticGateway;
    o[QStringLiteral("staticDns")]         = p.staticDns;

    o[QStringLiteral("trustMode")]         = trustModeToString(p.trustMode);
    o[QStringLiteral("caCertPath")]        = p.caCertPath;
    o[QStringLiteral("userCertPath")]      = p.userCertPath;
    // userCertPin — stored via CredentialStore.

    o[QStringLiteral("authMode")]          = authModeToString(p.authMode);
    o[QStringLiteral("dot1xUseRjv3")]      = p.dot1xUseRjv3;
    o[QStringLiteral("dot1xServiceType")]  = p.dot1xServiceType;
    o[QStringLiteral("dot1xCarrier")]      = p.dot1xCarrier;
    o[QStringLiteral("dot1xExtraArgs")]    = p.dot1xExtraArgs;
    o[QStringLiteral("wlanSsid")]          = p.wlanSsid;
    o[QStringLiteral("wlanHiddenSsid")]    = p.wlanHiddenSsid;

    // portalSecret — stored via CredentialStore.
    o[QStringLiteral("portalDialect")]     = p.portalDialect;

    o[QStringLiteral("sslvpnUrl")]         = p.sslvpnUrl;
    o[QStringLiteral("sslvpnSplitTunnel")] = p.sslvpnSplitTunnel;
    o[QStringLiteral("sslvpnPinSha256")]   = p.sslvpnPinSha256;
    o[QStringLiteral("sslvpnEadHostcheck")] = p.sslvpnEadHostcheck;
    // sslvpnSpaKey — stored via CredentialStore.
    o[QStringLiteral("sslvpnSpaAid")]      = p.sslvpnSpaAid;
    o[QStringLiteral("sslvpnSpaPorts")]    = p.sslvpnSpaPorts;

    // psk — stored via CredentialStore.
    o[QStringLiteral("l2tpForceUdpEncap")] = p.l2tpForceUdpEncap;

    o[QStringLiteral("eadServer")]         = p.eadServer;
    o[QStringLiteral("eadPort")]           = p.eadPort;
    o[QStringLiteral("eadRequired")]       = p.eadRequired;
}

// Read the non-secret part from JSON. Secret fields are left empty here
// and populated separately from the CredentialStore by hydrateSecrets().
// Legacy plaintext secrets are captured into the out-params so load() can
// migrate them into the keyring on the fly.
struct LegacyPlaintext {
    bool present = false;
    QString portalSecret;
    QString psk;
    QString sslvpnSpaKey;
    QString userCertPin;
};

static Profile fromJson(const QJsonObject& o, LegacyPlaintext* legacy) {
    Profile p;
    p.id           = QUuid::fromString(o.value(QStringLiteral("id")).toString());
    p.name         = o.value(QStringLiteral("name")).toString();
    p.kind         = protocolFromInt(o.value(QStringLiteral("kind")).toInt(8021));

    p.username     = o.value(QStringLiteral("username")).toString();
    p.domain       = o.value(QStringLiteral("domain")).toString();
    p.serviceName  = o.value(QStringLiteral("serviceName")).toString();
    p.serverHost   = o.value(QStringLiteral("serverHost")).toString();
    p.serverPort   = static_cast<quint16>(o.value(QStringLiteral("serverPort")).toInt());
    p.iface        = o.value(QStringLiteral("iface")).toString();

    p.savePassword = o.value(QStringLiteral("savePassword")).toBool();
    p.autoConnect  = o.value(QStringLiteral("autoConnect")).toBool();
    p.autoReconnect = o.value(QStringLiteral("autoReconnect")).toBool();
    p.reconnectMaxTries   = o.value(QStringLiteral("reconnectMaxTries")).toInt(5);
    p.reconnectBackoffSec = o.value(QStringLiteral("reconnectBackoff")).toInt(10);
    p.heartbeatSec = o.value(QStringLiteral("heartbeatSec")).toInt(30);
    p.logLevel     = o.value(QStringLiteral("logLevel")).toInt(3);

    p.ipMode          = ipModeFromString(o.value(QStringLiteral("ipMode")).toString());
    p.staticIp        = o.value(QStringLiteral("staticIp")).toString();
    p.staticNetmask   = o.value(QStringLiteral("staticNetmask")).toString();
    p.staticGateway   = o.value(QStringLiteral("staticGateway")).toString();
    p.staticDns       = o.value(QStringLiteral("staticDns")).toString();

    p.trustMode    = trustModeFromString(o.value(QStringLiteral("trustMode")).toString());
    p.caCertPath   = o.value(QStringLiteral("caCertPath")).toString();
    p.userCertPath = o.value(QStringLiteral("userCertPath")).toString();

    p.authMode         = authModeFromString(o.value(QStringLiteral("authMode")).toString());
    p.dot1xUseRjv3     = o.value(QStringLiteral("dot1xUseRjv3")).toBool(true);
    p.dot1xServiceType = o.value(QStringLiteral("dot1xServiceType")).toInt(1);
    p.dot1xCarrier     = o.value(QStringLiteral("dot1xCarrier")).toString();
    p.dot1xExtraArgs   = o.value(QStringLiteral("dot1xExtraArgs")).toString();
    p.wlanSsid         = o.value(QStringLiteral("wlanSsid")).toString();
    p.wlanHiddenSsid   = o.value(QStringLiteral("wlanHiddenSsid")).toBool();

    p.portalDialect = o.value(QStringLiteral("portalDialect")).toInt(0);

    p.sslvpnUrl    = o.value(QStringLiteral("sslvpnUrl")).toString();
    p.sslvpnSplitTunnel = o.value(QStringLiteral("sslvpnSplitTunnel")).toBool(true);
    p.sslvpnPinSha256   = o.value(QStringLiteral("sslvpnPinSha256")).toString();
    p.sslvpnEadHostcheck = o.value(QStringLiteral("sslvpnEadHostcheck")).toBool(false);
    p.sslvpnSpaAid      = o.value(QStringLiteral("sslvpnSpaAid")).toString();
    p.sslvpnSpaPorts    = o.value(QStringLiteral("sslvpnSpaPorts")).toString();

    p.l2tpForceUdpEncap  = o.value(QStringLiteral("l2tpForceUdpEncap")).toBool(true);

    p.eadServer    = o.value(QStringLiteral("eadServer")).toString();
    p.eadPort      = static_cast<quint16>(o.value(QStringLiteral("eadPort")).toInt(9019));
    p.eadRequired  = o.value(QStringLiteral("eadRequired")).toBool(false);

    // Legacy: earlier builds wrote these as plaintext. Capture them here so
    // load() can migrate them into the CredentialStore, then rewrite the
    // JSON without them.
    if (legacy) {
        const QString portalSecret = o.value(QStringLiteral("portalSecret")).toString();
        const QString psk          = o.value(QStringLiteral("psk")).toString();
        const QString spa          = o.value(QStringLiteral("sslvpnSpaKey")).toString();
        const QString pin          = o.value(QStringLiteral("userCertPin")).toString();
        if (!portalSecret.isEmpty() || !psk.isEmpty()
                || !spa.isEmpty() || !pin.isEmpty()) {
            legacy->present = true;
            legacy->portalSecret = portalSecret;
            legacy->psk          = psk;
            legacy->sslvpnSpaKey = spa;
            legacy->userCertPin  = pin;
        }
    }

    if (p.id.isNull()) p.id = QUuid::createUuid();
    return p;
}

// Fill in the secret fields on `p` from the CredentialStore. Leaves fields
// empty when the store has no entry for them (or the backend is locked).
static void hydrateSecrets(Profile& p) {
    auto& cs = CredentialStore::instance();
    QString s;
    if (cs.retrieve(p.id, SecretField::Psk,          &s)) p.psk          = s;
    if (cs.retrieve(p.id, SecretField::PortalSecret, &s)) p.portalSecret = s;
    if (cs.retrieve(p.id, SecretField::SpaKey,       &s)) p.sslvpnSpaKey = s;
    if (cs.retrieve(p.id, SecretField::CertPin,      &s)) p.userCertPin  = s;
}

// Write the profile's secret fields into the keyring. Empty values erase
// the corresponding entry.
static void persistSecrets(const Profile& p) {
    auto& cs = CredentialStore::instance();
    cs.store(p.id, SecretField::Psk,          p.psk);
    cs.store(p.id, SecretField::PortalSecret, p.portalSecret);
    cs.store(p.id, SecretField::SpaKey,       p.sslvpnSpaKey);
    cs.store(p.id, SecretField::CertPin,      p.userCertPin);
    // Note: SecretField::Password is managed by MainWindow::persistPassword,
    // which honors the profile's savePassword checkbox.
}

void ProfileStore::load() {
    m_profiles.clear();
    QFile f(storagePath());
    if (!f.open(QIODevice::ReadOnly)) return;
    const auto doc = QJsonDocument::fromJson(f.readAll());
    const auto arr = doc.array();
    m_profiles.reserve(arr.size());

    // Only rewrite profiles.json (which drops the legacy plaintext fields)
    // when every legacy secret we found was successfully moved into the
    // CredentialStore — otherwise we'd throw away the user's data if they
    // e.g. cancelled the master-password prompt.
    bool fullyMigrated = true;
    bool anyMigrated   = false;
    for (const auto& v : arr) {
        LegacyPlaintext legacy;
        Profile p = fromJson(v.toObject(), &legacy);
        if (legacy.present) {
            auto& cs = CredentialStore::instance();
            auto move = [&](SecretField field, const QString& val, QString Profile::* member) {
                if (val.isEmpty()) return;
                p.*member = val;
                if (cs.store(p.id, field, val)) anyMigrated = true;
                else                            fullyMigrated = false;
            };
            move(SecretField::Psk,          legacy.psk,          &Profile::psk);
            move(SecretField::PortalSecret, legacy.portalSecret, &Profile::portalSecret);
            move(SecretField::SpaKey,       legacy.sslvpnSpaKey, &Profile::sslvpnSpaKey);
            move(SecretField::CertPin,      legacy.userCertPin,  &Profile::userCertPin);
        } else {
            hydrateSecrets(p);
        }
        m_profiles.push_back(std::move(p));
    }
    if (anyMigrated && fullyMigrated) save();
    emit changed();
}

void ProfileStore::save() const {
    QJsonArray arr;
    for (const auto& p : m_profiles) {
        QJsonObject o;
        serializeNonSecret(p, o);
        arr.append(o);
    }
    QSaveFile f(storagePath());
    if (!f.open(QIODevice::WriteOnly)) {
        Logger::instance().error(QStringLiteral(
            "profiles: cannot write %1 (%2) — changes are not persisted")
            .arg(storagePath(), f.errorString()));
        return;
    }
    f.write(QJsonDocument(arr).toJson(QJsonDocument::Indented));
    if (!f.commit()) {
        Logger::instance().error(QStringLiteral(
            "profiles: commit failed for %1 — changes are not persisted")
            .arg(storagePath()));
    }
}

void ProfileStore::upsert(const Profile& p) {
    persistSecrets(p);
    for (auto& existing : m_profiles) {
        if (existing.id == p.id) { existing = p; save(); emit changed(); return; }
    }
    m_profiles.push_back(p);
    save();
    emit changed();
}

void ProfileStore::remove(const QUuid& id) {
    const auto n = m_profiles.size();
    // Wipe every stored secret for this profile before dropping it from
    // memory — MainWindow::onRemoveProfile also calls forget(id) for the
    // primary password, and doing the sweep here catches the rest.
    CredentialStore::instance().forget(id);
    m_profiles.erase(std::remove_if(m_profiles.begin(), m_profiles.end(),
                                    [&](const Profile& p) { return p.id == id; }),
                     m_profiles.end());
    if (m_profiles.size() != n) { save(); emit changed(); }
}

const Profile* ProfileStore::find(const QUuid& id) const {
    for (const auto& p : m_profiles) if (p.id == id) return &p;
    return nullptr;
}

const Profile* ProfileStore::findByName(const QString& name) const {
    for (const auto& p : m_profiles) if (p.name == name) return &p;
    return nullptr;
}

const Profile* ProfileStore::autoConnectProfile() const {
    for (const auto& p : m_profiles) if (p.autoConnect) return &p;
    return nullptr;
}

} // namespace inode
