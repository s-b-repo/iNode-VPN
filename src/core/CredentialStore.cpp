#include "CredentialStore.h"

#include "EncryptedFileStore.h"
#include "SecretServiceStore.h"

#include <QByteArray>
#include <QDir>
#include <QHash>
#include <QFile>
#include <QFileInfo>
#include <QIODevice>
#include <QLatin1String>
#include <QMutex>
#include <QMutexLocker>
#include <QProcess>
#include <QStandardPaths>
#include <QVector>

#include "Logger.h"

#include <QString>

#ifdef HAVE_KF6
#include <KWallet>
#endif

namespace inode {

namespace {

// Stable string names used to build the compound backend key
// "<uuid>/<field>". Order-independent — do not reorder for legacy reasons,
// but changing a name would orphan existing entries.
const char* fieldName(SecretField f) {
    switch (f) {
        case SecretField::Password:     return "password";
        case SecretField::Psk:          return "psk";
        case SecretField::PortalSecret: return "portal-secret";
        case SecretField::SpaKey:       return "spa-key";
        case SecretField::CertPin:      return "cert-pin";
    }
    return "password";
}

// Every field we might store, so forget-all can iterate them.
constexpr SecretField kAllFields[] = {
    SecretField::Password, SecretField::Psk, SecretField::PortalSecret,
    SecretField::SpaKey,   SecretField::CertPin,
};

QString compoundKey(const QUuid& id, SecretField f) {
    return id.toString(QUuid::WithoutBraces) + QLatin1Char('/')
         + QString::fromLatin1(fieldName(f));
}

// --- Legacy GPG store migration -----------------------------------------
//
// The system-GnuPG backend was removed (v0.3). Its on-disk store was a single
// ASCII-armored file ~/.config/iNodeClient-Qt/secrets.gpg whose plaintext is
// a header line followed by "<key>\t<base64(secret)>" lines. On first use we
// decrypt that file (gpg-agent/pinentry own the passphrase — this process
// never sees it), re-seal every entry into the now-active backend, and rename
// the legacy file to secrets.gpg.migrated so nothing is lost even if the
// migration is interrupted. Best effort: if gpg is missing or decryption is
// refused, we leave the file untouched and simply skip it.

QString legacyGpgStorePath() {
    return QStandardPaths::writableLocation(QStandardPaths::AppConfigLocation)
         + QStringLiteral("/secrets.gpg");
}

QString legacyMigratedPath() {
    return legacyGpgStorePath() + QStringLiteral(".migrated");
}

QString findGpgBinary() {
    for (const char* name : {"gpg", "gpg2"}) {
        QString p = QStandardPaths::findExecutable(QLatin1String(name));
        if (!p.isEmpty()) return p;
    }
    return QString();
}

bool runGpgDecrypt(const QString& gpg, const QString& path, QByteArray* out) {
    QProcess proc;
    proc.setProgram(gpg);
    proc.setArguments({QStringLiteral("--quiet"), QStringLiteral("--batch"),
                       QStringLiteral("--decrypt"), path});
    proc.start(QIODevice::ReadOnly);
    if (!proc.waitForStarted(5000)) return false;
    if (!proc.waitForFinished(30000)) {
        proc.kill();
        proc.waitForFinished(5000);
        return false;
    }
    if (proc.exitStatus() != QProcess::NormalExit || proc.exitCode() != 0)
        return false;
    *out = proc.readAllStandardOutput();
    return true;
}

struct LegacyEntry { QString key; QString secret; };

// Parse the v1 payload: header line, then "<key>\t<base64(secret)>" lines.
bool parseLegacyPayload(const QByteArray& plain, QVector<LegacyEntry>* entries) {
    const QByteArray header = QByteArrayLiteral("iNodeClient-Qt gpg credential store v1");
    const QList<QByteArray> lines = plain.split('\n');
    if (lines.isEmpty() || lines.first() != header) return false;
    for (int i = 1; i < lines.size(); ++i) {
        const QByteArray& line = lines.at(i);
        if (line.isEmpty()) continue;
        const int tab = line.indexOf('\t');
        if (tab <= 0) return false;
        entries->append({QString::fromUtf8(line.left(tab)),
                         QString::fromUtf8(QByteArray::fromBase64(
                             line.mid(tab + 1)))});
    }
    return true;
}

// Store through the normal backend priority. KWallet needs the Impl's
// tryOpenWallet(), so the wallet step is injected by the caller below.
bool storeIntoActiveBackends(const QString& key, const QString& secret) {
    if (secretservice::available() && secretservice::store(key, secret))
        return true;
    if (encfilestore::haveCrypto()) return encfilestore::store(key, secret);
    return false;
}

} // namespace

struct CredentialStore::Impl {
    // In-memory overlay keyed by compoundKey(); see setSessionSecret().
    QHash<QString, QString> session;
#ifdef HAVE_KF6
    KWallet::Wallet* wallet = nullptr;
    ~Impl() { delete wallet; }
    bool tryOpenWallet() {
        if (wallet && wallet->isOpen()) return true;
        delete wallet;                     // openWallet() result is caller-owned
        wallet = nullptr;
        wallet = KWallet::Wallet::openWallet(KWallet::Wallet::NetworkWallet(), 0);
        if (!wallet) return false;
        if (!wallet->hasFolder(QStringLiteral("iNodeClient-Qt")))
            wallet->createFolder(QStringLiteral("iNodeClient-Qt"));
        wallet->setFolder(QStringLiteral("iNodeClient-Qt"));
        return true;
    }
#endif
};

// One-time, idempotent. Serialized by the caller (guarded by a mutex).
// Member function: it needs access to the private Impl (KWallet path).
void CredentialStore::migrateLegacyGpgStore() {
    Impl* impl = d;
    const QString legacy = legacyGpgStorePath();
    if (!QFileInfo::exists(legacy)) return;          // nothing to migrate
    if (QFileInfo::exists(legacyMigratedPath())) {   // already done, stale file
        QFile::remove(legacy);
        return;
    }

    const QString gpg = findGpgBinary();
    if (gpg.isEmpty()) {
        Logger::instance().warn(
            QStringLiteral("legacy GPG credential store found but gpg is not "
                           "installed — install gpg once to migrate saved "
                           "passwords (file kept: %1)").arg(legacy));
        return;
    }

    QByteArray plain;
    if (!runGpgDecrypt(gpg, legacy, &plain)) {
        Logger::instance().warn(
            QStringLiteral("could not decrypt legacy GPG credential store "
                           "(agent refused or passphrase cancelled) — kept "
                           "at %1").arg(legacy));
        return;
    }

    QVector<LegacyEntry> entries;
    if (!parseLegacyPayload(plain, &entries) || entries.isEmpty()) {
        Logger::instance().warn(
            QStringLiteral("legacy GPG credential store is empty or "
                           "unreadable — renamed to %1").arg(legacyMigratedPath()));
        QFile::rename(legacy, legacyMigratedPath());
        return;
    }

    // Re-seal each entry into the currently active backend. The encrypted-
    // file fallback prompts for its master password when it is the only
    // backend available.
#ifdef HAVE_KF6
    const bool haveWallet = impl && impl->tryOpenWallet();
#else
    const bool haveWallet = false;
    Q_UNUSED(impl);
#endif
    int migrated = 0;
    for (const LegacyEntry& e : entries) {
        if (e.key.isEmpty() || e.secret.isEmpty()) continue;
        bool ok = false;
#ifdef HAVE_KF6
        if (haveWallet)
            ok = impl->wallet->writePassword(e.key, e.secret) == 0;
#endif
        if (!ok) ok = storeIntoActiveBackends(e.key, e.secret);
        if (ok) ++migrated;
    }

    if (migrated == entries.size()) {
        if (QFile::rename(legacy, legacyMigratedPath()))
            Logger::instance().info(QStringLiteral(
                "migrated %1 saved credential(s) from the legacy GPG store").arg(migrated));
    } else {
        Logger::instance().warn(QStringLiteral(
            "GPG store migration incomplete (%1/%2) — legacy file kept at %3")
            .arg(migrated).arg(entries.size()).arg(legacy));
    }
}

CredentialStore::CredentialStore() : d(new Impl) {}
CredentialStore::~CredentialStore() { delete d; }

CredentialStore& CredentialStore::instance() {
    static CredentialStore s;
    return s;
}

void CredentialStore::setPasswordPrompt(PasswordPrompt p) {
    encfilestore::setPrompt(std::move(p));
}

CredentialStore::Backend CredentialStore::activeBackend() const {
#ifdef HAVE_KF6
    if (d->wallet && d->wallet->isOpen()) return Backend::KWallet;
#endif
    if (secretservice::available()) return Backend::SecretService;
    if (encfilestore::haveCrypto())  return Backend::EncryptedFile;
    return Backend::None;
}

bool CredentialStore::isSecureBackend() const {
    return activeBackend() != Backend::None;
}

QString CredentialStore::backendDescription() const {
    switch (activeBackend()) {
        case Backend::KWallet:
            return QStringLiteral("KWallet (login password via PAM)");
        case Backend::SecretService:
            return QStringLiteral("Secret Service (login keyring)");
        case Backend::EncryptedFile:
            return QStringLiteral("AES-256-GCM file (master password)");
        case Backend::None:
            return QStringLiteral("no secure backend available");
    }
    return {};
}

// Runs the one-time legacy-GPG migration at most once per process. The
// migration may open dialogs (encfilestore master password) that spin the
// event loop, so the "done" flag is set BEFORE running it: a re-entrant
// store()/retrieve() from that event loop must not block on the (non-
// recursive) mutex held by the outer frame. The migration itself is
// idempotent, so even a cross-thread double-run is benign.
void CredentialStore::ensureLegacyMigration() {
    static bool migrationDone = false;
    if (migrationDone) return;
    static QMutex m;
    QMutexLocker lock(&m);
    if (migrationDone) return;
    migrationDone = true;
    migrateLegacyGpgStore();
}

void CredentialStore::setSessionSecret(const QUuid& profileId, SecretField field,
                                       const QString& secret) {
    const QString key = compoundKey(profileId, field);
    if (secret.isEmpty()) d->session.remove(key);
    else                  d->session.insert(key, secret);
}

void CredentialStore::clearSessionSecrets(const QUuid& profileId) {
    for (SecretField f : kAllFields) d->session.remove(compoundKey(profileId, f));
}

bool CredentialStore::store(const QUuid& profileId, SecretField field,
                            const QString& secret) {
    if (secret.isEmpty()) return forget(profileId, field);
    ensureLegacyMigration();
    const QString key = compoundKey(profileId, field);
    bool ok = false;
#ifdef HAVE_KF6
    if (d->tryOpenWallet())
        ok = d->wallet->writePassword(key, secret) == 0;
    else
#endif
    if (secretservice::available())
        ok = secretservice::store(key, secret);
    else if (encfilestore::haveCrypto())
        ok = encfilestore::store(key, secret);
    // else: no secure backend — refuse rather than write plaintext.
    if (ok) d->session.remove(key);          // durable copy wins
    else    Logger::instance().warn(QStringLiteral(
                "could not store secret '%1' in %2").arg(key, backendDescription()));
    return ok;
}

bool CredentialStore::retrieve(const QUuid& profileId, SecretField field,
                               QString* outSecret) {
    if (!outSecret) return false;
    const QString key = compoundKey(profileId, field);
    if (const auto it = d->session.constFind(key); it != d->session.constEnd()) {
        *outSecret = it.value();
        return true;
    }
    ensureLegacyMigration();
#ifdef HAVE_KF6
    if (d->tryOpenWallet()) {
        QString s;
        if (d->wallet->readPassword(key, s) == 0 && !s.isEmpty()) {
            *outSecret = s;
            return true;
        }
    }
#endif
    if (secretservice::available() && secretservice::lookup(key, outSecret))
        return true;
    // Only pay the master-password-prompt cost if there is at least one
    // entry on disk; a first-launch install shouldn't nag.
    if (encfilestore::haveCrypto() && encfilestore::hasAnyStoredEntry()
            && encfilestore::lookup(key, outSecret))
        return true;
    return false;
}

bool CredentialStore::forget(const QUuid& profileId, SecretField field) {
    const QString key = compoundKey(profileId, field);
    d->session.remove(key);
#ifdef HAVE_KF6
    if (d->tryOpenWallet()) d->wallet->removeEntry(key);
#endif
    if (secretservice::available()) secretservice::clear(key);
    if (encfilestore::haveCrypto()) encfilestore::clear(key);
    return true;
}

bool CredentialStore::forget(const QUuid& profileId) {
    for (SecretField f : kAllFields) forget(profileId, f);
    return true;
}

} // namespace inode
