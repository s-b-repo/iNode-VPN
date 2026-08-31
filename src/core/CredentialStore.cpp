#include "CredentialStore.h"

#include "EncryptedFileStore.h"
#include "GpgFileStore.h"
#include "SecretServiceStore.h"

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

} // namespace

struct CredentialStore::Impl {
#ifdef HAVE_KF6
    KWallet::Wallet* wallet = nullptr;
    bool tryOpenWallet() {
        if (wallet && wallet->isOpen()) return true;
        wallet = KWallet::Wallet::openWallet(KWallet::Wallet::NetworkWallet(), 0);
        if (!wallet) return false;
        if (!wallet->hasFolder(QStringLiteral("iNodeClient-Qt")))
            wallet->createFolder(QStringLiteral("iNodeClient-Qt"));
        wallet->setFolder(QStringLiteral("iNodeClient-Qt"));
        return true;
    }
#endif
};

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
    if (gpgstore::available())      return Backend::GpgFile;
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
        case Backend::GpgFile:
            return gpgstore::description();
        case Backend::EncryptedFile:
            return QStringLiteral("AES-256-GCM file (master password)");
        case Backend::None:
            return QStringLiteral("no secure backend available");
    }
    return {};
}

bool CredentialStore::store(const QUuid& profileId, SecretField field,
                            const QString& secret) {
    if (secret.isEmpty()) return forget(profileId, field);
    const QString key = compoundKey(profileId, field);
#ifdef HAVE_KF6
    if (d->tryOpenWallet())
        return d->wallet->writePassword(key, secret) == 0;
#endif
    if (secretservice::available())
        return secretservice::store(key, secret);
    if (gpgstore::available())
        return gpgstore::store(key, secret);
    if (encfilestore::haveCrypto())
        return encfilestore::store(key, secret);
    return false;   // no secure backend — refuse rather than write plaintext
}

bool CredentialStore::retrieve(const QUuid& profileId, SecretField field,
                               QString* outSecret) {
    if (!outSecret) return false;
    const QString key = compoundKey(profileId, field);
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
    // GPG: gpg-agent prompts through pinentry when the key is not yet
    // unlocked; the agent caches for the session like any other GPG use.
    if (gpgstore::available() && gpgstore::lookup(key, outSecret))
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
#ifdef HAVE_KF6
    if (d->tryOpenWallet()) d->wallet->removeEntry(key);
#endif
    if (secretservice::available()) secretservice::clear(key);
    if (gpgstore::available()) gpgstore::clear(key);
    if (encfilestore::haveCrypto()) encfilestore::clear(key);
    return true;
}

bool CredentialStore::forget(const QUuid& profileId) {
    for (SecretField f : kAllFields) forget(profileId, f);
    return true;
}

} // namespace inode
