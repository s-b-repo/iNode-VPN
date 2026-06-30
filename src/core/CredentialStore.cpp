#include "CredentialStore.h"

#include "SecretServiceStore.h"

#include <QByteArray>
#include <QCryptographicHash>
#include <QSettings>

#ifdef HAVE_KF6
#include <KWallet>
#endif

namespace inode {

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

    QSettings fallback{QStringLiteral("iNodeClient-Qt"), QStringLiteral("credentials")};
};

static QByteArray scramble(const QByteArray& in, const QByteArray& key) {
    QByteArray out = in;
    for (int i = 0; i < out.size(); ++i) out[i] = out[i] ^ key[i % key.size()];
    return out;
}

static QByteArray machineKey() {
    // Not a secret — just a stable-per-host byte sequence for the fallback.
    const auto h = QCryptographicHash::hash(QByteArrayLiteral("iNodeClient-Qt-v1"),
                                            QCryptographicHash::Sha256);
    return h;
}

CredentialStore::CredentialStore() : d(new Impl) {}
CredentialStore::~CredentialStore() { delete d; }

CredentialStore& CredentialStore::instance() {
    static CredentialStore s;
    return s;
}

bool CredentialStore::isSecureBackend() const {
#ifdef HAVE_KF6
    if (d->wallet && d->wallet->isOpen()) return true;
#endif
    // Portable secure store via the freedesktop Secret Service (gnome-keyring,
    // ksecretd, KeePassXC, …) — covers most non-KDE distros.
    return secretservice::available();
}

bool CredentialStore::store(const QUuid& profileId, const QString& secret) {
    const QString key = profileId.toString(QUuid::WithoutBraces);
#ifdef HAVE_KF6
    if (d->tryOpenWallet())
        return d->wallet->writePassword(key, secret) == 0;
#endif
    if (secretservice::available())
        return secretservice::store(key, secret);
    const auto enc = scramble(secret.toUtf8(), machineKey()).toBase64();
    d->fallback.setValue(key, enc);
    return true;
}

bool CredentialStore::retrieve(const QUuid& profileId, QString* outSecret) {
    if (!outSecret) return false;
    const QString key = profileId.toString(QUuid::WithoutBraces);
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
    if (!d->fallback.contains(key)) return false;
    const auto raw = QByteArray::fromBase64(d->fallback.value(key).toByteArray());
    *outSecret = QString::fromUtf8(scramble(raw, machineKey()));
    return true;
}

bool CredentialStore::forget(const QUuid& profileId) {
    const QString key = profileId.toString(QUuid::WithoutBraces);
#ifdef HAVE_KF6
    if (d->tryOpenWallet()) d->wallet->removeEntry(key);
#endif
    if (secretservice::available()) secretservice::clear(key);
    d->fallback.remove(key);
    return true;
}

} // namespace inode
