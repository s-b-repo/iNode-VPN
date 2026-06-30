#pragma once

#include <QString>
#include <QUuid>

namespace inode {

// Abstraction over credential storage. Tries, in order:
//   1. KWallet (KF6::Wallet) when linked and open — KDE-native.
//   2. The freedesktop **Secret Service** (libsecret, dlopen'd at runtime) —
//      gnome-keyring / ksecretd / KeePassXC etc., covering most non-KDE distros.
//   3. A QSettings keyed-XOR scramble fallback — NOT secure against a local
//      attacker; exists only so the app is usable where no keyring is present.
//      The UI shows a warning when only this fallback is active.
class CredentialStore {
public:
    static CredentialStore& instance();

    bool isSecureBackend() const;

    bool store(const QUuid& profileId, const QString& secret);
    bool retrieve(const QUuid& profileId, QString* outSecret);
    bool forget(const QUuid& profileId);

private:
    CredentialStore();
    ~CredentialStore();
    CredentialStore(const CredentialStore&) = delete;
    CredentialStore& operator=(const CredentialStore&) = delete;

    struct Impl;
    Impl* d;
};

} // namespace inode
