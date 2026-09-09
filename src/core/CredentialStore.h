#pragma once

#include <QString>
#include <QUuid>

#include <functional>

namespace inode {

// Named secret fields per profile. Each maps to a distinct entry in the
// backend keyring under the compound key "<uuid>/<field>". Adding a new
// kind of secret only takes appending an enumerator here and teaching
// ProfileStore how to route it.
enum class SecretField {
    Password = 0,     // primary connection password
    Psk,              // IPSec pre-shared key
    PortalSecret,     // portal shared secret
    SpaKey,           // SDP/SPA HOTP hex key
    CertPin,          // user cert PKCS#12 pin
};

// Abstraction over credential storage. Tries, in order:
//   1. KWallet (KF6::Wallet) when linked and open — KDE-native; the wallet
//      itself is unlocked by the user's login password via PAM by default.
//   2. The freedesktop **Secret Service** (libsecret, dlopen'd at runtime) —
//      gnome-keyring / ksecretd / KeePassXC etc. On most distros the default
//      collection is "login" and is unlocked by the login password via PAM.
//   3. A local AES-256-GCM + PBKDF2 file, unlocked by a master password the
//      user types on first use (cached in memory for the session only). Used
//      as a last resort when no keyring daemon is available.
//
// Legacy migration: credentials written by the removed system-GnuPG backend
// (a gpg-sealed `secrets.gpg`) are transparently re-sealed into the active
// backend on first use, after which the legacy file is renamed
// `secrets.gpg.migrated`. gpg-agent/pinentry handles the passphrase during
// that one-time decrypt — this app still never sees it.
//
// The XOR "scramble" fallback that shipped in earlier versions has been
// removed — every path now writes ciphertext to disk.
class CredentialStore {
public:
    static CredentialStore& instance();

    enum class Backend {
        None = 0,        // no backend usable (locked/refused/no libcrypto)
        KWallet,
        SecretService,
        EncryptedFile,
    };
    Backend activeBackend() const;
    bool isSecureBackend() const;          // true for any Backend != None
    QString backendDescription() const;    // short human-readable name

    // Prompt used by the encrypted-file backend to obtain the master password.
    //   reason: short line to show to the user ("Unlock" / "Set" / retry).
    //   confirm: when true, ask the user to type it twice (first-time setup).
    // Return an empty QString to cancel — the operation then fails cleanly.
    using PasswordPrompt =
        std::function<QString(const QString& reason, bool confirm)>;
    void setPasswordPrompt(PasswordPrompt p);

    // Multi-field API. store() with an empty secret is equivalent to forget().
    bool store(const QUuid& profileId, SecretField field, const QString& secret);
    bool retrieve(const QUuid& profileId, SecretField field, QString* outSecret);
    bool forget(const QUuid& profileId, SecretField field);

    // Compatibility shims — operate on SecretField::Password so existing call
    // sites (protocols, MainWindow::persistPassword) keep working unchanged.
    bool store(const QUuid& profileId, const QString& secret) {
        return store(profileId, SecretField::Password, secret);
    }
    bool retrieve(const QUuid& profileId, QString* outSecret) {
        return retrieve(profileId, SecretField::Password, outSecret);
    }

    // Clears every field for the profile (used when a profile is removed).
    bool forget(const QUuid& profileId);

    // Session-only secrets: a password typed at connect time (or one the user
    // chose not to store, or that the backend refused to store) is kept in
    // memory for the lifetime of this process so the connection can proceed.
    // retrieve() consults this overlay first. Never written to disk.
    void setSessionSecret(const QUuid& profileId, SecretField field, const QString& secret);
    void setSessionSecret(const QUuid& profileId, const QString& secret) {
        setSessionSecret(profileId, SecretField::Password, secret);
    }
    void clearSessionSecrets(const QUuid& profileId);

private:
    CredentialStore();
    ~CredentialStore();
    CredentialStore(const CredentialStore&) = delete;
    CredentialStore& operator=(const CredentialStore&) = delete;

    // One-time re-seal of a leftover secrets.gpg (removed GnuPG backend) into
    // the active backend; idempotent, gpg-agent handles the passphrase.
    void migrateLegacyGpgStore();
    // ensureLegacyMigration(): at-most-once wrapper (safe under event-loop
    // re-entrancy while a prompt dialog is open).
    void ensureLegacyMigration();

    struct Impl;
    Impl* d;
};

} // namespace inode
