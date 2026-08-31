#pragma once

#include <QString>

#include <functional>

namespace inode {

// Local encrypted credential backend used when no keyring daemon is
// available. Every entry is sealed with AES-256-GCM under a key derived
// from the user's master password via PBKDF2-HMAC-SHA256 (200 000
// iterations, per-file random salt). The master password never touches
// disk — it lives in memory only for the app's lifetime, and the derived
// key is zeroed on shutdown.
//
// File layout (INI, ~/.config/iNodeClient-Qt/secrets.enc):
//   [header]
//   version=1
//   iters=200000
//   salt=<base64 16 bytes>
//   verifier=<base64 nonce||ct||tag of a known plaintext>
//   [entries]
//   <profile-key>=<base64 nonce||ct||tag>
namespace encfilestore {

// Callback the store uses to obtain the user's master password.
//   reason:  "Set" (first-time) / "Unlock" / "Wrong password, try again".
//   confirm: true → prompt for confirmation (first-time setup).
// Return an empty QString to cancel; every store/lookup then fails cleanly.
using PromptFn = std::function<QString(const QString& reason, bool confirm)>;
void setPrompt(PromptFn p);

// True iff libcrypto could be dlopen'd. Says nothing about whether the
// user has unlocked the store — call unlock() for that.
bool haveCrypto();

// Attempt to unlock (or first-time-init) the store using the registered
// prompt. Cached: further calls become no-ops after success. Returns false
// if the user cancels or crypto is unavailable.
bool unlock();

// True after a successful unlock() this session.
bool isUnlocked();

// Same shape as SecretServiceStore's API. Return false if not unlocked,
// crypto missing, or the operation fails.
bool store(const QString& key, const QString& secret);
bool lookup(const QString& key, QString* outSecret);
bool clear(const QString& key);

// True iff at least one stored entry exists on disk (used by CredentialStore
// to decide whether to prompt at startup — a first-launch install with no
// stored secrets shouldn't nag).
bool hasAnyStoredEntry();

} // namespace encfilestore
} // namespace inode
