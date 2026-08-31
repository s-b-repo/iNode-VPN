#pragma once

#include <QString>

namespace inode {

// System-GnuPG credential backend. Every credential is sealed with the
// user's own GPG setup — either to their default secret key (asymmetric,
// agent + pinentry handle the passphrase) or, when no key exists,
// symmetric (gpg prompts via pinentry on first write / read).
//
// Nothing here ever sees a passphrase: gpg-agent owns the keys and does the
// prompting, so this backend integrates with whatever pinentry the desktop
// ships (Qt, GTK, curses) and caches unlocks in the agent like every other
// GPG user on the system.
//
// On-disk layout: a single ASCII-armored file
//   ~/.config/iNodeClient-Qt/secrets.gpg
// whose plaintext is lines of "<key>\t<base64(secret)>" under a version
// header. Atomic replace on write, 0600 on the armored file.
namespace gpgstore {

// True iff a usable gpg binary was found. Does not guarantee a key exists —
// symmetric mode always works if gpg itself works.
bool available();

// Short human-readable description of the resolved mode,
// e.g. "GPG (key 3F2A…)" or "GPG (symmetric, pinentry)".
QString description();

// Same shape as the other credential backends.
bool store(const QString& key, const QString& secret);
bool lookup(const QString& key, QString* outSecret);
bool clear(const QString& key);

} // namespace gpgstore
} // namespace inode
