#pragma once

#include <QString>

namespace inode {

// Freedesktop **Secret Service** credential backend (libsecret), loaded at
// runtime via dlopen so there is NO build-time dependency. This is the portable
// secure store: it talks to whatever Secret Service daemon the session provides
// — gnome-keyring (GNOME/XFCE/Cinnamon/most distros), KWallet's Secret Service
// bridge (ksecretd), KeePassXC, etc. — covering the non-KDE installs that the
// KWallet-only backend misses. Falls through cleanly when unavailable.
namespace secretservice {

// True only if libsecret is present AND a Secret Service daemon round-trips a
// probe secret (so the UI can honestly report "secure storage"). Cached.
bool available();

bool store(const QString& key, const QString& secret);
bool lookup(const QString& key, QString* outSecret);   // false if missing/error
bool clear(const QString& key);

} // namespace secretservice
} // namespace inode
