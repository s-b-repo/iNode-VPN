#include "SecretServiceStore.h"

#include <dlfcn.h>

namespace inode {
namespace secretservice {
namespace {

// --- Minimal libsecret/glib ABI (we only dlopen the C "simple password" API) -
extern "C" {
using gboolean = int;
using gchar = char;
struct GError { unsigned int domain; int code; char* message; };

struct SecretSchemaAttribute { const char* name; int type; };  // type: 0 = string
struct SecretSchema {
    const char* name;
    int flags;                                   // 0 = SECRET_SCHEMA_NONE
    SecretSchemaAttribute attributes[32];
    // trailing reserved fields (kept so our struct matches libsecret's size)
    int reserved;
    void* r1; void* r2; void* r3; void* r4; void* r5; void* r6; void* r7;
};

using store_fn  = gboolean (*)(const SecretSchema*, const char* collection,
                               const char* label, const char* password,
                               void* cancellable, GError** error, ...);
using lookup_fn = gchar*   (*)(const SecretSchema*, void* cancellable,
                               GError** error, ...);
using clear_fn  = gboolean (*)(const SecretSchema*, void* cancellable,
                               GError** error, ...);
using pwfree_fn = void     (*)(void*);
using errfree_fn = void    (*)(GError*);
}

// One schema shared by all of our entries; attribute "profile" = the key.
const SecretSchema kSchema = {
    "org.inode.ClientQt.Credential", 0,
    { { "profile", 0 }, { nullptr, 0 } },
    0, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr
};

struct Lib {
    void*      handle = nullptr;
    store_fn   store  = nullptr;
    lookup_fn  lookup = nullptr;
    clear_fn   clear  = nullptr;
    pwfree_fn  pwfree = nullptr;
    errfree_fn errfree = nullptr;
    bool       ok = false;

    Lib() {
        handle = dlopen("libsecret-1.so.0", RTLD_NOW | RTLD_GLOBAL);
        if (!handle) return;
        store  = reinterpret_cast<store_fn>(dlsym(handle, "secret_password_store_sync"));
        lookup = reinterpret_cast<lookup_fn>(dlsym(handle, "secret_password_lookup_sync"));
        clear  = reinterpret_cast<clear_fn>(dlsym(handle, "secret_password_clear_sync"));
        pwfree = reinterpret_cast<pwfree_fn>(dlsym(handle, "secret_password_free"));
        // g_error_free lives in glib (a libsecret dependency).
        errfree = reinterpret_cast<errfree_fn>(dlsym(handle, "g_error_free"));
        if (!errfree) {
            if (void* glib = dlopen("libglib-2.0.so.0", RTLD_NOW | RTLD_GLOBAL))
                errfree = reinterpret_cast<errfree_fn>(dlsym(glib, "g_error_free"));
        }
        ok = store && lookup && clear && pwfree;
    }
};

Lib& lib() { static Lib l; return l; }

void freeError(GError* e) {
    if (e && lib().errfree) lib().errfree(e);
}

} // namespace

bool store(const QString& key, const QString& secret) {
    Lib& l = lib();
    if (!l.ok) return false;
    const QByteArray k = key.toUtf8();
    const QByteArray pw = secret.toUtf8();
    const QByteArray label = QByteArrayLiteral("iNode Client — ") + k;
    GError* err = nullptr;
    gboolean r = l.store(&kSchema, nullptr /*default collection*/, label.constData(),
                         pw.constData(), nullptr, &err,
                         "profile", k.constData(), static_cast<const char*>(nullptr));
    if (err) { freeError(err); return false; }
    return r != 0;
}

bool lookup(const QString& key, QString* outSecret) {
    Lib& l = lib();
    if (!l.ok || !outSecret) return false;
    const QByteArray k = key.toUtf8();
    GError* err = nullptr;
    gchar* pw = l.lookup(&kSchema, nullptr, &err,
                         "profile", k.constData(), static_cast<const char*>(nullptr));
    if (err) { freeError(err); return false; }
    if (!pw) return false;                 // no entry
    *outSecret = QString::fromUtf8(pw);
    l.pwfree(pw);
    return true;
}

bool clear(const QString& key) {
    Lib& l = lib();
    if (!l.ok) return false;
    const QByteArray k = key.toUtf8();
    GError* err = nullptr;
    gboolean r = l.clear(&kSchema, nullptr, &err,
                         "profile", k.constData(), static_cast<const char*>(nullptr));
    if (err) { freeError(err); return false; }
    return r != 0;
}

bool available() {
    // Probe once: round-trip a sentinel so we only claim "secure" when a daemon
    // actually answers (libsecret present but no running service must read false).
    static const bool probed = [] {
        if (!lib().ok) return false;
        const QString k = QStringLiteral("__probe__");
        if (!store(k, QStringLiteral("1"))) return false;
        QString back;
        const bool ok = lookup(k, &back) && back == QStringLiteral("1");
        clear(k);
        return ok;
    }();
    return probed;
}

} // namespace secretservice
} // namespace inode
