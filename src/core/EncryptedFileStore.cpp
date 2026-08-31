#include "EncryptedFileStore.h"

#include <QByteArray>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QSettings>
#include <QStandardPaths>

#include <dlfcn.h>
#include <cstring>

namespace inode {
namespace encfilestore {
namespace {

// --- Minimal OpenSSL ABI. We dlopen libcrypto so there is no build-time
//     dependency; the shape below matches OpenSSL 1.1 / 3.x, which is what
//     every Linux distro this app targets ships. -------------------------

extern "C" {
struct EVP_CIPHER;         // opaque
struct EVP_CIPHER_CTX;     // opaque
struct EVP_MD;             // opaque
struct ENGINE;             // opaque

using evp_cipher_ctx_new_fn  = EVP_CIPHER_CTX* (*)();
using evp_cipher_ctx_free_fn = void (*)(EVP_CIPHER_CTX*);
using evp_aes_256_gcm_fn     = const EVP_CIPHER* (*)();
using evp_sha256_fn          = const EVP_MD* (*)();
using evp_encrypt_init_ex_fn = int (*)(EVP_CIPHER_CTX*, const EVP_CIPHER*, ENGINE*,
                                       const unsigned char* key,
                                       const unsigned char* iv);
using evp_encrypt_update_fn  = int (*)(EVP_CIPHER_CTX*, unsigned char* out, int* outl,
                                       const unsigned char* in, int inl);
using evp_encrypt_final_fn   = int (*)(EVP_CIPHER_CTX*, unsigned char* out, int* outl);
using evp_decrypt_init_ex_fn = int (*)(EVP_CIPHER_CTX*, const EVP_CIPHER*, ENGINE*,
                                       const unsigned char* key,
                                       const unsigned char* iv);
using evp_decrypt_update_fn  = int (*)(EVP_CIPHER_CTX*, unsigned char* out, int* outl,
                                       const unsigned char* in, int inl);
using evp_decrypt_final_fn   = int (*)(EVP_CIPHER_CTX*, unsigned char* out, int* outl);
using evp_cipher_ctx_ctrl_fn = int (*)(EVP_CIPHER_CTX*, int type, int arg, void* ptr);
using pkcs5_pbkdf2_fn        = int (*)(const char* pass, int passlen,
                                       const unsigned char* salt, int saltlen,
                                       int iter, const EVP_MD* digest,
                                       int keylen, unsigned char* out);
using rand_bytes_fn          = int (*)(unsigned char* buf, int num);
}

// GCM ctrl codes are stable across OpenSSL 1.1+ / 3.x.
constexpr int kEvpCtrlGcmSetIvLen = 0x9;
constexpr int kEvpCtrlGcmGetTag   = 0x10;
constexpr int kEvpCtrlGcmSetTag   = 0x11;

constexpr int kSaltLen  = 16;
constexpr int kIvLen    = 12;   // GCM standard nonce
constexpr int kTagLen   = 16;   // GCM tag
constexpr int kKeyLen   = 32;   // AES-256
constexpr int kIters    = 200000;
constexpr int kVersion  = 1;

struct Lib {
    void* handle = nullptr;
    evp_cipher_ctx_new_fn   ctx_new  = nullptr;
    evp_cipher_ctx_free_fn  ctx_free = nullptr;
    evp_aes_256_gcm_fn      aes_gcm  = nullptr;
    evp_sha256_fn           sha256   = nullptr;
    evp_encrypt_init_ex_fn  enc_init = nullptr;
    evp_encrypt_update_fn   enc_upd  = nullptr;
    evp_encrypt_final_fn    enc_fin  = nullptr;
    evp_decrypt_init_ex_fn  dec_init = nullptr;
    evp_decrypt_update_fn   dec_upd  = nullptr;
    evp_decrypt_final_fn    dec_fin  = nullptr;
    evp_cipher_ctx_ctrl_fn  ctx_ctrl = nullptr;
    pkcs5_pbkdf2_fn         pbkdf2   = nullptr;
    rand_bytes_fn           rand_b   = nullptr;
    bool ok = false;

    Lib() {
        // Try the SONAMEs distros actually ship, newest first.
        const char* candidates[] = {
            "libcrypto.so.3", "libcrypto.so.1.1", "libcrypto.so", nullptr };
        for (int i = 0; candidates[i] && !handle; ++i)
            handle = dlopen(candidates[i], RTLD_NOW | RTLD_GLOBAL);
        if (!handle) return;

        ctx_new  = reinterpret_cast<evp_cipher_ctx_new_fn >(dlsym(handle, "EVP_CIPHER_CTX_new"));
        ctx_free = reinterpret_cast<evp_cipher_ctx_free_fn>(dlsym(handle, "EVP_CIPHER_CTX_free"));
        aes_gcm  = reinterpret_cast<evp_aes_256_gcm_fn    >(dlsym(handle, "EVP_aes_256_gcm"));
        sha256   = reinterpret_cast<evp_sha256_fn         >(dlsym(handle, "EVP_sha256"));
        enc_init = reinterpret_cast<evp_encrypt_init_ex_fn>(dlsym(handle, "EVP_EncryptInit_ex"));
        enc_upd  = reinterpret_cast<evp_encrypt_update_fn >(dlsym(handle, "EVP_EncryptUpdate"));
        enc_fin  = reinterpret_cast<evp_encrypt_final_fn  >(dlsym(handle, "EVP_EncryptFinal_ex"));
        dec_init = reinterpret_cast<evp_decrypt_init_ex_fn>(dlsym(handle, "EVP_DecryptInit_ex"));
        dec_upd  = reinterpret_cast<evp_decrypt_update_fn >(dlsym(handle, "EVP_DecryptUpdate"));
        dec_fin  = reinterpret_cast<evp_decrypt_final_fn  >(dlsym(handle, "EVP_DecryptFinal_ex"));
        ctx_ctrl = reinterpret_cast<evp_cipher_ctx_ctrl_fn>(dlsym(handle, "EVP_CIPHER_CTX_ctrl"));
        pbkdf2   = reinterpret_cast<pkcs5_pbkdf2_fn       >(dlsym(handle, "PKCS5_PBKDF2_HMAC"));
        rand_b   = reinterpret_cast<rand_bytes_fn         >(dlsym(handle, "RAND_bytes"));

        ok = ctx_new && ctx_free && aes_gcm && sha256 && enc_init && enc_upd && enc_fin
          && dec_init && dec_upd && dec_fin && ctx_ctrl && pbkdf2 && rand_b;
    }
};

Lib& lib() { static Lib l; return l; }

// A single INI file, opened lazily. Keep a global so header updates
// (salt/verifier) and entry writes go through one QSettings instance.
QString filePath() {
    QString dir = QStandardPaths::writableLocation(QStandardPaths::AppConfigLocation);
    QDir().mkpath(dir);
    return dir + QStringLiteral("/secrets.enc");
}

// The store holds ciphertext, but the header (salt + verifier) still leaks
// offline-cracking material to every local user if the file is group/other
// readable. QSettings writes with the process umask, which is frequently
// 022 -> 0644. Force 0600 after every sync point.
QSettings& file() {
    static QSettings s(filePath(), QSettings::IniFormat);
    return s;
}

bool syncAndHarden() {
    file().sync();
    if (file().status() != QSettings::NoError) return false;
    QFile f(filePath());
    if (f.exists())
        f.setPermissions(QFile::ReadOwner | QFile::WriteOwner);
    return true;
}

// --- Session state (in-memory only) -----------------------------------

struct Session {
    QByteArray key;         // 32 bytes derived via PBKDF2
    bool unlocked = false;
    PromptFn prompt;

    ~Session() {
        if (!key.isEmpty()) {
            // Best-effort scrub. QByteArray may CoW, but on shutdown this
            // is the only reference — the memset actually runs on our data.
            std::memset(key.data(), 0, key.size());
        }
    }
};
Session& session() { static Session s; return s; }

// --- Crypto helpers ---------------------------------------------------

bool randomBytes(void* buf, int n) {
    return lib().rand_b(static_cast<unsigned char*>(buf), n) == 1;
}

QByteArray derive(const QByteArray& password, const QByteArray& salt, int iters) {
    QByteArray out(kKeyLen, 0);
    const int r = lib().pbkdf2(password.constData(), password.size(),
                               reinterpret_cast<const unsigned char*>(salt.constData()),
                               salt.size(), iters, lib().sha256(),
                               kKeyLen, reinterpret_cast<unsigned char*>(out.data()));
    return r == 1 ? out : QByteArray();
}

// AES-256-GCM seal → nonce || ciphertext || tag (raw bytes).
QByteArray seal(const QByteArray& key, const QByteArray& plaintext) {
    Lib& l = lib();
    if (key.size() != kKeyLen) return {};
    unsigned char iv[kIvLen];
    if (!randomBytes(iv, kIvLen)) return {};

    EVP_CIPHER_CTX* ctx = l.ctx_new();
    if (!ctx) return {};
    QByteArray out;
    out.reserve(kIvLen + plaintext.size() + kTagLen);
    out.append(reinterpret_cast<char*>(iv), kIvLen);

    bool ok = l.enc_init(ctx, l.aes_gcm(), nullptr, nullptr, nullptr) == 1
           && l.ctx_ctrl(ctx, kEvpCtrlGcmSetIvLen, kIvLen, nullptr) == 1
           && l.enc_init(ctx, nullptr, nullptr,
                         reinterpret_cast<const unsigned char*>(key.constData()),
                         iv) == 1;
    if (ok) {
        QByteArray ct(plaintext.size() + 64, 0);   // slack for block size
        int len = 0;
        if (l.enc_upd(ctx, reinterpret_cast<unsigned char*>(ct.data()), &len,
                      reinterpret_cast<const unsigned char*>(plaintext.constData()),
                      plaintext.size()) != 1) ok = false;
        int total = len;
        if (ok && l.enc_fin(ctx, reinterpret_cast<unsigned char*>(ct.data()) + total, &len) != 1)
            ok = false;
        total += len;
        if (ok) {
            unsigned char tag[kTagLen];
            if (l.ctx_ctrl(ctx, kEvpCtrlGcmGetTag, kTagLen, tag) != 1) ok = false;
            if (ok) {
                out.append(ct.constData(), total);
                out.append(reinterpret_cast<char*>(tag), kTagLen);
            }
        }
    }
    l.ctx_free(ctx);
    return ok ? out : QByteArray();
}

// AES-256-GCM open. Returns empty on tag mismatch (wrong key/tamper).
QByteArray open(const QByteArray& key, const QByteArray& sealed) {
    Lib& l = lib();
    if (key.size() != kKeyLen || sealed.size() < kIvLen + kTagLen) return {};
    const unsigned char* iv  = reinterpret_cast<const unsigned char*>(sealed.constData());
    const unsigned char* ct  = iv + kIvLen;
    const int ctLen          = sealed.size() - kIvLen - kTagLen;
    unsigned char tag[kTagLen];
    std::memcpy(tag, sealed.constData() + kIvLen + ctLen, kTagLen);

    EVP_CIPHER_CTX* ctx = l.ctx_new();
    if (!ctx) return {};
    QByteArray out(ctLen + 64, 0);
    bool ok = l.dec_init(ctx, l.aes_gcm(), nullptr, nullptr, nullptr) == 1
           && l.ctx_ctrl(ctx, kEvpCtrlGcmSetIvLen, kIvLen, nullptr) == 1
           && l.dec_init(ctx, nullptr, nullptr,
                         reinterpret_cast<const unsigned char*>(key.constData()),
                         iv) == 1;
    int total = 0;
    if (ok) {
        int len = 0;
        if (l.dec_upd(ctx, reinterpret_cast<unsigned char*>(out.data()), &len, ct, ctLen) != 1)
            ok = false;
        total = len;
    }
    if (ok) {
        if (l.ctx_ctrl(ctx, kEvpCtrlGcmSetTag, kTagLen, tag) != 1) ok = false;
    }
    if (ok) {
        int len = 0;
        // Final returns 0 on tag mismatch — that's how we detect wrong password.
        if (l.dec_fin(ctx, reinterpret_cast<unsigned char*>(out.data()) + total, &len) != 1)
            ok = false;
        total += len;
    }
    l.ctx_free(ctx);
    if (!ok) return {};
    out.resize(total);
    return out;
}

// --- Header helpers ---------------------------------------------------

const char* kVerifierPlaintext = "iNodeClient-Qt: verifier v1";

bool headerExists() {
    return file().contains(QStringLiteral("header/salt"))
        && file().contains(QStringLiteral("header/verifier"));
}

QByteArray currentSalt() {
    return QByteArray::fromBase64(
        file().value(QStringLiteral("header/salt")).toByteArray());
}

int currentIters() {
    return file().value(QStringLiteral("header/iters"), kIters).toInt();
}

bool writeHeaderAndVerifier(const QByteArray& salt, int iters, const QByteArray& key) {
    const QByteArray sealed = seal(key, QByteArray(kVerifierPlaintext));
    if (sealed.isEmpty()) return false;
    file().setValue(QStringLiteral("header/version"), kVersion);
    file().setValue(QStringLiteral("header/iters"), iters);
    file().setValue(QStringLiteral("header/salt"), salt.toBase64());
    file().setValue(QStringLiteral("header/verifier"), sealed.toBase64());
    return syncAndHarden();
}

bool verifierMatches(const QByteArray& key) {
    const QByteArray sealed = QByteArray::fromBase64(
        file().value(QStringLiteral("header/verifier")).toByteArray());
    const QByteArray got = open(key, sealed);
    return got == QByteArray(kVerifierPlaintext);
}

} // namespace

// --- Public API -------------------------------------------------------

void setPrompt(PromptFn p) { session().prompt = std::move(p); }
bool haveCrypto() { return lib().ok; }
bool isUnlocked() { return session().unlocked; }

bool hasAnyStoredEntry() {
    if (!QFileInfo::exists(filePath())) return false;
    // Any child key under [entries] counts. QSettings::childKeys() at the
    // group level gives us the entry names directly.
    file().beginGroup(QStringLiteral("entries"));
    const bool any = !file().childKeys().isEmpty();
    file().endGroup();
    return any;
}

bool unlock() {
    Session& s = session();
    if (s.unlocked) return true;
    if (!lib().ok || !s.prompt) return false;

    if (!headerExists()) {
        // First-time setup: prompt with confirmation, generate salt, seal
        // the verifier.
        const QString pw = s.prompt(QStringLiteral("Set"), true);
        if (pw.isEmpty()) return false;
        unsigned char saltBytes[kSaltLen];
        if (!randomBytes(saltBytes, kSaltLen)) return false;
        const QByteArray salt(reinterpret_cast<char*>(saltBytes), kSaltLen);
        const QByteArray key = derive(pw.toUtf8(), salt, kIters);
        if (key.isEmpty()) return false;
        if (!writeHeaderAndVerifier(salt, kIters, key)) return false;
        s.key = key;
        s.unlocked = true;
        return true;
    }

    // Existing store — try up to a few times before giving up.
    const QByteArray salt = currentSalt();
    const int iters = currentIters();
    for (int attempt = 0; attempt < 3; ++attempt) {
        const QString reason = attempt == 0 ? QStringLiteral("Unlock")
                                            : QStringLiteral("Wrong password, try again");
        const QString pw = s.prompt(reason, false);
        if (pw.isEmpty()) return false;
        const QByteArray key = derive(pw.toUtf8(), salt, iters);
        if (!key.isEmpty() && verifierMatches(key)) {
            s.key = key;
            s.unlocked = true;
            return true;
        }
    }
    return false;
}

bool store(const QString& key, const QString& secret) {
    if (!unlock()) return false;
    const QByteArray sealed = seal(session().key, secret.toUtf8());
    if (sealed.isEmpty()) return false;
    file().setValue(QStringLiteral("entries/") + key, sealed.toBase64());
    return syncAndHarden();
}

bool lookup(const QString& key, QString* outSecret) {
    if (!outSecret) return false;
    if (!unlock()) return false;
    const QVariant v = file().value(QStringLiteral("entries/") + key);
    if (!v.isValid()) return false;
    const QByteArray sealed = QByteArray::fromBase64(v.toByteArray());
    const QByteArray pt = open(session().key, sealed);
    if (pt.isEmpty()) return false;
    *outSecret = QString::fromUtf8(pt);
    return true;
}

bool clear(const QString& key) {
    // Removing an entry doesn't require the master password — a locked-out
    // user must still be able to delete profiles.
    file().remove(QStringLiteral("entries/") + key);
    return syncAndHarden();
}

} // namespace encfilestore
} // namespace inode
