#include "GpgFileStore.h"

#include <QByteArray>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QMutex>
#include <QMutexLocker>
#include <QProcess>
#include <QStandardPaths>
#include <QTemporaryFile>

#include <atomic>
#include <filesystem>
#include <system_error>

namespace inode {
namespace gpgstore {
namespace {

// Resolve the gpg binary once. Prefer gpg, fall back to gpg2 (older distros).
QString gpgBinary() {
    static const QString path = [] {
        for (const char* name : {"gpg", "gpg2"}) {
            QString p = QStandardPaths::findExecutable(QLatin1String(name));
            if (!p.isEmpty()) return p;
        }
        return QString();
    }();
    return path;
}

QString storePath() {
    QString dir = QStandardPaths::writableLocation(QStandardPaths::AppConfigLocation);
    QDir().mkpath(dir);
    return dir + QStringLiteral("/secrets.gpg");
}

// The gpg process must never inherit our env in a way that changes where the
// agent looks for keys; we simply don't touch the environment. Passphrases
// are exclusively the agent's business (pinentry), never argv/stdin here.
class Gpg {
public:
    Gpg(const QStringList& args) : m_args(args) {}

    // Run gpg with `input` on stdin; return stdout and true on exit 0.
    bool run(const QByteArray& input, QByteArray* out) {
        QProcess proc;
        proc.setProgram(gpgBinary());
        // -q keeps status noise out of stderr; --batch stops any tty prompt.
        proc.setArguments(QStringList() << QStringLiteral("--quiet") << QStringLiteral("--batch")
                                        << m_args);
        proc.start(QIODevice::ReadWrite);
        if (!proc.waitForStarted(5000)) return false;
        if (!input.isEmpty()) {
            if (proc.write(input) != input.size()) {
                proc.kill();
                return false;
            }
        }
        proc.closeWriteChannel();
        if (!proc.waitForFinished(30000)) {
            proc.kill();
            proc.waitForFinished(5000);
            return false;
        }
        if (proc.exitStatus() != QProcess::NormalExit || proc.exitCode() != 0)
            return false;
        if (out) *out = proc.readAllStandardOutput();
        return true;
    }

private:
    QStringList m_args;
};

// First available secret key fingerprint for recipient mode.
// Empty → symmetric mode. Result is memoized; pass refresh=true to re-probe
// (used as a healing path when the cached key was deleted/rotated mid-session).
QString defaultRecipient() {
    QByteArray out;
    Gpg g({QStringLiteral("--list-secret-keys"),
           QStringLiteral("--with-colons"), QStringLiteral("--fixed-list-mode")});
    if (!g.run(QByteArray(), &out)) return {};
    // `--with-colons` emits, per secret key: "sec:" then an "fpr:" record for
    // the primary key (subkeys' fpr records come later). Take the first fpr.
    for (const QByteArray& line : out.split('\n')) {
        if (line.startsWith("fpr:")) {
            const QList<QByteArray> f = line.split(':');
            if (f.size() > 9 && f.at(9).size() >= 16)
                return QString::fromLatin1(f.at(9));
        }
    }
    return {};
}

QString recipient(bool refresh = false) {
    static QString cached;
    static bool have = false;
    if (!have || refresh) {
        cached = defaultRecipient();
        have = true;
    }
    return cached;
}

// --- Payload codec ----------------------------------------------------

constexpr const char* kPayloadHeader = "iNodeClient-Qt gpg credential store v1";

struct Entry { QString key; QString value; };   // value: base64 of utf-8 secret

bool decode(const QByteArray& pt, QVector<Entry>* entries) {
    const QList<QByteArray> lines = pt.split('\n');
    if (lines.isEmpty() || lines.first() != QByteArray(kPayloadHeader))
        return false;
    for (int i = 1; i < lines.size(); ++i) {
        const QByteArray& line = lines.at(i);
        if (line.isEmpty()) continue;
        const int tab = line.indexOf('\t');
        if (tab <= 0) return false;
        entries->append({QString::fromUtf8(line.left(tab)),
                         QString::fromLatin1(line.mid(tab + 1))});
    }
    return true;
}

QByteArray encode(const QVector<Entry>& entries) {
    QByteArray pt(kPayloadHeader);
    pt += '\n';
    for (const Entry& e : entries) {
        pt += e.key.toUtf8();
        pt += '\t';
        pt += e.value.toLatin1();
        pt += '\n';
    }
    return pt;
}

// Serialize all entries: read (decrypting), modify, re-encrypt, atomically
// replace. `mutate` returns false to abort without writing.
template <typename F>
bool mutateStore(F mutate) {
    if (gpgBinary().isEmpty()) return false;

    // Decrypt current contents (empty file / first run is fine).
    // NOTE: the file path MUST be passed as an argument — bare `gpg --decrypt`
    // reads (empty) stdin and every subsequent operation would fail.
    QByteArray current;
    const QString path = storePath();
    if (QFileInfo::exists(path)) {
        Gpg dec({QStringLiteral("--decrypt"), path});
        if (!dec.run(QByteArray(), &current)) return false;   // agent denied / bad blob
    }
    QVector<Entry> entries;
    if (!current.isEmpty() && !decode(current, &entries)) return false;

    if (!mutate(entries)) return false;

    // Re-encrypt. Recipient mode when a secret key exists, symmetric otherwise.
    // If encryption with the cached recipient fails (key deleted/rotated since
    // startup), re-probe once; a fresh empty probe falls back to symmetric.
    // The whole blob is rewritten on every store, so mode switches are safe.
    const QByteArray pt = encode(entries);
    QByteArray sealed;
    const QString rcpt = recipient();
    if (!rcpt.isEmpty()) {
        Gpg enc({QStringLiteral("--armor"),
                 QStringLiteral("--trust-model"), QStringLiteral("always"),
                 QStringLiteral("--encrypt"),
                 QStringLiteral("-r"), rcpt});
        if (!enc.run(pt, &sealed) || sealed.isEmpty()) {
            const QString fresh = recipient(/*refresh=*/true);
            if (fresh.isEmpty()) {
                Gpg sym({QStringLiteral("--armor"), QStringLiteral("--symmetric")});
                if (!sym.run(pt, &sealed) || sealed.isEmpty()) return false;
            } else if (fresh != rcpt) {
                Gpg enc2({QStringLiteral("--armor"),
                          QStringLiteral("--trust-model"), QStringLiteral("always"),
                          QStringLiteral("--encrypt"),
                          QStringLiteral("-r"), fresh});
                if (!enc2.run(pt, &sealed) || sealed.isEmpty()) return false;
            } else {
                return false;
            }
        }
    } else {
        Gpg enc({QStringLiteral("--armor"), QStringLiteral("--symmetric")});
        if (!enc.run(pt, &sealed) || sealed.isEmpty()) return false;
    }

    // Atomic replace: POSIX rename(2) replaces the target atomically, keeping
    // the old blob intact until the new one is fully in place. (QFile::rename
    // refuses to overwrite an existing target, which would break every write
    // after the first — hence std::filesystem here.)
    QTemporaryFile tmp(path + QStringLiteral(".tmpXXXXXX"));
    if (!tmp.open()) return false;
    const QString tmpPath = tmp.fileName();
    if (tmp.write(sealed) != sealed.size()) { tmp.remove(); return false; }
    tmp.setPermissions(QFile::ReadOwner | QFile::WriteOwner);
    tmp.close();
    std::error_code ec;
    std::filesystem::rename(tmpPath.toStdString(), path.toStdString(), ec);
    if (ec) {
        // Non-POSIX fallback (no atomic replace there): remove + retry.
        QFile::remove(path);
        std::filesystem::rename(tmpPath.toStdString(), path.toStdString(), ec);
        if (ec) { QFile::remove(tmpPath); return false; }
    }
    QFile f(path);
    f.setPermissions(QFile::ReadOwner | QFile::WriteOwner);
    return true;
}

// Serialize every store/lookup/clear: mutateStore is a decrypt→modify→
// re-encrypt cycle, so two concurrent mutators (GUI thread + a protocol
// worker storing a different field) would silently lose one update. gpg
// calls take ~50 ms with a cached agent key, so contention is cheap.
QMutex& storeMutex() { static QMutex m; return m; }

// Caller must hold storeMutex().
bool clearLocked(const QString& key) {
    if (!QFileInfo::exists(storePath())) return true;
    return mutateStore([&](QVector<Entry>& entries) {
        for (int i = 0; i < entries.size(); ++i) {
            if (entries.at(i).key == key) { entries.remove(i); break; }
        }
        return true;
    });
}

} // namespace

bool available() {
    static std::atomic_bool probed{false};
    static std::atomic_bool ok{false};
    if (!probed.load()) {
        ok.store(!gpgBinary().isEmpty());
        probed.store(true);
    }
    return ok.load();
}

QString description() {
    if (gpgBinary().isEmpty()) return QStringLiteral("gpg not found");
    const QString r = recipient();
    if (r.isEmpty()) return QStringLiteral("GPG (symmetric, pinentry)");
    return QStringLiteral("GPG (key %1…)").arg(r.left(8));
}

bool clear(const QString& key) {
    QMutexLocker lock(&storeMutex());
    return clearLocked(key);
}

bool store(const QString& key, const QString& secret) {
    QMutexLocker lock(&storeMutex());
    // Empty secret == forget(). clearLocked, not clear(): storeMutex() is
    // already held here and QMutex is non-recursive.
    if (secret.isEmpty()) return clearLocked(key);
    return mutateStore([&](QVector<Entry>& entries) {
        const QByteArray v = secret.toUtf8().toBase64();
        for (Entry& e : entries) {
            if (e.key == key) { e.value = QString::fromLatin1(v); return true; }
        }
        entries.append({key, QString::fromLatin1(v)});
        return true;
    });
}

bool lookup(const QString& key, QString* outSecret) {
    QMutexLocker lock(&storeMutex());
    if (!outSecret || gpgBinary().isEmpty()) return false;
    const QString path = storePath();
    if (!QFileInfo::exists(path)) return false;
    QByteArray current;
    Gpg dec({QStringLiteral("--decrypt"), path});
    if (!dec.run(QByteArray(), &current)) return false;
    QVector<Entry> entries;
    if (!decode(current, &entries)) return false;
    for (const Entry& e : entries) {
        if (e.key == key) {
            *outSecret = QString::fromUtf8(QByteArray::fromBase64(e.value.toLatin1()));
            return true;
        }
    }
    return false;
}

} // namespace gpgstore
} // namespace inode
