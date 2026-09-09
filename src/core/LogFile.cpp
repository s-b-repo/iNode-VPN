#include "LogFile.h"

#include <QDir>
#include <QFileInfo>
#include <QTextStream>

namespace inode {

namespace {
// A failed open/rotate must not silently disable logging — surface it on
// stderr where `--doctor` users and journalctl can see it. (We can't route
// through Logger here: LogFile is Logger's sink.)
void reportOpenFailure(const QString& path, const QString& err) {
    qWarning("iNode log file: could not open %s: %s",
             qUtf8Printable(path), qUtf8Printable(err));
}
} // namespace

LogFile::LogFile(QObject* parent) : QObject(parent) {}

LogFile::~LogFile() {
    if (m_file.isOpen()) m_file.close();
}

void LogFile::setPath(const QString& path) {
    if (path == m_path) return;
    if (m_file.isOpen()) m_file.close();
    m_path = path;
    if (!m_path.isEmpty()) QDir().mkpath(QFileInfo(m_path).absolutePath());
    if (m_enabled && !m_path.isEmpty()) {
        m_file.setFileName(m_path);
        if (!m_file.open(QIODevice::WriteOnly | QIODevice::Append | QIODevice::Text))
            reportOpenFailure(m_path, m_file.errorString());
    }
}

void LogFile::setEnabled(bool on) {
    m_enabled = on;
    if (!on && m_file.isOpen()) m_file.close();
    if (on && !m_path.isEmpty() && !m_file.isOpen()) {
        m_file.setFileName(m_path);
        if (!m_file.open(QIODevice::WriteOnly | QIODevice::Append | QIODevice::Text))
            reportOpenFailure(m_path, m_file.errorString());
    }
}

void LogFile::rotate() {
    if (m_file.isOpen()) m_file.close();
    const QString old = m_path + QStringLiteral(".1");
    QFile::remove(old);
    QFile::rename(m_path, old);
    m_file.setFileName(m_path);
    if (!m_file.open(QIODevice::WriteOnly | QIODevice::Append | QIODevice::Text))
        reportOpenFailure(m_path, m_file.errorString());
}

void LogFile::append(const QString& line) {
    if (!m_enabled || m_path.isEmpty()) return;
    if (!m_file.isOpen()) {
        m_file.setFileName(m_path);
        if (!m_file.open(QIODevice::WriteOnly | QIODevice::Append | QIODevice::Text)) return;
    }
    if (m_file.size() >= m_maxBytes) rotate();
    QTextStream ts(&m_file);
    ts << line << '\n';
    ts.flush();
}

} // namespace inode
