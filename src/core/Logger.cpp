#include "Logger.h"

#include "Settings.h"

#include <QDateTime>

namespace inode {

Logger& Logger::instance() {
    static Logger L;
    return L;
}

static QString stamp() {
    return QDateTime::currentDateTime().toString(QStringLiteral("yyyy-MM-dd HH:mm:ss"));
}

// Log levels:
//   0 = off
//   1 = errors only
//   2 = + warnings
//   3 = + info (default)
//   4 = + debug hooks (reserved)
//   5 = + trace
static int threshold() { return Settings::instance().logLevel(); }

void Logger::info(const QString& line) {
    if (threshold() < 3) return;
    emit this->line(QStringLiteral("[%1] [INFO] %2").arg(stamp(), line));
}

void Logger::warn(const QString& line) {
    if (threshold() < 2) return;
    emit this->line(QStringLiteral("[%1] [WARN] %2").arg(stamp(), line));
}

void Logger::error(const QString& line) {
    if (threshold() < 1) return;
    emit this->line(QStringLiteral("[%1] [ERR ] %2").arg(stamp(), line));
}

void Logger::debug(const QString& line) {
    if (threshold() < 5) return;
    emit this->line(QStringLiteral("[%1] [DBG ] %2").arg(stamp(), line));
}

} // namespace inode
