#include "AutoReconnect.h"

#include "Logger.h"

#include <algorithm>

namespace inode {

AutoReconnect::AutoReconnect(QObject* parent) : QObject(parent) {
    m_timer.setSingleShot(true);
    connect(&m_timer, &QTimer::timeout, this, &AutoReconnect::retry);
}

void AutoReconnect::armFor(const Profile& profile) {
    // If we're re-arming for the *same* profile (i.e. a retry), preserve the
    // attempt counter so the backoff progresses and we eventually give up.
    const bool sameProfile = m_profile.id == profile.id && !profile.id.isNull();
    m_profile = profile;
    m_armed   = profile.autoReconnect;
    if (!sameProfile) m_attempt = 0;
    m_timer.stop();
}

void AutoReconnect::cancel() {
    m_armed = false;
    m_attempt = 0;
    m_timer.stop();
}

void AutoReconnect::noteSuccess() { m_attempt = 0; }

void AutoReconnect::noteFailure() {
    if (!m_armed) return;
    if (m_attempt >= m_profile.reconnectMaxTries) {
        Logger::instance().warn(QStringLiteral("auto-reconnect: giving up after %1 attempts")
                                    .arg(m_attempt));
        m_armed = false;
        return;
    }
    ++m_attempt;
    const int base = std::max(1, m_profile.reconnectBackoffSec);
    const int delay = std::min(60, base * (1 << std::min(4, m_attempt - 1)));
    Logger::instance().info(QStringLiteral("auto-reconnect: retry #%1 in %2s")
                                .arg(m_attempt).arg(delay));
    m_timer.start(delay * 1000);
}

} // namespace inode
