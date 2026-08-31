#pragma once

#include "Profile.h"
#include <QObject>
#include <QTimer>

namespace inode {

// Exponential-backoff reconnect scheduler. Owner decides when to feed it
// events:
//   - noteSuccess(): resets attempt counter
//   - noteFailure(): starts the backoff; emits retry() when delay elapses
//   - cancel(): cancels any pending retry
//
// Not tied to a specific protocol — the MainWindow drives the lifecycle.
class AutoReconnect : public QObject {
    Q_OBJECT
public:
    explicit AutoReconnect(QObject* parent = nullptr);

    void armFor(const Profile& profile);
    void cancel();
    void noteSuccess();
    void noteFailure();

    bool isArmed() const { return m_armed; }

signals:
    void retry();

private:
    QTimer  m_timer;
    Profile m_profile;
    bool    m_armed     = false;
    int     m_attempt   = 0;
};

} // namespace inode
