#pragma once

#include "core/ConnectionStats.h"
#include "core/Protocol.h"

#include <QDateTime>
#include <QElapsedTimer>
#include <QList>
#include <QWidget>

class QLabel;
class QProgressBar;

namespace inode {

// A small sparkline: a ring buffer of throughput samples drawn as a filled
// polyline. Stdlib-only painting, no chart dependency.
class Sparkline : public QWidget {
    Q_OBJECT
public:
    explicit Sparkline(QWidget* parent = nullptr);
    void push(double value);
    void reset();
protected:
    void paintEvent(QPaintEvent*) override;
private:
    QList<double> m_data;
    double        m_max = 1.0;
};

// The top-of-window connection panel. Owns the whole status display (state +
// active profile) and, while connected, shows IP / gateway / interface / uptime
// and live ↓↑ throughput with a sparkline. Replaces the separate status badge,
// status-bar label and stats strip.
class ConnectionPanel : public QWidget {
    Q_OBJECT
public:
    explicit ConnectionPanel(QWidget* parent = nullptr);

    void setState(ConnectionState state, const QString& profileName);
    void updateStats(const ConnectionStats& stats);

private:
    void refreshUptime();

    QLabel*       m_statusLine = nullptr;   // coloured state + profile
    QWidget*      m_details    = nullptr;    // shown only when connected
    QLabel*       m_ip         = nullptr;
    QLabel*       m_gw         = nullptr;
    QLabel*       m_iface      = nullptr;
    QLabel*       m_uptime     = nullptr;
    QLabel*       m_rate       = nullptr;
    QProgressBar* m_progress   = nullptr;    // indeterminate while connecting
    Sparkline*    m_spark      = nullptr;

    ConnectionState m_state = ConnectionState::Disconnected;
    QDateTime       m_connectedAt;
    qint64          m_lastRx = -1;
    qint64          m_lastTx = -1;
    QElapsedTimer   m_sampleClock;
};

} // namespace inode
