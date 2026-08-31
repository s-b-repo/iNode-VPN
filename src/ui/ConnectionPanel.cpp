#include "ConnectionPanel.h"

#include <QGridLayout>
#include <QLabel>
#include <QPainterPath>
#include <QPainter>
#include <QProgressBar>
#include <QStyle>
#include <QTimer>
#include <QVBoxLayout>

#include <algorithm>

namespace inode {

// ---- helpers ---------------------------------------------------------------
static QString humanRate(double bytesPerSec) {
    const char* u[] = {"B/s", "KiB/s", "MiB/s", "GiB/s"};
    double v = bytesPerSec < 0 ? 0 : bytesPerSec;
    int i = 0;
    while (v >= 1024.0 && i < 3) { v /= 1024.0; ++i; }
    return QStringLiteral("%1 %2").arg(v, 0, 'f', v < 10 ? 1 : 0).arg(QLatin1String(u[i]));
}

static QString humanDuration(const QDateTime& start) {
    if (!start.isValid()) return QStringLiteral("00:00:00");
    qint64 s = start.secsTo(QDateTime::currentDateTime());
    if (s < 0) s = 0;
    return QStringLiteral("%1:%2:%3")
        .arg(s / 3600, 2, 10, QLatin1Char('0'))
        .arg((s % 3600) / 60, 2, 10, QLatin1Char('0'))
        .arg(s % 60, 2, 10, QLatin1Char('0'));
}

// ---- Sparkline -------------------------------------------------------------
Sparkline::Sparkline(QWidget* parent) : QWidget(parent) {
    setMinimumSize(140, 30);
}

void Sparkline::push(double value) {
    m_data.append(value < 0 ? 0 : value);
    while (m_data.size() > 80) m_data.removeFirst();
    m_max = 1.0;
    for (double v : m_data) m_max = std::max(m_max, v);
    update();
}

void Sparkline::reset() { m_data.clear(); m_max = 1.0; update(); }

void Sparkline::paintEvent(QPaintEvent*) {
    QPainter p(this);
    p.setRenderHint(QPainter::Antialiasing, true);
    const QRectF r = rect().adjusted(1, 1, -1, -1);
    p.fillRect(rect(), QColor(0x0f, 0x1d, 0x2e));
    if (m_data.size() < 2) return;

    const double n = m_data.size();
    auto xAt = [&](int i) { return r.left() + r.width() * (i / (n - 1)); };
    auto yAt = [&](double v) { return r.bottom() - (r.height() - 2) * (v / m_max); };

    QPainterPath line;
    line.moveTo(xAt(0), yAt(m_data[0]));
    for (int i = 1; i < m_data.size(); ++i) line.lineTo(xAt(i), yAt(m_data[i]));

    QPainterPath fill = line;
    fill.lineTo(r.right(), r.bottom());
    fill.lineTo(r.left(), r.bottom());
    fill.closeSubpath();
    p.fillPath(fill, QColor(0x44, 0xad, 0x4a, 60));
    p.setPen(QPen(QColor(0x4f, 0xc4, 0x56), 1.6));
    p.drawPath(line);
}

// ---- ConnectionPanel -------------------------------------------------------
ConnectionPanel::ConnectionPanel(QWidget* parent) : QWidget(parent) {
    auto* root = new QVBoxLayout(this);
    root->setContentsMargins(0, 0, 0, 0);
    root->setSpacing(8);

    m_statusLine = new QLabel(tr("Disconnected"), this);
    m_statusLine->setObjectName(QStringLiteral("statusBadge"));
    m_statusLine->setProperty("state", "disconnected");
    root->addWidget(m_statusLine, 0, Qt::AlignLeft);

    m_progress = new QProgressBar(this);
    m_progress->setRange(0, 0);            // indeterminate
    m_progress->setTextVisible(false);
    m_progress->setFixedHeight(4);
    m_progress->hide();
    root->addWidget(m_progress);

    m_details = new QWidget(this);
    auto* grid = new QGridLayout(m_details);
    grid->setContentsMargins(6, 2, 6, 2);
    grid->setHorizontalSpacing(18);
    grid->setVerticalSpacing(4);

    auto mk = [&](const QString& cap, QLabel*& val, int row, int col) {
        auto* c = new QLabel(cap, m_details);
        c->setObjectName(QStringLiteral("statCaption"));
        val = new QLabel(QStringLiteral("–"), m_details);
        val->setObjectName(QStringLiteral("statValue"));
        grid->addWidget(c,  row, col * 2);
        grid->addWidget(val, row, col * 2 + 1);
    };
    mk(tr("IP"),        m_ip,     0, 0);
    mk(tr("Gateway"),   m_gw,     0, 1);
    mk(tr("Interface"), m_iface,  1, 0);
    mk(tr("Uptime"),    m_uptime, 1, 1);

    m_rate = new QLabel(QStringLiteral("↓ –   ↑ –"), m_details);
    m_rate->setObjectName(QStringLiteral("statValue"));
    grid->addWidget(m_rate, 2, 0, 1, 2);

    m_spark = new Sparkline(m_details);
    grid->addWidget(m_spark, 0, 4, 3, 1);
    grid->setColumnStretch(4, 1);

    root->addWidget(m_details);
    m_details->hide();

    auto* t = new QTimer(this);
    t->setInterval(1000);
    connect(t, &QTimer::timeout, this, &ConnectionPanel::refreshUptime);
    t->start();
}

void ConnectionPanel::setState(ConnectionState state, const QString& profileName) {
    m_state = state;

    QString text = stateName(state);
    if (state != ConnectionState::Disconnected && !profileName.isEmpty())
        text = QStringLiteral("%1 — %2").arg(stateName(state), profileName);
    m_statusLine->setText(text);

    const char* st = "disconnected";
    switch (state) {
        case ConnectionState::Connected:      st = "connected";    break;
        case ConnectionState::Connecting:
        case ConnectionState::Authenticating:
        case ConnectionState::Disconnecting:  st = "connecting";   break;
        case ConnectionState::Failed:         st = "failed";       break;
        default:                              st = "disconnected"; break;
    }
    m_statusLine->setProperty("state", st);
    m_statusLine->style()->unpolish(m_statusLine);
    m_statusLine->style()->polish(m_statusLine);

    const bool connecting = state == ConnectionState::Connecting
                         || state == ConnectionState::Authenticating;
    m_progress->setVisible(connecting);
    m_details->setVisible(state == ConnectionState::Connected);

    if (state == ConnectionState::Connected) {
        if (!m_connectedAt.isValid()) m_connectedAt = QDateTime::currentDateTime();
    } else {
        m_connectedAt = QDateTime();
        m_lastRx = m_lastTx = -1;
        m_spark->reset();
    }
}

void ConnectionPanel::updateStats(const ConnectionStats& s) {
    m_ip->setText(s.localIp.isEmpty()    ? QStringLiteral("–") : s.localIp);
    m_gw->setText(s.gatewayIp.isEmpty()  ? QStringLiteral("–") : s.gatewayIp);
    m_iface->setText(s.iface.isEmpty()   ? QStringLiteral("–") : s.iface);
    if (s.connectedAt.isValid()) m_connectedAt = s.connectedAt;

    // Derive a rate from the cumulative byte counters between samples.
    if (m_lastRx >= 0 && m_sampleClock.isValid()) {
        const double dt = m_sampleClock.elapsed() / 1000.0;
        if (dt > 0.05 && s.bytesRx >= 0 && s.bytesTx >= 0) {
            const double rx = std::max(0.0, double(s.bytesRx - m_lastRx)) / dt;
            const double tx = std::max(0.0, double(s.bytesTx - m_lastTx)) / dt;
            m_rate->setText(QStringLiteral("↓ %1   ↑ %2").arg(humanRate(rx), humanRate(tx)));
            m_spark->push(rx + tx);
        }
    }
    m_lastRx = s.bytesRx;
    m_lastTx = s.bytesTx;
    m_sampleClock.restart();
}

void ConnectionPanel::refreshUptime() {
    if (m_state == ConnectionState::Connected)
        m_uptime->setText(humanDuration(m_connectedAt));
}

} // namespace inode
