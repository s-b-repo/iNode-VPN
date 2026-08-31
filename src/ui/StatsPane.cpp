#include "StatsPane.h"

#include <QDateTime>
#include <QHBoxLayout>
#include <QLabel>

namespace inode {

static QString humanBytes(qint64 n) {
    if (n < 0) return QStringLiteral("–");
    const char* units[] = {"B", "KiB", "MiB", "GiB", "TiB"};
    double v = static_cast<double>(n);
    int u = 0;
    while (v >= 1024.0 && u < 4) { v /= 1024.0; ++u; }
    return QStringLiteral("%1 %2").arg(v, 0, 'f', v < 10 ? 1 : 0).arg(QLatin1String(units[u]));
}

static QString humanDuration(const QDateTime& start) {
    if (!start.isValid()) return {};
    const qint64 s = start.secsTo(QDateTime::currentDateTime());
    if (s < 0) return {};
    const qint64 h = s / 3600, m = (s % 3600) / 60, sec = s % 60;
    return QStringLiteral("%1:%2:%3")
        .arg(h, 2, 10, QLatin1Char('0'))
        .arg(m, 2, 10, QLatin1Char('0'))
        .arg(sec, 2, 10, QLatin1Char('0'));
}

StatsPane::StatsPane(QWidget* parent) : QWidget(parent) {
    auto* lay = new QHBoxLayout(this);
    lay->setContentsMargins(0, 0, 0, 0);
    lay->setSpacing(12);

    m_iface = new QLabel(this);
    m_ip    = new QLabel(this);
    m_gw    = new QLabel(this);
    m_bytes = new QLabel(this);
    m_up    = new QLabel(this);

    for (auto* w : {m_iface, m_ip, m_gw, m_bytes, m_up}) {
        w->setMinimumWidth(60);
        lay->addWidget(w);
    }
    lay->addStretch();
    clear();
}

void StatsPane::clear() {
    m_iface->clear();
    m_ip->clear();
    m_gw->clear();
    m_bytes->clear();
    m_up->clear();
}

void StatsPane::update(const ConnectionStats& s) {
    m_iface->setText(s.iface.isEmpty() ? QString() : tr("if: %1").arg(s.iface));
    m_ip->setText(s.localIp.isEmpty() ? QString() : tr("ip: %1").arg(s.localIp));
    m_gw->setText(s.gatewayIp.isEmpty() ? QString() : tr("gw: %1").arg(s.gatewayIp));
    m_bytes->setText(
        (s.bytesRx < 0 && s.bytesTx < 0)
            ? QString()
            : tr("↓ %1  ↑ %2").arg(humanBytes(s.bytesRx), humanBytes(s.bytesTx)));
    m_up->setText(s.connectedAt.isValid()
                  ? tr("up: %1").arg(humanDuration(s.connectedAt))
                  : QString());
}

} // namespace inode
