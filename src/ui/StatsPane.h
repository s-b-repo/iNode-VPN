#pragma once

#include "core/ConnectionStats.h"
#include <QWidget>

class QLabel;

namespace inode {

// Small strip of labels showing live connection info (iface, IP, gateway,
// bytes in/out, uptime). Displayed in the status bar when connected.
class StatsPane : public QWidget {
    Q_OBJECT
public:
    explicit StatsPane(QWidget* parent = nullptr);

public slots:
    void update(const ConnectionStats& s);
    void clear();

private:
    QLabel* m_iface = nullptr;
    QLabel* m_ip    = nullptr;
    QLabel* m_gw    = nullptr;
    QLabel* m_bytes = nullptr;
    QLabel* m_up    = nullptr;
};

} // namespace inode
