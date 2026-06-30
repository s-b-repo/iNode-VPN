#pragma once

#include <QStyledItemDelegate>

namespace inode {

// Renders a profile row: a state dot, the bold name with a dim username/server
// subtitle, and a right-aligned protocol pill. Data is read from custom roles
// set by MainWindow::refreshList().
class ProfileListDelegate : public QStyledItemDelegate {
    Q_OBJECT
public:
    enum Role {
        IdRole       = Qt::UserRole,        // QUuid (kept compatible with prior code)
        NameRole     = Qt::UserRole + 1,    // QString
        SubtitleRole = Qt::UserRole + 2,    // QString
        ProtocolRole = Qt::UserRole + 3,    // QString
        StateRole    = Qt::UserRole + 4,    // int: 0 none, 1 connected, 2 connecting, 3 failed
    };

    explicit ProfileListDelegate(QObject* parent = nullptr)
        : QStyledItemDelegate(parent) {}

    void paint(QPainter* p, const QStyleOptionViewItem& opt,
               const QModelIndex& index) const override;
    QSize sizeHint(const QStyleOptionViewItem& opt,
                   const QModelIndex& index) const override;
};

} // namespace inode
