#include "ProfileListDelegate.h"

#include <QFontMetrics>
#include <QPainter>

namespace inode {

// Resize a font by a point delta, working whether the base font is defined in
// points or pixels (a pixel-size font returns -1 from pointSizeF()).
static QFont resized(QFont f, double dPt) {
    if (f.pointSizeF() > 0)
        f.setPointSizeF(f.pointSizeF() + dPt);
    else if (f.pixelSize() > 0)
        f.setPixelSize(qMax(1, f.pixelSize() + qRound(dPt * 1.3)));
    return f;
}

QSize ProfileListDelegate::sizeHint(const QStyleOptionViewItem&,
                                    const QModelIndex& index) const {
    // Empty-state / non-profile rows stay compact.
    return index.data(NameRole).toString().isEmpty() ? QSize(0, 36) : QSize(0, 58);
}

void ProfileListDelegate::paint(QPainter* p, const QStyleOptionViewItem& opt,
                                const QModelIndex& index) const {
    p->save();
    p->setRenderHint(QPainter::Antialiasing, true);
    const QRect r = opt.rect;
    const bool selected = opt.state & QStyle::State_Selected;

    // Row background (a delegate bypasses the QSS ::item rules, so draw it here).
    QRect bg = r.adjusted(4, 2, -4, -2);
    if (selected)
        p->setBrush(QColor(0x2f, 0x6f, 0xb0));
    else if (opt.state & QStyle::State_MouseOver)
        p->setBrush(QColor(0x24, 0x4a, 0x6e));
    else
        p->setBrush(Qt::NoBrush);
    p->setPen(Qt::NoPen);
    if (p->brush().style() != Qt::NoBrush)
        p->drawRoundedRect(bg, 8, 8);

    const QString name = index.data(NameRole).toString();

    // Empty-state row: just the display text, dim and centred-left.
    if (name.isEmpty()) {
        p->setPen(QColor(0x8f, 0xa3, 0xb8));
        p->drawText(r.adjusted(14, 0, -14, 0), Qt::AlignVCenter | Qt::TextSingleLine,
                    index.data(Qt::DisplayRole).toString());
        p->restore();
        return;
    }

    const QString subtitle = index.data(SubtitleRole).toString();
    const QString proto    = index.data(ProtocolRole).toString();
    const int     state    = index.data(StateRole).toInt();
    const int pad = 14;

    // State dot.
    QColor dot = QColor(0x5a, 0x73, 0x8f);
    if (state == 1) dot = QColor(0x6e, 0xe8, 0x7f);
    else if (state == 2) dot = QColor(0xec, 0xcf, 0x63);
    else if (state == 3) dot = QColor(0xff, 0x8a, 0x7d);
    p->setBrush(dot);
    p->setPen(Qt::NoPen);
    const int cy = r.center().y();
    p->drawEllipse(QPoint(r.left() + pad + 4, cy), 5, 5);

    const int textX = r.left() + pad + 20;

    // Protocol pill (right-aligned).
    QFont pf = resized(opt.font, -1.0);
    const QFontMetrics pfm(pf);
    const int pillW = pfm.horizontalAdvance(proto) + 18;
    const QRect pill(r.right() - pad - pillW, cy - 11, pillW, 22);
    p->setBrush(selected ? QColor(0x21, 0x40, 0x5f) : QColor(0x29, 0x4d, 0x73));
    p->setPen(Qt::NoPen);
    p->drawRoundedRect(pill, 11, 11);
    p->setFont(pf);
    p->setPen(QColor(0xcd, 0xd9, 0xe8));
    p->drawText(pill, Qt::AlignCenter, proto);

    const int textW = pill.left() - textX - 12;

    // Name (bold, bright).
    QFont nf = resized(opt.font, 0.5);
    nf.setBold(true);
    p->setFont(nf);
    p->setPen(selected ? QColor(Qt::white) : QColor(0xe8, 0xee, 0xf5));
    const QFontMetrics nfm(nf);
    p->drawText(QRect(textX, r.top() + 9, textW, nfm.height()),
                Qt::AlignVCenter | Qt::TextSingleLine,
                nfm.elidedText(name, Qt::ElideRight, textW));

    // Subtitle (dim).
    if (!subtitle.isEmpty()) {
        QFont sf = resized(opt.font, -0.5);
        p->setFont(sf);
        p->setPen(selected ? QColor(0xd4, 0xe2, 0xf2) : QColor(0x8f, 0xa3, 0xb8));
        const QFontMetrics sfm(sf);
        p->drawText(QRect(textX, r.top() + 9 + nfm.height() + 1, textW, sfm.height()),
                    Qt::AlignVCenter | Qt::TextSingleLine,
                    sfm.elidedText(subtitle, Qt::ElideRight, textW));
    }

    p->restore();
}

} // namespace inode
