#include "LogPane.h"

#include <QFile>
#include <QFileDialog>
#include <QFont>
#include <QHBoxLayout>
#include <QLabel>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QTextStream>
#include <QVBoxLayout>

namespace inode {

LogPane::LogPane(QWidget* parent) : QWidget(parent) {
    auto* root = new QVBoxLayout(this);
    root->setContentsMargins(0, 0, 0, 0);

    auto* header = new QHBoxLayout;
    header->addWidget(new QLabel(tr("Log"), this));
    header->addStretch();

    auto* clearBtn = new QPushButton(tr("Clear"), this);
    auto* saveBtn  = new QPushButton(tr("Save…"), this);
    header->addWidget(clearBtn);
    header->addWidget(saveBtn);
    root->addLayout(header);

    m_view = new QPlainTextEdit(this);
    m_view->setReadOnly(true);
    m_view->setMaximumBlockCount(5000);
    m_view->setFont(QFont(QStringLiteral("monospace")));
    root->addWidget(m_view, 1);

    connect(clearBtn, &QPushButton::clicked, this, &LogPane::clearLog);
    connect(saveBtn,  &QPushButton::clicked, this, &LogPane::saveLog);
}

void LogPane::appendLine(const QString& formatted) {
    m_view->appendPlainText(formatted);
}

void LogPane::clearLog() { m_view->clear(); }

void LogPane::saveLog() {
    const QString path = QFileDialog::getSaveFileName(this, tr("Save log"),
                                                      QStringLiteral("inode-client.log"));
    if (path.isEmpty()) return;
    QFile f(path);
    if (!f.open(QIODevice::WriteOnly | QIODevice::Text)) return;
    QTextStream(&f) << m_view->toPlainText();
}

} // namespace inode
