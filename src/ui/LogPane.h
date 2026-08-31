#pragma once

#include <QWidget>

class QPlainTextEdit;

namespace inode {

class LogPane : public QWidget {
    Q_OBJECT
public:
    explicit LogPane(QWidget* parent = nullptr);

public slots:
    void appendLine(const QString& formatted);
    void clearLog();
    void saveLog();

private:
    QPlainTextEdit* m_view = nullptr;
};

} // namespace inode
