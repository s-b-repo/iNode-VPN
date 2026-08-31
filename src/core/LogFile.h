#pragma once

#include <QFile>
#include <QObject>
#include <QString>

namespace inode {

// A tiny rotating-file sink for Logger::line. On overflow, renames the
// current log to "<path>.1" and starts fresh. Single-writer, single-file —
// adequate for a desktop client.
class LogFile : public QObject {
    Q_OBJECT
public:
    explicit LogFile(QObject* parent = nullptr);
    ~LogFile() override;

    void setPath(const QString& path);
    void setMaxBytes(int bytes) { m_maxBytes = bytes; }
    void setEnabled(bool on);
    bool isEnabled() const { return m_enabled; }

public slots:
    void append(const QString& line);

private:
    void rotate();

    QString m_path;
    int     m_maxBytes = 2 * 1024 * 1024;
    bool    m_enabled  = false;
    QFile   m_file;
};

} // namespace inode
