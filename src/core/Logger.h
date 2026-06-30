#pragma once

#include <QObject>
#include <QString>

namespace inode {

class Logger : public QObject {
    Q_OBJECT
public:
    static Logger& instance();

    void info(const QString& line);
    void warn(const QString& line);
    void error(const QString& line);
    void debug(const QString& line);

signals:
    void line(const QString& formatted);

private:
    Logger() = default;
};

} // namespace inode
