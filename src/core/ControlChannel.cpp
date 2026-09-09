#include "ControlChannel.h"

#include "Logger.h"

#include <QDir>
#include <QFile>
#include <QLocalServer>
#include <QLocalSocket>
#include <QStandardPaths>

#include <unistd.h>

namespace inode {

QString controlSocketPath() {
    QString dir = QStandardPaths::writableLocation(QStandardPaths::RuntimeLocation);
    if (dir.isEmpty() || !QDir(dir).exists())
        dir = QDir::tempPath();
    return dir + QStringLiteral("/iNodeClient-Qt-%1.sock").arg(getuid());
}

ControlServer::ControlServer(Handler handler, QObject* parent)
    : QObject(parent), m_server(new QLocalServer(this)), m_handler(std::move(handler)) {
    m_server->setSocketOptions(QLocalServer::UserAccessOption);
    connect(m_server, &QLocalServer::newConnection, this, [this] {
        while (QLocalSocket* sock = m_server->nextPendingConnection()) {
            connect(sock, &QLocalSocket::readyRead, sock, [this, sock] {
                if (!sock->canReadLine()) return;
                const QString cmd = QString::fromUtf8(sock->readLine()).trimmed();
                QString reply = m_handler ? m_handler(cmd) : QStringLiteral("error: no handler");
                sock->write(reply.toUtf8() + '\n');
                sock->flush();
                sock->disconnectFromServer();
            });
            connect(sock, &QLocalSocket::disconnected, sock, &QObject::deleteLater);
        }
    });
}

bool ControlServer::listen() {
    const QString path = controlSocketPath();
    if (m_server->listen(path)) return true;
    // A socket file is there. Live instance, or a leftover from a crash?
    QString probe;
    if (sendControlCommand(QStringLiteral("status"), &probe, 1000))
        return false;                              // someone is really listening
    QLocalServer::removeServer(path);              // stale — reclaim it
    if (m_server->listen(path)) return true;
    Logger::instance().warn(QStringLiteral("control socket unavailable (%1): %2 — "
                                           "--status/--disconnect will not reach this instance")
                                .arg(path, m_server->errorString()));
    return false;
}

bool sendControlCommand(const QString& command, QString* reply, int timeoutMs) {
    QLocalSocket sock;
    sock.connectToServer(controlSocketPath());
    if (!sock.waitForConnected(timeoutMs)) return false;
    sock.write(command.toUtf8() + '\n');
    sock.flush();
    QByteArray line;
    while (!line.endsWith('\n')) {
        if (!sock.waitForReadyRead(timeoutMs)) break;
        line += sock.readAll();
    }
    if (reply) *reply = QString::fromUtf8(line).trimmed();
    return !line.isEmpty();
}

} // namespace inode
