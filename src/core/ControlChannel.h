#pragma once

#include <QObject>
#include <QString>

#include <functional>

class QLocalServer;

namespace inode {

// Local control channel between a running GUI instance and a second process
// started with --status / --disconnect / --connect <name>. One newline-
// terminated command per connection, one line back. Lives on a per-user
// socket in $XDG_RUNTIME_DIR (0700), so other users cannot drive the client.
//
// Commands:  status | disconnect | connect <profile name> | show
QString controlSocketPath();

class ControlServer : public QObject {
    Q_OBJECT
public:
    using Handler = std::function<QString(const QString& command)>;
    explicit ControlServer(Handler handler, QObject* parent = nullptr);
    // Binds the socket. Returns false if another live instance owns it.
    bool listen();
private:
    QLocalServer* m_server = nullptr;
    Handler m_handler;
};

// Client side: send one command to a running instance. Returns false when no
// instance is listening (socket absent or dead); *reply receives the answer.
bool sendControlCommand(const QString& command, QString* reply, int timeoutMs = 5000);

} // namespace inode
