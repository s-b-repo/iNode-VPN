#pragma once

#include "ConnectionStats.h"
#include <QMetaType>
#include <QObject>
#include <QString>
#include <QVariantMap>

namespace inode {

enum class ProtocolKind {
    Dot1x       = 8021,
    Portal      = 5020,
    SslVpn      = 7000,
    L2tpIpsec   = 2401,
    Wlan        = 1100,
    Ead         = 9019,
    Sdp         = 19006,
};

QString protocolName(ProtocolKind k);
ProtocolKind protocolFromInt(int value);

enum class ConnectionState {
    Disconnected,
    Connecting,
    Authenticating,
    Connected,
    Disconnecting,
    Failed,
};

QString stateName(ConnectionState s);

} // namespace inode

Q_DECLARE_METATYPE(inode::ConnectionState)

namespace inode {

class Profile;

class IProtocol : public QObject {
    Q_OBJECT
public:
    explicit IProtocol(QObject* parent = nullptr) : QObject(parent) {}
    ~IProtocol() override = default;

    virtual ProtocolKind kind() const = 0;
    virtual bool isImplemented() const = 0;

    virtual void connectWith(const Profile& profile) = 0;
    virtual void disconnect() = 0;

    ConnectionState         state() const { return m_state; }
    const ConnectionStats&  stats() const { return m_stats; }

signals:
    void stateChanged(inode::ConnectionState state);
    void logLine(const QString& line);
    void errorOccurred(const QString& message);
    void statsUpdated(const inode::ConnectionStats& stats);

protected:
    void setState(ConnectionState s);
    void setStats(const ConnectionStats& s);

private:
    ConnectionState m_state = ConnectionState::Disconnected;
    ConnectionStats m_stats;
};

} // namespace inode
