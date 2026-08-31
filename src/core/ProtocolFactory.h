#pragma once

#include "Protocol.h"
#include <QObject>
#include <memory>

namespace inode {

class ProtocolFactory {
public:
    static std::unique_ptr<IProtocol> create(ProtocolKind kind, QObject* parent = nullptr);
};

} // namespace inode
