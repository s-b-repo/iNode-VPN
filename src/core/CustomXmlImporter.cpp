#include "CustomXmlImporter.h"
#include "Logger.h"

#include <QDomDocument>
#include <QFile>

namespace inode {

static QString readXmlLeaf(const QDomElement& root, const QString& tag) {
    const auto nodes = root.elementsByTagName(tag);
    if (nodes.isEmpty()) return {};
    return nodes.at(0).toElement().text().trimmed();
}

QVector<Profile> CustomXmlImporter::importFromInstall(const QString& installDir) {
    QVector<Profile> out;

    // 1. Read locations.xml for scenarios
    QFile locFile(installDir + QStringLiteral("/custom/clientfiles/locations.xml"));
    if (!locFile.open(QIODevice::ReadOnly)) {
        Logger::instance().warn(QStringLiteral("locations.xml not found at %1").arg(locFile.fileName()));
        return out;
    }

    QDomDocument doc;
    if (!doc.setContent(&locFile)) {
        Logger::instance().warn(QStringLiteral("failed to parse locations.xml"));
        return out;
    }

    // 2. Pull EAD defaults from iNodeCustom.xml
    QString eadHost;
    quint16 eadPort = 9019;
    {
        QFile cf(installDir + QStringLiteral("/custom/iNodeCustom.xml"));
        if (cf.open(QIODevice::ReadOnly)) {
            QDomDocument cd;
            if (cd.setContent(&cf)) {
                const auto root = cd.documentElement();
                eadHost = readXmlLeaf(root, QStringLiteral("msgAuthServIP"));
                const auto pStr = readXmlLeaf(root, QStringLiteral("msgAuthServPort"));
                if (!pStr.isEmpty()) eadPort = static_cast<quint16>(pStr.toUInt());
            }
        }
    }

    // 3. Walk <location><connection> tuples
    const auto locations = doc.elementsByTagName(QStringLiteral("location"));
    for (int i = 0; i < locations.size(); ++i) {
        const auto loc = locations.at(i).toElement();
        const auto locName = readXmlLeaf(loc, QStringLiteral("name"));
        const auto conns = loc.elementsByTagName(QStringLiteral("connection"));
        for (int j = 0; j < conns.size(); ++j) {
            const auto c = conns.at(j).toElement();
            const auto protoStr = readXmlLeaf(c, QStringLiteral("proto"));
            if (protoStr.isEmpty()) continue;

            Profile p = Profile::makeNew();
            p.kind = protocolFromInt(protoStr.toInt());
            p.name = locName.isEmpty()
                ? QStringLiteral("%1 (imported)").arg(protocolName(p.kind))
                : QStringLiteral("%1 – %2").arg(locName, protocolName(p.kind));
            p.eadServer = eadHost;
            p.eadPort   = eadPort;
            out.push_back(p);
        }
    }

    Logger::instance().info(QStringLiteral("imported %1 profile(s) from %2")
                                .arg(out.size()).arg(installDir));
    return out;
}

} // namespace inode
