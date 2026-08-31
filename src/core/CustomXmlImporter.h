#pragma once

#include "Profile.h"
#include <QString>
#include <QVector>

namespace inode {

// Imports scenarios from an original iNodeClient installation. Reads:
//   <install>/custom/clientfiles/locations.xml
//   <install>/custom/iNodeCustom.xml   (for EAD/common defaults)
// and produces a Profile per <connection> element.
//
// Returns an empty vector if the files are missing or malformed.
class CustomXmlImporter {
public:
    static QVector<Profile> importFromInstall(const QString& installDir);
};

} // namespace inode
