#pragma once

#include "Profile.h"
#include <QObject>
#include <QVector>

namespace inode {

class ProfileStore : public QObject {
    Q_OBJECT
public:
    explicit ProfileStore(QObject* parent = nullptr);

    const QVector<Profile>& profiles() const { return m_profiles; }

    void load();
    void save() const;

    void upsert(const Profile& p);
    void remove(const QUuid& id);
    const Profile* find(const QUuid& id) const;
    const Profile* findByName(const QString& name) const;
    const Profile* autoConnectProfile() const;

signals:
    void changed();

private:
    QString storagePath() const;
    QVector<Profile> m_profiles;
};

} // namespace inode
