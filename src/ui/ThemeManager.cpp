#include "ThemeManager.h"

#include <QApplication>
#include <QFile>

namespace inode {

ThemeManager& ThemeManager::instance() {
    static ThemeManager m;
    return m;
}

ThemeManager::ThemeManager() = default;

static QString loadResource(const QString& path) {
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly | QIODevice::Text)) return {};
    return QString::fromUtf8(f.readAll());
}

void ThemeManager::start() {
    apply(Settings::instance().theme());
    connect(&Settings::instance(), &Settings::themeChanged, this, [this](int t) {
        apply(static_cast<Settings::Theme>(t));
    });
}

void ThemeManager::apply(Settings::Theme theme) {
    QString qss;
    switch (theme) {
        case Settings::ThemeAero:
            qss = loadResource(QStringLiteral(":/themes/areo.qss"));
            break;
        case Settings::ThemeBright:
            qss = loadResource(QStringLiteral(":/themes/brightness.qss"));
            break;
        case Settings::ThemeDark:
            qss = loadResource(QStringLiteral(":/themes/star.qss"));
            break;
        case Settings::ThemeMullvad:
            qss = loadResource(QStringLiteral(":/themes/mullvad.qss"));
            break;
        case Settings::ThemeSystem:
        default:
            qss.clear();
            break;
    }
    if (auto* app = qobject_cast<QApplication*>(QCoreApplication::instance()))
        app->setStyleSheet(qss);
}

} // namespace inode
