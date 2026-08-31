#include "Settings.h"

#include <QDir>
#include <QFile>
#include <QSettings>
#include <QStandardPaths>
#include <QTextStream>

namespace inode {

namespace {
constexpr auto K_TRAY        = "ui/minimizeToTray";
constexpr auto K_START_MIN   = "ui/startMinimized";
constexpr auto K_AUTOSTART   = "ui/autostart";
constexpr auto K_THEME       = "ui/theme";
constexpr auto K_LANGUAGE    = "ui/language";
constexpr auto K_LOG_LEVEL   = "log/level";
constexpr auto K_LOG_FILE    = "log/toFile";
constexpr auto K_LOG_BYTES   = "log/maxBytes";
constexpr auto K_NOTIFY      = "ui/notify";

QSettings& store() {
    static QSettings s(QStringLiteral("iNodeClient-Qt"),
                       QStringLiteral("iNodeClient-Qt"));
    return s;
}

QString autostartDesktopPath() {
    QString dir = QStandardPaths::writableLocation(QStandardPaths::GenericConfigLocation)
                  + QStringLiteral("/autostart");
    QDir().mkpath(dir);
    return dir + QStringLiteral("/iNodeClient-Qt.desktop");
}
} // namespace

Settings& Settings::instance() {
    static Settings s;
    return s;
}

Settings::Settings() = default;

bool Settings::minimizeToTray() const { return store().value(K_TRAY, true).toBool(); }
void Settings::setMinimizeToTray(bool b) { store().setValue(K_TRAY, b); }

bool Settings::startMinimized() const { return store().value(K_START_MIN, false).toBool(); }
void Settings::setStartMinimized(bool b) { store().setValue(K_START_MIN, b); }

bool Settings::autostart() const {
    return QFile::exists(autostartDesktopPath());
}

void Settings::setAutostart(bool b) {
    const QString path = autostartDesktopPath();
    if (!b) { QFile::remove(path); return; }
    QFile f(path);
    if (!f.open(QIODevice::WriteOnly | QIODevice::Text)) return;
    QTextStream ts(&f);
    ts << "[Desktop Entry]\n"
       << "Type=Application\n"
       << "Name=iNode Client (Qt)\n"
       << "Comment=Connect to H3C iNode-compatible networks on login\n"
       << "Exec=iNodeClient-Qt --minimized\n"
       << "Icon=org.inode.ClientQt\n"
       << "Terminal=false\n"
       << "X-GNOME-Autostart-enabled=true\n";
}

Settings::Theme Settings::theme() const {
    // Default to the modern dark "Mullvad" theme for a fresh install.
    return static_cast<Theme>(store().value(K_THEME, int(ThemeMullvad)).toInt());
}
void Settings::setTheme(Theme t) {
    store().setValue(K_THEME, int(t));
    emit themeChanged(int(t));
}

QString Settings::language() const { return store().value(K_LANGUAGE, QString()).toString(); }
void Settings::setLanguage(const QString& loc) {
    store().setValue(K_LANGUAGE, loc);
    emit languageChanged(loc);
}

int Settings::logLevel() const { return store().value(K_LOG_LEVEL, 3).toInt(); }
void Settings::setLogLevel(int lvl) { store().setValue(K_LOG_LEVEL, qBound(0, lvl, 5)); }

bool Settings::logToFile() const { return store().value(K_LOG_FILE, true).toBool(); }
void Settings::setLogToFile(bool b) { store().setValue(K_LOG_FILE, b); }

QString Settings::logFilePath() const {
    QString dir = QStandardPaths::writableLocation(QStandardPaths::GenericDataLocation)
                  + QStringLiteral("/iNodeClient-Qt/logs");
    QDir().mkpath(dir);
    return dir + QStringLiteral("/iNodeClient-Qt.log");
}

int Settings::logMaxBytes() const { return store().value(K_LOG_BYTES, 2 * 1024 * 1024).toInt(); }
void Settings::setLogMaxBytes(int bytes) { store().setValue(K_LOG_BYTES, bytes); }

bool Settings::notifyOnStateChange() const { return store().value(K_NOTIFY, true).toBool(); }
void Settings::setNotifyOnStateChange(bool b) { store().setValue(K_NOTIFY, b); }

} // namespace inode
