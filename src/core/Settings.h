#pragma once

#include <QObject>
#include <QString>

namespace inode {

// App-wide (not per-profile) user preferences. Backed by QSettings so it
// round-trips through the system's native config location. Access through
// the singleton: `Settings::instance()`.
class Settings : public QObject {
    Q_OBJECT
public:
    enum Theme { ThemeSystem = 0, ThemeAero, ThemeBright, ThemeDark, ThemeMullvad };

    static Settings& instance();

    bool    minimizeToTray() const;
    void    setMinimizeToTray(bool b);

    bool    startMinimized() const;
    void    setStartMinimized(bool b);

    bool    autostart() const;                   // XDG desktop autostart entry
    void    setAutostart(bool b);

    Theme   theme() const;
    void    setTheme(Theme t);

    QString language() const;                    // "", "en", "zh_CN", "ja_JP"
    void    setLanguage(const QString& loc);

    int     logLevel() const;
    void    setLogLevel(int lvl);                // 0..5 (5 verbose)

    bool    logToFile() const;
    void    setLogToFile(bool b);

    QString logFilePath() const;                 // computed; not directly editable
    int     logMaxBytes() const;
    void    setLogMaxBytes(int bytes);

    bool    notifyOnStateChange() const;
    void    setNotifyOnStateChange(bool b);

signals:
    void themeChanged(int theme);
    void languageChanged(const QString& loc);

private:
    Settings();
};

} // namespace inode
