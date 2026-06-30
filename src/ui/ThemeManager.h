#pragma once

#include "core/Settings.h"
#include <QObject>

class QGuiApplication;

namespace inode {

// Applies the selected stylesheet to the running QApplication. Three
// built-in themes live in the Qt resource system under :/themes/ and map
// directly to the original client's areo / brightness / star.
class ThemeManager : public QObject {
    Q_OBJECT
public:
    static ThemeManager& instance();

    // Called once at startup; applies the currently-persisted theme and
    // subscribes to future changes via Settings::themeChanged.
    void start();

    void apply(Settings::Theme theme);

private:
    ThemeManager();
};

} // namespace inode
