#pragma once

#include <QDialog>

class QCheckBox;
class QComboBox;
class QSpinBox;

namespace inode {

// Application-wide preferences dialog. Commits on Ok to Settings::instance();
// Cancel throws the changes away.
class SettingsDialog : public QDialog {
    Q_OBJECT
public:
    explicit SettingsDialog(QWidget* parent = nullptr);

private:
    void load();
    void save();

    QCheckBox* m_tray      = nullptr;
    QCheckBox* m_startMin  = nullptr;
    QCheckBox* m_autostart = nullptr;
    QComboBox* m_theme     = nullptr;
    QComboBox* m_language  = nullptr;
    QSpinBox*  m_logLevel  = nullptr;
    QCheckBox* m_logToFile = nullptr;
    QCheckBox* m_notify    = nullptr;
};

} // namespace inode
