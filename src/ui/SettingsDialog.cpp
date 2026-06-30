#include "SettingsDialog.h"

#include "core/Settings.h"

#include <QCheckBox>
#include <QComboBox>
#include <QDialogButtonBox>
#include <QFormLayout>
#include <QLabel>
#include <QSpinBox>
#include <QTabWidget>
#include <QVBoxLayout>

namespace inode {

SettingsDialog::SettingsDialog(QWidget* parent) : QDialog(parent) {
    setWindowTitle(tr("Preferences"));
    setModal(true);
    resize(460, 360);

    auto* root = new QVBoxLayout(this);
    auto* tabs = new QTabWidget(this);
    root->addWidget(tabs, 1);

    // --- General ---
    {
        auto* w = new QWidget;
        auto* f = new QFormLayout(w);
        m_tray      = new QCheckBox(tr("Minimize to system tray on close"), w);
        m_startMin  = new QCheckBox(tr("Start minimized"), w);
        m_autostart = new QCheckBox(tr("Launch at login"), w);
        m_notify    = new QCheckBox(tr("Show desktop notifications on state changes"), w);

        m_theme = new QComboBox(w);
        m_theme->addItem(tr("Mullvad (modern dark)"), Settings::ThemeMullvad);
        m_theme->addItem(tr("System default"), Settings::ThemeSystem);
        m_theme->addItem(tr("Aero"),           Settings::ThemeAero);
        m_theme->addItem(tr("Brightness"),     Settings::ThemeBright);
        m_theme->addItem(tr("Star (dark)"),    Settings::ThemeDark);

        m_language = new QComboBox(w);
        m_language->addItem(tr("System default"), QString());
        m_language->addItem(QStringLiteral("English"),  QStringLiteral("en"));
        m_language->addItem(QStringLiteral("简体中文"), QStringLiteral("zh_CN"));
        m_language->addItem(QStringLiteral("日本語"),   QStringLiteral("ja_JP"));

        f->addRow(m_tray);
        f->addRow(m_startMin);
        f->addRow(m_autostart);
        f->addRow(m_notify);
        f->addRow(tr("Theme:"),    m_theme);
        f->addRow(tr("Language:"), m_language);
        auto* note = new QLabel(tr("Language changes take effect on next launch."), w);
        note->setStyleSheet(QStringLiteral("color: gray;"));
        f->addRow(QString(), note);

        tabs->addTab(w, tr("General"));
    }

    // --- Logging ---
    {
        auto* w = new QWidget;
        auto* f = new QFormLayout(w);
        m_logLevel = new QSpinBox(w);
        m_logLevel->setRange(0, 5);
        m_logLevel->setToolTip(tr("0 = quiet, 5 = verbose. Matches LOG_LEVEL in the original client."));
        m_logToFile = new QCheckBox(tr("Also write log to file (%1)").arg(Settings::instance().logFilePath()), w);

        f->addRow(tr("Log level:"), m_logLevel);
        f->addRow(m_logToFile);

        tabs->addTab(w, tr("Logging"));
    }

    auto* buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, this);
    root->addWidget(buttons);
    connect(buttons, &QDialogButtonBox::accepted, this, [this] { save(); accept(); });
    connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);

    load();
}

void SettingsDialog::load() {
    auto& s = Settings::instance();
    m_tray->setChecked(s.minimizeToTray());
    m_startMin->setChecked(s.startMinimized());
    m_autostart->setChecked(s.autostart());
    m_notify->setChecked(s.notifyOnStateChange());
    m_logLevel->setValue(s.logLevel());
    m_logToFile->setChecked(s.logToFile());

    const int ti = m_theme->findData(int(s.theme()));
    if (ti >= 0) m_theme->setCurrentIndex(ti);

    const int li = m_language->findData(s.language());
    if (li >= 0) m_language->setCurrentIndex(li);
}

void SettingsDialog::save() {
    auto& s = Settings::instance();
    s.setMinimizeToTray(m_tray->isChecked());
    s.setStartMinimized(m_startMin->isChecked());
    s.setAutostart(m_autostart->isChecked());
    s.setNotifyOnStateChange(m_notify->isChecked());
    s.setLogLevel(m_logLevel->value());
    s.setLogToFile(m_logToFile->isChecked());
    s.setTheme(static_cast<Settings::Theme>(m_theme->currentData().toInt()));
    s.setLanguage(m_language->currentData().toString());
}

} // namespace inode
