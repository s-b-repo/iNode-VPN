cmake_minimum_required(VERSION 3.22)
project(iNodeClient-Qt VERSION 0.2.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

find_package(Qt6 6.5 REQUIRED COMPONENTS Core Gui Widgets Network Xml)
find_package(Qt6 6.5 COMPONENTS LinguistTools QUIET)

# Optional KDE Frameworks integration. App runs without them; we just prefer
# KWallet / KConfig / KI18n when present.
find_package(KF6 6.0 COMPONENTS Config Wallet I18n CoreAddons QUIET)
if(KF6_FOUND)
    set(HAVE_KF6 ON)
    add_compile_definitions(HAVE_KF6=1)
endif()

set(INODE_SOURCES
    src/main.cpp
    src/MainWindow.cpp
    src/MainWindow.h

    # Core
    src/core/AutoReconnect.cpp
    src/core/AutoReconnect.h
    src/core/ConnectionStats.h
    src/core/CredentialStore.cpp
    src/core/CredentialStore.h
    src/core/SecretServiceStore.cpp
    src/core/SecretServiceStore.h
    src/core/CustomXmlImporter.cpp
    src/core/CustomXmlImporter.h
    src/core/Dhcp.cpp
    src/core/Dhcp.h
    src/core/InterfaceDiscovery.cpp
    src/core/InterfaceDiscovery.h
    src/core/IpConfigurator.cpp
    src/core/IpConfigurator.h
    src/core/LogFile.cpp
    src/core/LogFile.h
    src/core/Logger.cpp
    src/core/Logger.h
    src/core/NetUtil.cpp
    src/core/NetUtil.h
    src/core/Profile.cpp
    src/core/Profile.h
    src/core/ProfileStore.cpp
    src/core/ProfileStore.h
    src/core/Protocol.cpp
    src/core/Protocol.h
    src/core/ProtocolFactory.cpp
    src/core/ProtocolFactory.h
    src/core/Settings.cpp
    src/core/Settings.h

    # Protocols
    src/protocols/Dot1xProtocol.cpp
    src/protocols/Dot1xProtocol.h
    src/protocols/EadProtocol.cpp
    src/protocols/EadProtocol.h
    src/protocols/L2tpIpsecProtocol.cpp
    src/protocols/L2tpIpsecProtocol.h
    src/protocols/PortalProtocol.cpp
    src/protocols/PortalProtocol.h
    src/protocols/SslVpnProtocol.cpp
    src/protocols/SslVpnProtocol.h
    src/protocols/WlanProtocol.cpp
    src/protocols/WlanProtocol.h

    # UI
    src/ui/ConnectionPanel.cpp
    src/ui/ConnectionPanel.h
    src/ui/LogPane.cpp
    src/ui/LogPane.h
    src/ui/ProfileEditor.cpp
    src/ui/ProfileEditor.h
    src/ui/ProfileListDelegate.cpp
    src/ui/ProfileListDelegate.h
    src/ui/SettingsDialog.cpp
    src/ui/SettingsDialog.h
    src/ui/StatsPane.cpp
    src/ui/StatsPane.h
    src/ui/ThemeManager.cpp
    src/ui/ThemeManager.h
    src/ui/TrayIcon.cpp
    src/ui/TrayIcon.h
)

add_executable(iNodeClient-Qt
    ${INODE_SOURCES}
    resources/resources.qrc
)

target_include_directories(iNodeClient-Qt PRIVATE src)

target_link_libraries(iNodeClient-Qt PRIVATE
    Qt6::Core
    Qt6::Gui
    Qt6::Widgets
    Qt6::Network
    Qt6::Xml
    ${CMAKE_DL_LIBS}   # dlopen() for the runtime-loaded Secret Service backend
)

if(HAVE_KF6)
    target_link_libraries(iNodeClient-Qt PRIVATE
        KF6::ConfigCore
        KF6::ConfigGui
        KF6::Wallet
        KF6::I18n
        KF6::CoreAddons
    )
endif()

# Translations: scaffold files so `lupdate` can populate them.
set(INODE_TS_FILES
    i18n/iNodeClient-Qt_en.ts
    i18n/iNodeClient-Qt_zh_CN.ts
    i18n/iNodeClient-Qt_ja_JP.ts
)
if(Qt6LinguistTools_FOUND AND COMMAND qt_add_translations)
    qt_add_translations(iNodeClient-Qt
        TS_FILES ${INODE_TS_FILES}
        LUPDATE_OPTIONS -locations none
    )
endif()

include(GNUInstallDirs)
install(TARGETS iNodeClient-Qt RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
install(FILES resources/org.inode.ClientQt.desktop
        DESTINATION ${CMAKE_INSTALL_DATADIR}/applications)
install(FILES resources/org.inode.ClientQt.svg
        DESTINATION ${CMAKE_INSTALL_DATADIR}/icons/hicolor/scalable/apps)
install(FILES scripts/inode-l2tp-helper scripts/inode-dot1x-helper scripts/inode-svpn-helper
              scripts/inode-ipcfg-helper
        DESTINATION ${CMAKE_INSTALL_LIBEXECDIR}/iNodeClient-Qt
        PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE
                    GROUP_READ GROUP_EXECUTE
                    WORLD_READ WORLD_EXECUTE)
install(FILES resources/org.inode.ClientQt.policy
        DESTINATION ${CMAKE_INSTALL_DATADIR}/polkit-1/actions)

# Bundled clean-room SSL VPN backend (pure-Python h3csvpn package). Driven by
# the SslVpn protocol plugin via inode-svpn-helper. Installed next to the
# helpers so SslVpnProtocol::backendDir() can find it at runtime.
install(DIRECTORY backends/h3csvpn
        DESTINATION ${CMAKE_INSTALL_LIBEXECDIR}/iNodeClient-Qt/backends
        PATTERN "__pycache__" EXCLUDE)
