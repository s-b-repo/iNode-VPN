#include "Profile.h"

namespace inode {

QString authModeToString(AuthMode m) {
    switch (m) {
        case AuthMode::Auto:      return QStringLiteral("auto");
        case AuthMode::Pap:       return QStringLiteral("pap");
        case AuthMode::Chap:      return QStringLiteral("chap");
        case AuthMode::MsChapV2:  return QStringLiteral("mschapv2");
        case AuthMode::EapMd5:    return QStringLiteral("eap-md5");
        case AuthMode::EapPeap:   return QStringLiteral("eap-peap");
        case AuthMode::HcChapV2:  return QStringLiteral("hc-chapv2");
    }
    return QStringLiteral("auto");
}

AuthMode authModeFromString(const QString& s) {
    const auto v = s.trimmed().toLower();
    if (v == QLatin1String("pap"))       return AuthMode::Pap;
    if (v == QLatin1String("chap"))      return AuthMode::Chap;
    if (v == QLatin1String("mschapv2"))  return AuthMode::MsChapV2;
    if (v == QLatin1String("eap-md5"))   return AuthMode::EapMd5;
    if (v == QLatin1String("eap-peap"))  return AuthMode::EapPeap;
    if (v == QLatin1String("hc-chapv2")) return AuthMode::HcChapV2;
    return AuthMode::Auto;
}

QString ipModeToString(IpMode m) {
    switch (m) {
        case IpMode::Inherit: return QStringLiteral("inherit");
        case IpMode::Dhcp:    return QStringLiteral("dhcp");
        case IpMode::Static:  return QStringLiteral("static");
    }
    return QStringLiteral("inherit");
}

IpMode ipModeFromString(const QString& s) {
    const auto v = s.trimmed().toLower();
    if (v == QLatin1String("dhcp"))   return IpMode::Dhcp;
    if (v == QLatin1String("static")) return IpMode::Static;
    return IpMode::Inherit;
}

QString trustModeToString(TrustMode m) {
    switch (m) {
        case TrustMode::System: return QStringLiteral("system");
        case TrustMode::Pinned: return QStringLiteral("pinned");
        case TrustMode::None:   return QStringLiteral("none");
    }
    return QStringLiteral("system");
}

TrustMode trustModeFromString(const QString& s) {
    const auto v = s.trimmed().toLower();
    if (v == QLatin1String("pinned")) return TrustMode::Pinned;
    if (v == QLatin1String("none"))   return TrustMode::None;
    return TrustMode::System;
}

} // namespace inode
