"""Tiny persistent settings store for h3c-svpn.

Holds user-toggleable preferences that should survive across runs — currently
the CAPTCHA auto-solve/auto-retry behaviour. JSON under the XDG config dir
(``$XDG_CONFIG_HOME/h3csvpn/config.json``, default ``~/.config/h3csvpn``).
"""
from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass


def config_path() -> str:
    base = os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config")
    return os.path.join(base, "h3csvpn", "config.json")


@dataclass
class Settings:
    # CAPTCHA: auto-solve via OCR and auto-retry on "Verify code error".
    auto_captcha: bool = True
    captcha_retries: int = 8         # max fresh-captcha attempts before giving up
    show_captcha: bool = True        # render the image in the terminal each try

    @classmethod
    def load(cls) -> "Settings":
        try:
            with open(config_path(), "r", encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, ValueError):
            return cls()
        known = {f for f in cls().__dict__}
        return cls(**{k: v for k, v in data.items() if k in known})

    def save(self) -> None:
        path = config_path()
        os.makedirs(os.path.dirname(path), exist_ok=True)
        import tempfile
        fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path) or ".",
                                    prefix=".h3csvpn.tmp.")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(asdict(self), f, indent=2)
                f.write("\n")
            os.replace(tmp, path)
        except Exception:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
