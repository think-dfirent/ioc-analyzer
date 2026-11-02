"""Settings (API keys, rate limit) from the environment or one per-user file.

Environment variables win: that is how a SOAR runner or CI passes keys.
Otherwise one file in the user's config folder is read. The current folder is
never searched: analysts run tools inside evidence folders, and a planted .env
could set HTTPS_PROXY and send our requests, API keys included, to an attacker.
"""

import os
import sys
from collections.abc import Mapping
from pathlib import Path

from dotenv import dotenv_values

# The only names we read. Anything else in the file is ignored.
SETTINGS = ("VIRUSTOTAL_API", "ABUSEIPDB_API", "VIRUSTOTAL_RATE_PER_MIN")


def settings_file(
    env: Mapping[str, str] = os.environ, platform: str = sys.platform
) -> Path:
    """Where the per-user settings file lives.

    Windows: %APPDATA%\\ioc-analyzer\\.env
    Others:  $XDG_CONFIG_HOME/ioc-analyzer/.env (default ~/.config/ioc-analyzer/.env)
    """
    if platform == "win32":
        base = env.get("APPDATA") or Path.home() / "AppData" / "Roaming"
    else:
        base = env.get("XDG_CONFIG_HOME") or Path.home() / ".config"
    return Path(base) / "ioc-analyzer" / ".env"


def load_settings(
    env: Mapping[str, str] = os.environ, path: Path | None = None
) -> dict[str, str]:
    """Return our settings: an environment variable wins over the file.

    Empty values count as unset. Nothing is written to os.environ.
    """
    path = settings_file(env) if path is None else path
    from_file = dotenv_values(path) if path.is_file() else {}
    settings: dict[str, str] = {}
    for name in SETTINGS:
        value = env.get(name) or from_file.get(name)
        if value:
            settings[name] = value
    return settings
