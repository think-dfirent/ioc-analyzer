import os
from pathlib import Path

import pytest

from ioc_analyzer.config import load_settings, settings_file


@pytest.fixture
def settings_path(tmp_path):
    path = tmp_path / "ioc-analyzer" / ".env"
    path.parent.mkdir()
    return path


def test_file_is_used_when_the_environment_has_nothing(settings_path):
    settings_path.write_text("VIRUSTOTAL_API=from-file\n")
    assert load_settings(env={}, path=settings_path) == {"VIRUSTOTAL_API": "from-file"}


def test_environment_wins_over_the_file(settings_path):
    settings_path.write_text("VIRUSTOTAL_API=from-file\n")
    env = {"VIRUSTOTAL_API": "from-env"}
    assert load_settings(env=env, path=settings_path)["VIRUSTOTAL_API"] == "from-env"


def test_empty_values_count_as_unset(settings_path):
    settings_path.write_text("VIRUSTOTAL_API=from-file\nABUSEIPDB_API=\n")
    env = {"VIRUSTOTAL_API": ""}
    assert load_settings(env=env, path=settings_path) == {"VIRUSTOTAL_API": "from-file"}


def test_missing_file_means_environment_only(tmp_path):
    env = {"ABUSEIPDB_API": "k"}
    assert load_settings(env=env, path=tmp_path / "nope" / ".env") == env


def test_other_variables_in_the_file_are_ignored(settings_path, monkeypatch):
    monkeypatch.delenv("HTTPS_PROXY", raising=False)
    settings_path.write_text(
        "VIRUSTOTAL_API=k\nHTTPS_PROXY=http://attacker.example:8080\n"
    )

    settings = load_settings(env={}, path=settings_path)

    assert "HTTPS_PROXY" not in settings
    assert "HTTPS_PROXY" not in os.environ  # never copied into it


def test_a_dotenv_in_the_current_folder_is_ignored(tmp_path, monkeypatch):
    (tmp_path / ".env").write_text("VIRUSTOTAL_API=planted\n")
    monkeypatch.chdir(tmp_path)  # e.g. an analyst inside an evidence folder
    assert "VIRUSTOTAL_API" not in load_settings()


@pytest.mark.parametrize(
    ("platform", "env", "expected"),
    [
        (
            "win32",
            {"APPDATA": "C:/Users/a/AppData/Roaming"},
            Path("C:/Users/a/AppData/Roaming/ioc-analyzer/.env"),
        ),
        (
            "linux",
            {"XDG_CONFIG_HOME": "/home/a/.config"},
            Path("/home/a/.config/ioc-analyzer/.env"),
        ),
    ],
)
def test_settings_file_location(platform, env, expected):
    assert settings_file(env=env, platform=platform) == expected
