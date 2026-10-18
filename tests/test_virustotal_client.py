import pytest
from ioc_analyzer.clients.virustotal import VirusToTalClient, BASE_URL, build_url


@pytest.mark.parametrize("api_key", ["", None])
def test_virustotal_client_missing_api_key(api_key):
    with pytest.raises(ValueError, match="VIRUSTOTAL_API"):
        VirusToTalClient(api_key=api_key)


def virustotal_accepts_api_key(api_key):
    client = VirusToTalClient(api_key=api_key)
    assert client is not None


@pytest.mark.parametrize(
    ("kind", "endpoint"),
    [("ip", "ip_addresses"), ("domain", "domains"), ("file", "files")],
)
def test_build_url_uses_endpoint_for_kind(kind, endpoint):
    assert build_url("abc", kind) == f"{BASE_URL}/{endpoint}/abc"


def test_build_url_rejects_unknown_kind():
    with pytest.raises(ValueError, match="hash"):
        build_url("abc", "hash")


def test_build_url_encodes_path_characters():
    url = build_url("8.8.8.8/../users", "ip")
    assert url == f"{BASE_URL}/ip_addresses/8.8.8.8%2F..%2Fusers"
