import pytest
from ioc_analyzer.clients.virustotal import VirusToTalClient


@pytest.mark.parametrize("api_key", ["", None])
def test_virustotal_client_missing_api_key(api_key):
    with pytest.raises(ValueError, match="VIRUSTOTAL_API"):
        VirusToTalClient(api_key=api_key)


def virustotal_accepts_api_key(api_key):
    client = VirusToTalClient(api_key=api_key)
    assert client is not None
