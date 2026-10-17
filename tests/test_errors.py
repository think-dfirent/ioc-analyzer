from ioc_analyzer.clients.errors import ProviderError, ProviderUnavailableError


def test_unavailable_is_a_provider_error():
    assert issubclass(ProviderUnavailableError, ProviderError)
