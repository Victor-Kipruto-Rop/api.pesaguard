from unittest.mock import Mock

import pytest
import requests

from pesaguard_backend_pipeline.registry_datasource_client import (
    DatasourceContractError,
    DatasourceNotConfigured,
    DatasourceSettings,
    DatasourceUnavailable,
    RegistryDatasourceClient,
)


def make_client(session):
    return RegistryDatasourceClient(
        DatasourceSettings(
            base_url="http://127.0.0.1:8000",
            api_key="local-test-key",
            connect_timeout=1,
            read_timeout=2,
        ),
        session=session,
    )


def test_lookup_found_uses_server_key_timeout_and_correlation_id():
    session = Mock()
    response = Mock(status_code=200)
    response.json.return_value = {
        "found": True,
        "match_type": "exact_identifier",
        "source": "internal_registry",
        "organization": {"legal_name": "Example Limited"},
    }
    session.get.return_value = response

    result = make_client(session).lookup(registration_number="CPR/2024/12345", correlation_id="corr-123")

    assert result["found"] is True
    assert result["evidence_only"] is True
    assert "does not verify" in result["verification_note"]
    args, kwargs = session.get.call_args
    assert args[0] == "http://127.0.0.1:8000/api/v1/registry/lookup"
    assert kwargs["params"] == {"reg_no": "CPR/2024/12345"}
    assert kwargs["headers"]["X-API-Key"] == "local-test-key"
    assert kwargs["headers"]["X-Correlation-ID"] == "corr-123"
    assert kwargs["timeout"] == (1, 2)


def test_lookup_not_found_is_valid_evidence():
    session = Mock()
    response = Mock(status_code=200)
    response.json.return_value = {"found": False, "organization": None, "source": "internal_registry"}
    session.get.return_value = response

    result = make_client(session).lookup(tax_pin="A123456789")

    assert result["found"] is False
    assert result["organization"] is None


@pytest.mark.parametrize("status", [401, 403])
def test_auth_failure_is_configuration_error(status):
    session = Mock()
    session.get.return_value = Mock(status_code=status)
    with pytest.raises(DatasourceNotConfigured):
        make_client(session).lookup(registration_number="ABC123")


@pytest.mark.parametrize("status", [408, 425, 429, 500, 503])
def test_transient_status_is_unavailable(status):
    session = Mock()
    session.get.return_value = Mock(status_code=status)
    with pytest.raises(DatasourceUnavailable):
        make_client(session).lookup(registration_number="ABC123")


def test_transport_timeout_is_unavailable():
    session = Mock()
    session.get.side_effect = requests.Timeout("timeout")
    with pytest.raises(DatasourceUnavailable):
        make_client(session).lookup(registration_number="ABC123")


def test_invalid_payload_fails_closed():
    session = Mock()
    response = Mock(status_code=200)
    response.json.return_value = {"found": "yes", "organization": {}}
    session.get.return_value = response
    with pytest.raises(DatasourceContractError):
        make_client(session).lookup(registration_number="ABC123")


def test_identifier_choice_is_exactly_one():
    client = make_client(Mock())
    with pytest.raises(ValueError):
        client.lookup(registration_number="ABC123", tax_pin="A123456789")
    with pytest.raises(ValueError):
        client.lookup()
