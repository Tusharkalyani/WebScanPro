import pytest
from webscanpro.core.target_validator import TargetValidator, TargetValidationError

def test_normalize_url():
    assert TargetValidator.normalize_url("localhost:3000") == "http://localhost:3000"
    assert TargetValidator.normalize_url("http://127.0.0.1:4280/") == "http://127.0.0.1:4280"
    assert TargetValidator.normalize_url("https://localhost:8443/app") == "https://localhost:8443/app"

def test_reject_empty_or_invalid_scheme():
    with pytest.raises(TargetValidationError):
        TargetValidator.normalize_url("")

    with pytest.raises(TargetValidationError):
        TargetValidator.normalize_url("ftp://localhost:21")

def test_validate_target_authorized_loopback():
    res = TargetValidator.validate_target(
        url="http://localhost:3000",
        is_explicitly_authorized=True
    )
    assert res["valid"] is True
    assert res["host"] == "localhost"
    assert res["port"] == 3000

def test_reject_unauthorized_target():
    with pytest.raises(TargetValidationError, match="Explicit target authorization"):
        TargetValidator.validate_target(
            url="http://localhost:3000",
            is_explicitly_authorized=False
        )

def test_reject_public_unapproved_target():
    with pytest.raises(TargetValidationError, match="Security Boundary Enforcement"):
        TargetValidator.validate_target(
            url="http://example.com",
            is_explicitly_authorized=True
        )
