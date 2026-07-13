from __future__ import annotations

from fastapi.testclient import TestClient

from codeshield.api.main import app
from codeshield.version import __version__


def test_health_endpoint() -> None:
    client = TestClient(app)

    response = client.get("/health")

    assert response.status_code == 200
    assert response.json()["status"] == "ok"
    assert response.json()["local_only"] is True


def test_version_endpoint() -> None:
    client = TestClient(app)

    response = client.get("/version")

    assert response.status_code == 200
    assert response.json() == {"version": __version__}


def test_scan_text_endpoint_never_returns_raw_secret() -> None:
    client = TestClient(app)
    raw = "sk_live_51SyntheticTokenValue999"

    response = client.post(
        "/scan/text",
        json={"text": f'api_key = "{raw}"', "destination": "public_git"},
    )

    assert response.status_code == 200
    assert raw not in response.text
    assert response.json()[0]["recommended_action"] == "block"


def test_protect_and_restore_pseudonym_locally() -> None:
    client = TestClient(app)
    raw = "user@example.test"

    protected = client.post(
        "/protect",
        json={
            "text": f"contact={raw}",
            "destination": "external_llm",
            "mode": "pseudonymize",
            "session_id": "api-test",
        },
    )

    assert protected.status_code == 200
    assert raw not in protected.text
    protected_text = protected.json()["protected_text"]
    restored = client.post(
        "/restore",
        json={"text": protected_text, "session_id": "api-test"},
    )
    assert restored.status_code == 200
    assert restored.json()["restored_text"].endswith(raw)


def test_api_rejects_oversized_declared_request() -> None:
    client = TestClient(app)

    response = client.post(
        "/scan/text",
        content=b"{}",
        headers={"content-type": "application/json", "content-length": "1000001"},
    )

    assert response.status_code == 413


def test_api_validation_error_does_not_echo_supplied_secret() -> None:
    client = TestClient(app)
    raw = "sk_live_51SyntheticValidationValue999"

    response = client.post(
        "/scan/text",
        json={"text": raw, "destination": "not-a-destination"},
    )

    assert response.status_code == 422
    assert raw not in response.text
    assert response.json() == {"detail": "request validation failed"}
