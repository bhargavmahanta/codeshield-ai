"""Runtime and deterministic schema entry points."""

from __future__ import annotations

import base64

import uvicorn
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from codeshield_management_api.app import create_app
from codeshield_management_api.config import ManagementSettings
from codeshield_management_api.repository import RepositoryError


class SchemaRepository:
    """Unavailable repository used only to build OpenAPI without server secrets."""

    def __getattr__(self, name: str):  # type: ignore[no-untyped-def]
        async def unavailable(*args, **kwargs):  # type: ignore[no-untyped-def]
            del args, kwargs, name
            raise RepositoryError("schema repository is unavailable")

        return unavailable

    async def close(self) -> None:
        return None


def create_runtime_app():  # type: ignore[no-untyped-def]
    return create_app(ManagementSettings.from_environment())


def create_schema_app():  # type: ignore[no-untyped-def]
    private = base64.urlsafe_b64encode(bytes([1]) * 32).rstrip(b"=").decode()
    settings = ManagementSettings(
        supabase_url="http://127.0.0.1:54321",
        supabase_service_credential="schema-only-service-credential-0001",
        signing_private_key=private,
        signing_key_id="schema-key",
        token_pepper="schema-only-token-pepper-material-0001",
    )
    return create_app(
        settings,
        repository=SchemaRepository(),  # type: ignore[arg-type]
        signer=Ed25519PrivateKey.from_private_bytes(bytes([1]) * 32),
    )


app = create_schema_app()


def run() -> None:
    uvicorn.run(
        create_runtime_app(),
        host="127.0.0.1",
        port=8766,
        access_log=False,
        server_header=False,
    )
