from typing import Any

import jwt

from feast.permissions.auth.auth_type import AuthType
from feast.permissions.auth_model import (
    AuthConfig,
    KubernetesAuthConfig,
    OidcAuthConfig,
)
from feast.permissions.client.auth_client_manager import AuthenticationClientManager
from feast.permissions.client.kubernetes_auth_client_manager import (
    KubernetesAuthClientManager,
)
from feast.permissions.client.oidc_authentication_client_manager import (
    OidcAuthClientManager,
)


def get_auth_client_manager(auth_config: AuthConfig) -> AuthenticationClientManager:
    if auth_config.type == AuthType.OIDC.value:
        assert isinstance(auth_config, OidcAuthConfig)
        return OidcAuthClientManager(auth_config)
    elif auth_config.type == AuthType.KUBERNETES.value:
        assert isinstance(auth_config, KubernetesAuthConfig)
        return KubernetesAuthClientManager(auth_config)
    else:
        raise RuntimeError(
            f"No Auth client manager implemented for the auth type:${auth_config.type}"
        )


def get_auth_token(auth_config: AuthConfig) -> str:
    return get_auth_client_manager(auth_config).get_token()


def create_skip_auth_token(
    auth_config: AuthConfig, intra_communication_base64: str
) -> str:
    payload: dict[str, Any] = {}
    if auth_config.type == AuthType.OIDC.value:
        payload = {
            "preferred_username": f"{intra_communication_base64}",  # Subject claim
        }
    elif auth_config.type == AuthType.KUBERNETES.value:
        payload = {
            "sub": f":::{intra_communication_base64}",  # Subject claim
        }

    return jwt.encode(payload, "")
