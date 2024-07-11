from abc import ABC, abstractmethod
from typing import Tuple

from feast.permissions.auth.auth_type import AuthType
from feast.permissions.auth_model import (
    AuthConfig,
    KubernetesAuthConfig,
    OidcAuthConfig,
)


class AuthenticationClientManager(ABC):
    @abstractmethod
    def get_token(self) -> str:
        """Retrieves the token based on the authentication type configuration"""
        pass


def get_auth_client_manager(auth_config: AuthConfig) -> AuthenticationClientManager:
    if auth_config.type == AuthType.OIDC.value:
        assert isinstance(auth_config, OidcAuthConfig)

        from feast.permissions.client.oidc_authentication_client_manager import (
            OidcAuthClientManager,
        )

        return OidcAuthClientManager(auth_config)
    elif auth_config.type == AuthType.KUBERNETES.value:
        assert isinstance(auth_config, KubernetesAuthConfig)

        from feast.permissions.client.kubernetes_auth_client_manager import (
            KubernetesAuthClientManager,
        )

        return KubernetesAuthClientManager(auth_config)
    else:
        raise RuntimeError(
            f"No Auth client manager implemented for the auth type:${auth_config.type}"
        )


def create_metadata(auth_config: AuthConfig) -> Tuple[Tuple[str, str]]:
    auth_client_manager = get_auth_client_manager(auth_config)
    token = auth_client_manager.get_token()

    return (("authorization", "Bearer " + token),)