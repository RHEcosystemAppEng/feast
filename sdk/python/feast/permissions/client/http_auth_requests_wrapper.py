import requests

from feast.permissions.auth_model import AuthConfig
from feast.permissions.client.k8_authentication_client_manager import (
    K8AuthClientManager,
)
from feast.permissions.client.oidc_authentication_client_manager import (
    OidcAuthClientManager,
)


class AuthenticatedRequestsSession(requests.Session):
    def __init__(self, auth_token: str):
        super().__init__()
        self.auth_token = auth_token
        self.headers.update({"Authorization": f"Bearer {self.auth_token}"})


class AuthClientManagerFactory:
    @staticmethod
    def get_auth_client_manager(auth_config: AuthConfig):
        if auth_config.type == "oidc":
            return OidcAuthClientManager(auth_config)
        elif auth_config.type == "kubernetes":
            return K8AuthClientManager(auth_config)
        else:
            raise RuntimeError(
                f"No Auth client manager implemented for the auth type:${auth_config.type}"
            )


class HttpAuthRequestsSessionFactory:
    @staticmethod
    def get_auth_requests_session(auth_config: AuthConfig):
        auth_client_manager = AuthClientManagerFactory.get_auth_client_manager(
            auth_config
        )
        if auth_config.type == "no_auth":
            request_session = requests.session()
        else:
            request_session = AuthenticatedRequestsSession(
                auth_client_manager.get_token()
            )
        return request_session
