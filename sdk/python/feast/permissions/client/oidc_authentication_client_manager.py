import requests

from feast.permissions.auth_model import OidcAuthConfig
from feast.permissions.client.auth_client_manager import AuthenticationClientManager


class OidcAuthClientManager(AuthenticationClientManager):
    def __init__(self, auth_config: OidcAuthConfig):
        self.auth_config = auth_config

    def _get_token_endpoint(self):
        response = requests.get(self.auth_config.auth_discovery_url)
        if response.status_code == 200:
            oidc_config = response.json()
            if not oidc_config["token_endpoint"]:
                raise RuntimeError(
                    " OIDC token_endpoint is not available from discovery url response."
                )
            return oidc_config["token_endpoint"]
        else:
            raise RuntimeError(
                f"Error fetching OIDC token endpoint configuration: {response.status_code} - {response.text}"
            )

    def get_token(self):
        # Fetch the token endpoint from the discovery URL
        token_endpoint = self._get_token_endpoint()

        token_data = {
            "grant_type": "password",
            "client_id": "admin-cli",
            "username": self.auth_config.username,
            "password": self.auth_config.password,
        }

        token_response = requests.post(token_endpoint, data=token_data)
        if token_response.status_code == 200:
            global access_token
            access_token = token_response.json()["access_token"]
            return access_token
        else:
            raise Exception(
                "Failed to obtain access token: {token_response.status_code} - {token_response.text}"
            )
