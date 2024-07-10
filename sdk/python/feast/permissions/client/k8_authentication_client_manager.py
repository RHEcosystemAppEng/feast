from feast.permissions.auth_model import K8AuthConfig
from feast.permissions.client.auth_client_manager import AuthenticationClientManager


class K8AuthClientManager(AuthenticationClientManager):
    def __init__(self, auth_config: K8AuthConfig):
        self.auth_config = auth_config

    # TODO: needs to implement this for k8 auth.
    def get_token(self):
        return ""
