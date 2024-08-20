import os

import requests
from requests import Session

from feast.permissions.auth.auth_type import AuthType
from feast.permissions.auth_model import (
    AuthConfig,
)
from feast.permissions.client.auth_client_manager_factory import (
    create_skip_auth_token,
    get_auth_token,
)


class AuthenticatedRequestsSession(Session):
    def __init__(self, auth_token: str):
        super().__init__()
        self.headers.update({"Authorization": f"Bearer {auth_token}"})


def get_http_auth_requests_session(auth_config: AuthConfig) -> Session:
    if auth_config.type == AuthType.NONE.value:
        request_session = requests.session()
    else:
        intra_communication_base64 = os.getenv("INTRA_COMMUNICATION_BASE64")
        if intra_communication_base64:
            request_session = AuthenticatedRequestsSession(
                create_skip_auth_token(auth_config, intra_communication_base64)
            )
        else:
            request_session = AuthenticatedRequestsSession(get_auth_token(auth_config))
    return request_session
