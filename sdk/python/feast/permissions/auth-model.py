from enum import Enum


class OidcConfig:
    auth_server_url: str
    client_id: str
    client_secret: str
    username: str
    password: str
    realm: str = "master"


class AuthType(Enum):
    OIDC = "oidc"
    k8 = "k8"
