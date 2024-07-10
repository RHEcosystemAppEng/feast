from typing import Literal, Optional

from feast.repo_config import FeastConfigBaseModel


class AuthConfig(FeastConfigBaseModel):
    type: Literal["oidc", "kubernetes", "no_auth"] = "no_auth"


class OidcAuthConfig(AuthConfig):
    auth_server_url: Optional[str] = None
    auth_discovery_url: str
    client_id: Optional[str] = None
    client_secret: Optional[str] = None
    username: str
    password: str
    realm: str = "master"


class NoAuthConfig(AuthConfig):
    pass


class K8AuthConfig(AuthConfig):
    pass
