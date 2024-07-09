"""
A module with utility functions to support the authorization management in Feast servers.
"""

import enum
import logging
import os

import feast
from feast.permissions.auth.auth_manager import (
    AllowAll,
    AuthManager,
    set_auth_manager,
)
from feast.permissions.auth.kubernetes_token_parser import KubernetesTokenParser
from feast.permissions.auth.oidc_token_parser import OidcTokenParser
from feast.permissions.auth.token_extractor import TokenExtractor
from feast.permissions.auth.token_parser import TokenParser
from feast.permissions.security_manager import (
    SecurityManager,
    no_security_manager,
    set_security_manager,
)
from feast.permissions.server.arrow_flight_token_extractor import (
    ArrowFlightTokenExtractor,
)
from feast.permissions.server.rest_token_extractor import RestTokenExtractor

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


class ServerType(enum.Enum):
    """
    Identify the server type.
    """

    REST = "rest"
    ARROW = "arrow"
    GRPC = "grpc"  # TODO RBAC: to be completed


class AuthManagerType(enum.Enum):
    """
    Identify the type of authorization manager.
    """

    NONE = "none"
    OIDC = "oidc"
    KUBERNETES = "kubernetes"


# TODO RBAC: will remove once we can manage the auth configuration
def auth_manager_type_from_env() -> AuthManagerType:
    type = os.getenv("AUTH_MANAGER_TYPE", "none")
    print(f"Configuring authentication manager for {type}")

    if type.lower() == AuthManagerType.OIDC.value:
        return AuthManagerType.OIDC
    if type.lower() == AuthManagerType.KUBERNETES.value:
        return AuthManagerType.KUBERNETES

    return AuthManagerType.NONE


def init_security_manager(auth_manager_type: AuthManagerType, fs: "feast.FeatureStore"):
    """
    Initialize the global security manager.
    Must be invoked at Feast server initialization time to create the `SecurityManager` instance.

    Args:
        auth_manager_type: The authorization manager type.
        registry: The feature store registry.
    """
    if auth_manager_type == AuthManagerType.NONE:
        no_security_manager()
    else:
        # TODO permissions from registry
        set_security_manager(
            SecurityManager(
                project=fs.project,
                registry=fs.registry,
            )
        )


def init_auth_manager(server_type: ServerType, auth_manager_type: AuthManagerType):
    """
    Initialize the global authorization manager.
    Must be invoked at Feast server initialization time to create the `AuthManager` instance.

    Args:
        server_type: The server type.
        auth_manager_type: The authorization manager type.

    Raises:
        ValueError: If any input argument has an unmanaged value.
    """
    if auth_manager_type == AuthManagerType.NONE:
        return AllowAll()

    token_extractor: TokenExtractor
    token_parser: TokenParser

    if server_type == ServerType.REST:
        token_extractor = RestTokenExtractor()
    elif server_type == ServerType.ARROW:
        token_extractor = ArrowFlightTokenExtractor()
    else:
        raise ValueError(f"Unmanaged server type {server_type}")

    if auth_manager_type == AuthManagerType.KUBERNETES:
        token_parser = KubernetesTokenParser()
    elif auth_manager_type == AuthManagerType.OIDC:
        token_parser = OidcTokenParser()
    else:
        raise ValueError(f"Unmanaged authorization manager type {auth_manager_type}")

    auth_manager = AuthManager(
        token_extractor=token_extractor, token_parser=token_parser
    )
    set_auth_manager(auth_manager)
