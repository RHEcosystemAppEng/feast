import asyncio
import logging
from typing import Optional

import grpc

from feast.permissions.auth.auth_manager import (
    get_auth_manager,
)
from feast.permissions.server.utils import (
    AuthManagerType,
    auth_manager_type_from_env,
)

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


def grpc_interceptors() -> Optional[list[grpc.ServerInterceptor]]:
    """
    A list of the authorization interceptors.

    Returns:
        list[grpc.ServerInterceptor]: Optional list of interceptors. If the authorization type is set to `NONE`, it returns `None`.
    """
    # TODO RBAC remove and use the auth section of the feature store config instead
    auth_manager_type = auth_manager_type_from_env()
    if auth_manager_type == AuthManagerType.NONE:
        return None

    return [AuthInterceptor()]


class AuthInterceptor(grpc.ServerInterceptor):
    def intercept_service(self, continuation, handler_call_details):
        auth_manager = get_auth_manager()
        access_token = auth_manager.token_extractor.extract_access_token(
            metadata=dict(handler_call_details.invocation_metadata)
        )

        print(f"Fetching user for token: {len(access_token)}")
        current_user = asyncio.run(
            auth_manager.token_parser.user_details_from_access_token(access_token)
        )
        print(f"User is: {current_user}")

        return continuation(handler_call_details)
