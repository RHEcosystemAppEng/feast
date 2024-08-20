import logging
import os

import grpc

from feast.permissions.auth_model import AuthConfig
from feast.permissions.client.auth_client_manager_factory import (
    create_skip_auth_token,
    get_auth_token,
)

logger = logging.getLogger(__name__)


class GrpcClientAuthHeaderInterceptor(
    grpc.UnaryUnaryClientInterceptor,
    grpc.UnaryStreamClientInterceptor,
    grpc.StreamUnaryClientInterceptor,
    grpc.StreamStreamClientInterceptor,
):
    def __init__(self, auth_type: AuthConfig):
        self._auth_type = auth_type

    def intercept_unary_unary(
        self, continuation, client_call_details, request_iterator
    ):
        client_call_details = self._append_auth_header_metadata(client_call_details)
        return continuation(client_call_details, request_iterator)

    def intercept_unary_stream(
        self, continuation, client_call_details, request_iterator
    ):
        client_call_details = self._append_auth_header_metadata(client_call_details)
        return continuation(client_call_details, request_iterator)

    def intercept_stream_unary(
        self, continuation, client_call_details, request_iterator
    ):
        client_call_details = self._append_auth_header_metadata(client_call_details)
        return continuation(client_call_details, request_iterator)

    def intercept_stream_stream(
        self, continuation, client_call_details, request_iterator
    ):
        client_call_details = self._append_auth_header_metadata(client_call_details)
        return continuation(client_call_details, request_iterator)

    def _append_auth_header_metadata(self, client_call_details):
        logger.debug(
            "Intercepted the grpc api method call to inject Authorization header "
        )
        metadata = client_call_details.metadata or []

        intra_communication_base64 = os.getenv("INTRA_COMMUNICATION_BASE64")
        if intra_communication_base64:
            access_token = create_skip_auth_token(
                self._auth_type, intra_communication_base64
            )
        else:
            access_token = get_auth_token(self._auth_type)
        metadata.append((b"authorization", b"Bearer " + access_token.encode("utf-8")))
        client_call_details = client_call_details._replace(metadata=metadata)
        return client_call_details
