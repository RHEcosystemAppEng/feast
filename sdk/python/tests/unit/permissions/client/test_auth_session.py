from feast.permissions.client.http_auth_requests_wrapper import AuthenticatedRequestsSession


def test_authorization_header():
    token = "test_token"
    session = AuthenticatedRequestsSession(token)
    assert "Authorization" in session.headers, "Authorization header not found in session headers"
    assert session.headers["Authorization"] == f"Bearer {token}", "Authorization header value is incorrect"


