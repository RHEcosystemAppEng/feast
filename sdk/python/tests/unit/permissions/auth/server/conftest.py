import logging
import os
import platform
import sys
import tempfile
from textwrap import dedent

import pytest
import yaml
from testcontainers.keycloak import KeycloakContainer

from feast import (
    Entity,
    FeatureStore,
    FeatureView,
    OnDemandFeatureView,
    StreamFeatureView,
)
from feast.permissions.action import AuthzedAction
from feast.permissions.permission import Permission
from feast.permissions.policy import RoleBasedPolicy
from feast import FeatureStore
from tests.unit.permissions.auth.server import mock_utils
from tests.unit.permissions.auth.server.mock_utils import PROJECT_NAME
from tests.utils.cli_repo_creator import CliRunner
from tests.utils.http_server import free_port  # noqa: E402

logger = logging.getLogger(__name__)

list_permissions_perm = Permission(
    name="list_permissions_perm",
    types=Permission,
    policy=RoleBasedPolicy(roles=["reader"]),
    actions=[AuthzedAction.READ],
)

list_entities_perm = Permission(
    name="list_entities_perm",
    types=Entity,
    with_subclasses=False,
    policy=RoleBasedPolicy(roles=["reader"]),
    actions=[AuthzedAction.READ],
)

list_fv_perm = Permission(
    name="list_fv_perm",
    types=FeatureView,
    with_subclasses=False,
    policy=RoleBasedPolicy(roles=["reader"]),
    actions=[AuthzedAction.READ],
)


list_odfv_perm = Permission(
    name="list_odfv_perm",
    types=OnDemandFeatureView,
    with_subclasses=False,
    policy=RoleBasedPolicy(roles=["reader"]),
    actions=[AuthzedAction.READ],
)

list_sfv_perm = Permission(
    name="list_sfv_perm",
    types=StreamFeatureView,
    with_subclasses=False,
    policy=RoleBasedPolicy(roles=["reader"]),
    actions=[AuthzedAction.READ],
)

invalid_list_entities_perm = Permission(
    name="invalid_list_entity_perm",
    types=Entity,
    with_subclasses=False,
    policy=RoleBasedPolicy(roles=["dancer"]),
    actions=[AuthzedAction.READ],
)


@pytest.fixture(
    scope="module",
    params=[
        dedent("""
          auth:
            type: no_auth
          """),
        dedent("""
          auth:
            type: kubernetes
        """),
        dedent("""
          auth:
            type: oidc
            client_id: feast-integration-client
            client_secret: feast-integration-client-secret
            username: reader_writer
            password: password
            realm: master
            auth_server_url: KEYCLOAK_AUTH_SERVER_PLACEHOLDER
            auth_discovery_url: KEYCLOAK_AUTH_SERVER_PLACEHOLDER/realms/master/.well-known/openid-configuration
        """),
    ],
)
def auth_config(request):
    auth_config = request.param
    if "oidc" in auth_config:
        from _pytest.monkeypatch import MonkeyPatch

        monkeypatch = MonkeyPatch()
        request.addfinalizer(monkeypatch.undo)

        if platform.system() == "Darwin":
            auth_config_yaml = yaml.safe_load(auth_config)
            mock_utils._mock_oidc(
                request=request,
                monkeypatch=monkeypatch,
                client_id=auth_config_yaml["auth"]["client_id"],
            )
        else:
            keycloak_host = request.getfixturevalue("start_keycloak_server")
            auth_config = auth_config.replace(
                "KEYCLOAK_AUTH_SERVER_PLACEHOLDER", keycloak_host
            )
    return auth_config


@pytest.fixture
def temp_dir():
    with tempfile.TemporaryDirectory() as temp_dir:
        print(f"Created {temp_dir}")
        yield temp_dir


@pytest.fixture
def feature_store(temp_dir, auth_config, applied_permissions):
    print(f"Creating store at {temp_dir}")
    return _default_store(str(temp_dir), auth_config, applied_permissions)


@pytest.fixture(scope="module")
def start_keycloak_server():
    with KeycloakContainer("quay.io/keycloak/keycloak:24.0.1") as keycloak_container:
        keycloak_admin = keycloak_container.get_client()

        new_client_id = "feast-integration-client"
        new_client_secret = "feast-integration-client-secret"
        # Create a new client
        client_representation = {
            "clientId": new_client_id,
            "secret": new_client_secret,
            "enabled": True,
            "directAccessGrantsEnabled": True,
            "publicClient": False,
            "redirectUris": ["*"],
            "serviceAccountsEnabled": True,
            "standardFlowEnabled": True,
        }
        keycloak_admin.create_client(client_representation)

        # Get the client ID
        client_id = keycloak_admin.get_client_id(new_client_id)

        # Role representation
        reader_role_rep = {
            "name": "reader",
            "description": "feast reader client role",
            "composite": False,
            "clientRole": True,
            "containerId": client_id,
        }
        keycloak_admin.create_client_role(client_id, reader_role_rep, True)
        reader_role_id = keycloak_admin.get_client_role(
            client_id=client_id, role_name="reader"
        )

        # Role representation
        writer_role_rep = {
            "name": "writer",
            "description": "feast writer client role",
            "composite": False,
            "clientRole": True,
            "containerId": client_id,
        }
        keycloak_admin.create_client_role(client_id, writer_role_rep, True)
        writer_role_id = keycloak_admin.get_client_role(
            client_id=client_id, role_name="writer"
        )

        # Mapper representation
        mapper_representation = {
            "name": "client-roles-mapper",
            "protocol": "openid-connect",
            "protocolMapper": "oidc-usermodel-client-role-mapper",
            "consentRequired": False,
            "config": {
                "multivalued": "true",
                "userinfo.token.claim": "true",
                "id.token.claim": "true",
                "access.token.claim": "true",
                "claim.name": "roles",
                "jsonType.label": "String",
                "client.id": client_id,
            },
        }

        # Add predefined client roles mapper to the client
        keycloak_admin.add_mapper_to_client(client_id, mapper_representation)

        reader_writer_user = {
            "username": "reader_writer",
            "enabled": True,
            "firstName": "reader_writer fn",
            "lastName": "reader_writer ln",
            "email": "reader_writer@email.com",
            "emailVerified": True,
            "credentials": [
                {"value": "password", "type": "password", "temporary": False}
            ],
        }
        reader_writer_user_id = keycloak_admin.create_user(reader_writer_user)
        keycloak_admin.assign_client_role(
            user_id=reader_writer_user_id,
            client_id=client_id,
            roles=[reader_role_id, writer_role_id],
        )

        reader_user = {
            "username": "reader",
            "enabled": True,
            "firstName": "reader fn",
            "lastName": "reader ln",
            "email": "reader@email.com",
            "emailVerified": True,
            "credentials": [
                {"value": "password", "type": "password", "temporary": False}
            ],
        }
        reader_user_id = keycloak_admin.create_user(reader_user)
        keycloak_admin.assign_client_role(
            user_id=reader_user_id, client_id=client_id, roles=[reader_role_id]
        )

        writer_user = {
            "username": "writer",
            "enabled": True,
            "firstName": "writer fn",
            "lastName": "writer ln",
            "email": "writer@email.com",
            "emailVerified": True,
            "credentials": [
                {"value": "password", "type": "password", "temporary": False}
            ],
        }
        writer_user_id = keycloak_admin.create_user(writer_user)
        keycloak_admin.assign_client_role(
            user_id=writer_user_id, client_id=client_id, roles=[writer_role_id]
        )

        no_roles_user = {
            "username": "no_roles_user",
            "enabled": True,
            "firstName": "no_roles_user fn",
            "lastName": "no_roles_user ln",
            "email": "no_roles_user@email.com",
            "emailVerified": True,
            "credentials": [
                {"value": "password", "type": "password", "temporary": False}
            ],
        }
        keycloak_admin.create_user(no_roles_user)
        yield keycloak_container.get_url()


@pytest.fixture
def server_port():
    return free_port()


@pytest.fixture(
    scope="module",
    params=[
        [],
        [invalid_list_entities_perm],
        [
            list_entities_perm,
            list_permissions_perm,
            list_fv_perm,
            list_odfv_perm,
            list_sfv_perm,
        ],
    ],
)
def applied_permissions(request):
    return request.param


def _include_auth_config(file_path, auth_config: str):
    with open(file_path, "r") as file:
        existing_content = yaml.safe_load(file)
    new_section = yaml.safe_load(auth_config)
    if isinstance(existing_content, dict) and isinstance(new_section, dict):
        existing_content.update(new_section)
    else:
        raise ValueError("Both existing content and new section must be dictionaries.")
    with open(file_path, "w") as file:
        yaml.safe_dump(existing_content, file, default_flow_style=False)
    print(f"Updated auth section at {file_path}")


def _default_store(
    temp_dir,
    auth_config: str,
    permissions: list[Permission],
):
    runner = CliRunner()
    result = runner.run(["init", PROJECT_NAME], cwd=temp_dir)
    repo_path = os.path.join(temp_dir, PROJECT_NAME, "feature_repo")
    assert result.returncode == 0

    _include_auth_config(
        file_path=f"{repo_path}/feature_store.yaml", auth_config=auth_config
    )

    result = runner.run(["--chdir", repo_path, "apply"], cwd=temp_dir)
    assert result.returncode == 0

    fs = FeatureStore(repo_path=repo_path)

    fs.apply(permissions)

    return fs
