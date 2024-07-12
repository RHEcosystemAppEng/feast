import logging
import os
import warnings
from pathlib import Path
from typing import Any, Dict, Optional

import yaml
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictInt,
    StrictStr,
    ValidationError,
    ValidationInfo,
    field_validator,
    model_validator,
)

from feast.errors import (
    FeastFeatureServerTypeInvalidError,
    FeastInvalidAuthConfigClass,
    FeastOfflineStoreInvalidName,
    FeastOnlineStoreInvalidName,
    FeastRegistryNotSetError,
    FeastRegistryTypeInvalidError,
)
from feast.importer import import_class
from feast.permissions.auth.auth_type import AuthType

warnings.simplefilter("once", RuntimeWarning)

_logger = logging.getLogger(__name__)

# These dict exists so that:
# - existing values for the online store type in featurestore.yaml files continue to work in a backwards compatible way
# - first party and third party implementations can use the same class loading code path.
REGISTRY_CLASS_FOR_TYPE = {
    "file": "feast.infra.registry.registry.Registry",
    "sql": "feast.infra.registry.sql.SqlRegistry",
    "snowflake.registry": "feast.infra.registry.snowflake.SnowflakeRegistry",
    "remote": "feast.infra.registry.remote.RemoteRegistry",
}

BATCH_ENGINE_CLASS_FOR_TYPE = {
    "local": "feast.infra.materialization.local_engine.LocalMaterializationEngine",
    "snowflake.engine": "feast.infra.materialization.snowflake_engine.SnowflakeMaterializationEngine",
    "lambda": "feast.infra.materialization.aws_lambda.lambda_engine.LambdaMaterializationEngine",
    "k8s": "feast.infra.materialization.kubernetes.kubernetes_materialization_engine.KubernetesMaterializationEngine",
    "spark.engine": "feast.infra.materialization.contrib.spark.spark_materialization_engine.SparkMaterializationEngine",
}

ONLINE_STORE_CLASS_FOR_TYPE = {
    "sqlite": "feast.infra.online_stores.sqlite.SqliteOnlineStore",
    "datastore": "feast.infra.online_stores.datastore.DatastoreOnlineStore",
    "redis": "feast.infra.online_stores.redis.RedisOnlineStore",
    "dynamodb": "feast.infra.online_stores.dynamodb.DynamoDBOnlineStore",
    "snowflake.online": "feast.infra.online_stores.snowflake.SnowflakeOnlineStore",
    "bigtable": "feast.infra.online_stores.bigtable.BigtableOnlineStore",
    "postgres": "feast.infra.online_stores.contrib.postgres.PostgreSQLOnlineStore",
    "hbase": "feast.infra.online_stores.contrib.hbase_online_store.hbase.HbaseOnlineStore",
    "cassandra": "feast.infra.online_stores.contrib.cassandra_online_store.cassandra_online_store.CassandraOnlineStore",
    "mysql": "feast.infra.online_stores.contrib.mysql_online_store.mysql.MySQLOnlineStore",
    "rockset": "feast.infra.online_stores.contrib.rockset_online_store.rockset.RocksetOnlineStore",
    "hazelcast": "feast.infra.online_stores.contrib.hazelcast_online_store.hazelcast_online_store.HazelcastOnlineStore",
    "ikv": "feast.infra.online_stores.contrib.ikv_online_store.ikv.IKVOnlineStore",
    "elasticsearch": "feast.infra.online_stores.contrib.elasticsearch.ElasticSearchOnlineStore",
    "remote": "feast.infra.online_stores.remote.RemoteOnlineStore",
    "singlestore": "feast.infra.online_stores.contrib.singlestore_online_store.singlestore.SingleStoreOnlineStore",
}

OFFLINE_STORE_CLASS_FOR_TYPE = {
    "file": "feast.infra.offline_stores.file.FileOfflineStore",
    "bigquery": "feast.infra.offline_stores.bigquery.BigQueryOfflineStore",
    "redshift": "feast.infra.offline_stores.redshift.RedshiftOfflineStore",
    "snowflake.offline": "feast.infra.offline_stores.snowflake.SnowflakeOfflineStore",
    "spark": "feast.infra.offline_stores.contrib.spark_offline_store.spark.SparkOfflineStore",
    "trino": "feast.infra.offline_stores.contrib.trino_offline_store.trino.TrinoOfflineStore",
    "postgres": "feast.infra.offline_stores.contrib.postgres_offline_store.postgres.PostgreSQLOfflineStore",
    "athena": "feast.infra.offline_stores.contrib.athena_offline_store.athena.AthenaOfflineStore",
    "mssql": "feast.infra.offline_stores.contrib.mssql_offline_store.mssql.MsSqlServerOfflineStore",
    "duckdb": "feast.infra.offline_stores.duckdb.DuckDBOfflineStore",
    "remote": "feast.infra.offline_stores.remote.RemoteOfflineStore",
}

FEATURE_SERVER_CONFIG_CLASS_FOR_TYPE = {
    "local": "feast.infra.feature_servers.local_process.config.LocalFeatureServerConfig",
}

AUTH_CONFIGS_CLASS_FOR_TYPE = {
    "no_auth": "feast.permissions.auth_model.NoAuthConfig",
    "kubernetes": "feast.permissions.auth_model.KubernetesAuthConfig",
    "oidc": "feast.permissions.auth_model.OidcAuthConfig",
}


class FeastBaseModel(BaseModel):
    """Feast Pydantic Configuration Class"""

    model_config = ConfigDict(arbitrary_types_allowed=True, extra="allow")


class FeastConfigBaseModel(BaseModel):
    """Feast Pydantic Configuration Class"""

    model_config = ConfigDict(arbitrary_types_allowed=True, extra="forbid")


class RegistryConfig(FeastBaseModel):
    """Metadata Store Configuration. Configuration that relates to reading from and writing to the Feast registry."""

    registry_type: StrictStr = "file"
    """ str: Provider name or a class name that implements Registry."""

    registry_store_type: Optional[StrictStr] = None
    """ str: Provider name or a class name that implements RegistryStore. """

    path: StrictStr = ""
    """ str: Path to metadata store.
        If registry_type is 'file', then an be a local path, or remote object storage path, e.g. a GCS URI
        If registry_type is 'sql', then this is a database URL as expected by SQLAlchemy """

    cache_ttl_seconds: StrictInt = 600
    """int: The cache TTL is the amount of time registry state will be cached in memory. If this TTL is exceeded then
     the registry will be refreshed when any feature store method asks for access to registry state. The TTL can be
     set to infinity by setting TTL to 0 seconds, which means the cache will only be loaded once and will never
     expire. Users can manually refresh the cache by calling feature_store.refresh_registry() """

    s3_additional_kwargs: Optional[Dict[str, str]] = None
    """ Dict[str, str]: Extra arguments to pass to boto3 when writing the registry file to S3. """

    sqlalchemy_config_kwargs: Dict[str, Any] = {}
    """ Dict[str, Any]: Extra arguments to pass to SQLAlchemy.create_engine. """

    @field_validator("path")
    def validate_path(cls, path: str, values: ValidationInfo) -> str:
        if values.data.get("registry_type") == "sql":
            if path.startswith("postgresql://"):
                _logger.warning(
                    "The `path` of the `RegistryConfig` starts with a plain "
                    "`postgresql` string. We are updating this to `postgresql+psycopg` "
                    "to ensure that the `psycopg3` driver is used by `sqlalchemy`. If "
                    "you want to use `psycopg2` pass `postgresql+psycopg2` explicitely "
                    "to `path`. To silence this warning, pass `postgresql+psycopg` "
                    "explicitely to `path`."
                )
                return path.replace("postgresql://", "postgresql+psycopg://")
        return path


class RepoConfig(FeastBaseModel):
    """Repo config. Typically loaded from `feature_store.yaml`"""

    project: StrictStr
    """ str: Feast project id. This can be any alphanumeric string up to 16 characters.
        You can have multiple independent feature repositories deployed to the same cloud
        provider account, as long as they have different project ids.
    """

    provider: StrictStr = "local"
    """ str: local or gcp or aws """

    registry_config: Any = Field(alias="registry", default="data/registry.db")
    """ Configures the registry.
        Can be:
            1. str: a path to a file based registry (a local path, or remote object storage path, e.g. a GCS URI)
            2. RegistryConfig: A fully specified file based registry or SQL based registry
            3. SnowflakeRegistryConfig: Using a Snowflake table to store the registry
    """

    online_config: Any = Field(None, alias="online_store")
    """ OnlineStoreConfig: Online store configuration (optional depending on provider) """

    auth: Any = Field(None, alias="auth")
    """ auth: Optional if the services needs the authentication against IDPs (optional depending on provider) """

    offline_config: Any = Field(None, alias="offline_store")
    """ OfflineStoreConfig: Offline store configuration (optional depending on provider) """

    batch_engine_config: Any = Field(None, alias="batch_engine")
    """ BatchMaterializationEngine: Batch materialization configuration (optional depending on provider)"""

    feature_server: Optional[Any] = None
    """ FeatureServerConfig: Feature server configuration (optional depending on provider) """

    flags: Any = None
    """ Flags (deprecated field): Feature flags for experimental features """

    repo_path: Optional[Path] = None

    entity_key_serialization_version: StrictInt = 1
    """ Entity key serialization version: This version is used to control what serialization scheme is
    used when writing data to the online store.
    A value <= 1 uses the serialization scheme used by feast up to Feast 0.22.
    A value of 2 uses a newer serialization scheme, supported as of Feast 0.23.
    A value of 3 uses the latest serialization scheme, supported as of Feast 0.38.
    The main difference between the three schema is that
    v1: the serialization scheme v1 stored `long` values as `int`s, which would result in errors trying to serialize a range of values.
    v2: fixes this error, but v1 is kept around to ensure backwards compatibility - specifically the ability to read
    feature values for entities that have already been written into the online store.
    v3: add entity_key value length to serialized bytes to enable deserialization, which can be used in retrieval of entity_key in document retrieval.
    """

    coerce_tz_aware: Optional[bool] = True
    """ If True, coerces entity_df timestamp columns to be timezone aware (to UTC by default). """

    def __init__(self, **data: Any):
        super().__init__(**data)

        self._registry = None
        if "registry" not in data:
            raise FeastRegistryNotSetError()
        self.registry_config = data["registry"]

        self._offline_store = None
        self.offline_config = data.get("offline_store", "file")

        self._online_store = None
        self.online_config = data.get("online_store", "sqlite")

        self._auth = None
        if "auth" not in data:
            self.auth = dict()
            self.auth["type"] = AuthType.NONE.value
        else:
            self.auth = data.get("auth")

        self._batch_engine = None
        if "batch_engine" in data:
            self.batch_engine_config = data["batch_engine"]
        elif "batch_engine_config" in data:
            self.batch_engine_config = data["batch_engine_config"]
        else:
            # Defaults to using local in-process materialization engine.
            self.batch_engine_config = "local"

        if isinstance(self.feature_server, Dict):
            self.feature_server = get_feature_server_config_from_type(
                self.feature_server["type"]
            )(**self.feature_server)

        if self.entity_key_serialization_version <= 1:
            warnings.warn(
                "`entity_key_serialization_version` is either not specified in the feature_store.yaml, "
                "or is specified to a value <= 1."
                "This serialization version may cause errors when trying to write fields with the `Long` data type"
                " into the online store. Specifying `entity_key_serialization_version` to 2 is recommended for"
                " new projects. ",
                RuntimeWarning,
            )

    @property
    def registry(self):
        if not self._registry:
            if isinstance(self.registry_config, Dict):
                if "registry_type" in self.registry_config:
                    self._registry = get_registry_config_from_type(
                        self.registry_config["registry_type"]
                    )(**self.registry_config)
                else:
                    # This may be a custom registry store, which does not need a 'registry_type'
                    self._registry = RegistryConfig(**self.registry_config)
            elif isinstance(self.registry_config, str):
                # User passed in just a path to file registry
                self._registry = get_registry_config_from_type("file")(
                    path=self.registry_config
                )
            elif self.registry_config:
                self._registry = self.registry_config
        return self._registry

    @property
    def offline_store(self):
        if not self._offline_store:
            if isinstance(self.offline_config, Dict):
                self._offline_store = get_offline_config_from_type(
                    self.offline_config["type"]
                )(**self.offline_config)
            elif isinstance(self.offline_config, str):
                self._offline_store = get_offline_config_from_type(
                    self.offline_config
                )()
            elif self.offline_config:
                self._offline_store = self.offline_config
        return self._offline_store

    @property
    def auth_config(self):
        if not self._auth:
            if isinstance(self.auth, Dict):
                self._auth = get_auth_config_from_type(self.auth.get("type"))(
                    **self.auth
                )
            elif isinstance(self.auth, str):
                self._auth = get_auth_config_from_type(self.auth.get("type"))()
            elif self.auth:
                self._auth = self.auth

        return self._auth

    @property
    def online_store(self):
        if not self._online_store:
            if isinstance(self.online_config, Dict):
                self._online_store = get_online_config_from_type(
                    self.online_config["type"]
                )(**self.online_config)
            elif isinstance(self.online_config, str):
                self._online_store = get_online_config_from_type(self.online_config)()
            elif self.online_config:
                self._online_store = self.online_config

        return self._online_store

    @property
    def batch_engine(self):
        if not self._batch_engine:
            if isinstance(self.batch_engine_config, Dict):
                self._batch_engine = get_batch_engine_config_from_type(
                    self.batch_engine_config["type"]
                )(**self.batch_engine_config)
            elif isinstance(self.batch_engine_config, str):
                self._batch_engine = get_batch_engine_config_from_type(
                    self.batch_engine_config
                )()
            elif self.batch_engine_config:
                self._batch_engine = self._batch_engine

        return self._batch_engine

    @model_validator(mode="before")
    def _validate_auth_config(cls, values: Any) -> Any:
        from feast.permissions.auth_model import AuthConfig

        if "auth" in values:
            allowed_auth_types = AUTH_CONFIGS_CLASS_FOR_TYPE.keys()
            if isinstance(values["auth"], Dict):
                if values["auth"].get("type") is None:
                    raise ValueError(
                        f"auth configuration is not having authentication type. Possible values={allowed_auth_types}"
                    )
                elif values["auth"]["type"] not in allowed_auth_types:
                    raise ValueError(
                        f'auth configuration is having invalid authentication type={values["auth"]["type"]}. Possible '
                        f'values={allowed_auth_types}'
                    )
            elif isinstance(values["auth"], AuthConfig):
                if values["auth"].type not in allowed_auth_types:
                    raise ValueError(
                        f'auth configuration is having invalid authentication type={values["auth"].type}. Possible '
                        f'values={allowed_auth_types}'
                    )
        return values

    @model_validator(mode="before")
    def _validate_online_store_config(cls, values: Any) -> Any:
        # This method will validate whether the online store configurations are set correctly. This explicit validation
        # is necessary because Pydantic Unions throw very verbose and cryptic exceptions. We also use this method to
        # impute the default online store type based on the selected provider. For the time being this method should be
        # considered tech debt until we can implement https://github.com/samuelcolvin/pydantic/issues/619 or a more
        # granular configuration system

        # Set empty online_store config if it isn't set explicitly
        if "online_store" not in values:
            values["online_store"] = dict()

        # Skip if we aren't creating the configuration from a dict or online store is null or it is a string like "None" or "null"
        if not isinstance(values["online_store"], Dict):
            if isinstance(values["online_store"], str) and values[
                "online_store"
            ].lower() in {"none", "null"}:
                values["online_store"] = None
            return values

        # Set the default type
        # This is only direct reference to a provider or online store that we should have
        # for backwards compatibility.
        if "type" not in values["online_store"]:
            values["online_store"]["type"] = "sqlite"

        online_store_type = values["online_store"]["type"]

        # Validate the dict to ensure one of the union types match
        try:
            online_config_class = get_online_config_from_type(online_store_type)
            online_config_class(**values["online_store"])
        except ValidationError as e:
            raise e
        return values

    @model_validator(mode="before")
    @classmethod
    def _validate_offline_store_config(cls, values: Any) -> Any:
        # Set empty offline_store config if it isn't set explicitly
        if "offline_store" not in values:
            values["offline_store"] = dict()

        # Skip if we aren't creating the configuration from a dict
        if not isinstance(values["offline_store"], Dict):
            return values

        # Set the default type
        if "type" not in values["offline_store"]:
            values["offline_store"]["type"] = "file"

        offline_store_type = values["offline_store"]["type"]

        # Validate the dict to ensure one of the union types match
        try:
            offline_config_class = get_offline_config_from_type(offline_store_type)
            offline_config_class(**values["offline_store"])
        except ValidationError as e:
            raise e

        return values

    @model_validator(mode="before")
    @classmethod
    def _validate_feature_server_config(cls, values: Any) -> Any:
        # Having no feature server is the default.
        if "feature_server" not in values:
            return values

        # Skip if we aren't creating the configuration from a dict
        if not isinstance(values["feature_server"], Dict):
            return values

        defined_type = values["feature_server"].get("type", "local")
        values["feature_server"]["type"] = defined_type

        # Validate the dict to ensure one of the union types match
        try:
            feature_server_config_class = get_feature_server_config_from_type(
                defined_type
            )
            feature_server_config_class(**values["feature_server"])
        except ValidationError as e:
            raise e

        return values

    @field_validator("project")
    @classmethod
    def _validate_project_name(cls, v: str) -> str:
        from feast.repo_operations import is_valid_name

        if not is_valid_name(v):
            raise ValueError(
                f"Project name, {v}, should only have "
                f"alphanumerical values and underscores but not start with an underscore."
            )
        return v

    @field_validator("flags")
    @classmethod
    def _validate_flags(cls, v: Optional[dict]) -> Optional[dict]:
        if not isinstance(v, dict):
            return v

        _logger.warning(
            "Flags are no longer necessary in Feast. Experimental features will log warnings instead."
        )

        return v

    def write_to_path(self, repo_path: Path):
        config_path = repo_path / "feature_store.yaml"
        with open(config_path, mode="w") as f:
            yaml.dump(
                yaml.safe_load(
                    self.json(
                        exclude={"repo_path"},
                        exclude_unset=True,
                    )
                ),
                f,
                sort_keys=False,
            )

    model_config = ConfigDict(populate_by_name=True)


class FeastConfigError(Exception):
    def __init__(self, error_message, config_path):
        self._error_message = error_message
        self._config_path = config_path
        super().__init__(self._error_message)

    def __str__(self) -> str:
        return f"{self._error_message}\nat {self._config_path}"

    def __repr__(self) -> str:
        return (
            f"FeastConfigError({repr(self._error_message)}, {repr(self._config_path)})"
        )


def get_data_source_class_from_type(data_source_type: str):
    module_name, config_class_name = data_source_type.rsplit(".", 1)
    return import_class(module_name, config_class_name, "DataSource")


def get_registry_config_from_type(registry_type: str):
    # We do not support custom registry's right now
    if registry_type not in REGISTRY_CLASS_FOR_TYPE:
        raise FeastRegistryTypeInvalidError(registry_type)
    registry_type = REGISTRY_CLASS_FOR_TYPE[registry_type]
    module_name, registry_class_type = registry_type.rsplit(".", 1)
    config_class_name = f"{registry_class_type}Config"
    return import_class(module_name, config_class_name, config_class_name)


def get_batch_engine_config_from_type(batch_engine_type: str):
    if batch_engine_type in BATCH_ENGINE_CLASS_FOR_TYPE:
        batch_engine_type = BATCH_ENGINE_CLASS_FOR_TYPE[batch_engine_type]
    else:
        assert batch_engine_type.endswith("Engine")
    module_name, batch_engine_class_type = batch_engine_type.rsplit(".", 1)
    config_class_name = f"{batch_engine_class_type}Config"

    return import_class(module_name, config_class_name, config_class_name)


def get_online_config_from_type(online_store_type: str):
    if online_store_type in ONLINE_STORE_CLASS_FOR_TYPE:
        online_store_type = ONLINE_STORE_CLASS_FOR_TYPE[online_store_type]
    elif not online_store_type.endswith("OnlineStore"):
        raise FeastOnlineStoreInvalidName(online_store_type)
    module_name, online_store_class_type = online_store_type.rsplit(".", 1)
    config_class_name = f"{online_store_class_type}Config"

    return import_class(module_name, config_class_name, config_class_name)


def get_auth_config_from_type(auth_config_type: str):
    if auth_config_type in AUTH_CONFIGS_CLASS_FOR_TYPE:
        auth_config_type = AUTH_CONFIGS_CLASS_FOR_TYPE[auth_config_type]
    elif not auth_config_type.endswith("AuthConfig"):
        raise FeastInvalidAuthConfigClass(auth_config_type)
    module_name, online_store_class_type = auth_config_type.rsplit(".", 1)
    config_class_name = f"{online_store_class_type}"

    return import_class(module_name, config_class_name, config_class_name)


def get_offline_config_from_type(offline_store_type: str):
    if offline_store_type in OFFLINE_STORE_CLASS_FOR_TYPE:
        offline_store_type = OFFLINE_STORE_CLASS_FOR_TYPE[offline_store_type]
    elif not offline_store_type.endswith("OfflineStore"):
        raise FeastOfflineStoreInvalidName(offline_store_type)
    module_name, offline_store_class_type = offline_store_type.rsplit(".", 1)
    config_class_name = f"{offline_store_class_type}Config"

    return import_class(module_name, config_class_name, config_class_name)


def get_feature_server_config_from_type(feature_server_type: str):
    # We do not support custom feature servers right now.
    if feature_server_type not in FEATURE_SERVER_CONFIG_CLASS_FOR_TYPE:
        raise FeastFeatureServerTypeInvalidError(feature_server_type)

    feature_server_type = FEATURE_SERVER_CONFIG_CLASS_FOR_TYPE[feature_server_type]
    module_name, config_class_name = feature_server_type.rsplit(".", 1)
    return import_class(module_name, config_class_name, config_class_name)


def load_repo_config(repo_path: Path, fs_yaml_file: Path) -> RepoConfig:
    config_path = fs_yaml_file

    with open(config_path) as f:
        raw_config = yaml.safe_load(os.path.expandvars(f.read()))
        try:
            c = RepoConfig(**raw_config)
            c.repo_path = repo_path
            return c
        except ValidationError as e:
            raise FeastConfigError(e, config_path)
