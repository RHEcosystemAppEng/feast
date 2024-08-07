import logging
import re
from abc import ABC
from typing import TYPE_CHECKING, Any, Optional, Union

from feast.importer import import_class
from feast.permissions.action import AuthzedAction
from feast.permissions.decision import DecisionStrategy
from feast.permissions.matcher import actions_match_config, resource_match_config
from feast.permissions.policy import AllowAll, Policy
from feast.protos.feast.core.Permission_pb2 import Permission as PermissionProto

if TYPE_CHECKING:
    from feast.feast_object import FeastObject

logger = logging.getLogger(__name__)

"""
Constant to refer to all the managed types.
"""


class Permission(ABC):
    """
    The Permission class defines the authorization policy to be validated whenever the identified actions are
    requested on the matching resources.

    Attributes:
        name: The permission name (can be duplicated, used for logging troubleshooting).
        types: The list of protected resource  types as defined by the `FeastObject` type.
        Defaults to all managed types (e.g. the `ALL_RESOURCE_TYPES` constant)
        with_subclasses: If `True`, it includes sub-classes of the given types in the match, otherwise only exact type match is applied.
        Defaults to `True`.
        name_pattern: A regex to match the resource name. Defaults to None, meaning that no name filtering is applied
        required_tags: Dictionary of key-value pairs that must match the resource tags. All these required_tags must
        be present in a resource tags with the given value. Defaults to None, meaning that no tags filtering is applied.
        actions: The actions authorized by this permission. Defaults to `AuthzedAction.ALL`.
        policy: The policy to be applied to validate a client request.
    """

    _name: str
    _types: list["FeastObject"]
    _with_subclasses: bool
    _name_pattern: Optional[str]
    _required_tags: Optional[dict[str, str]]
    _actions: list[AuthzedAction]
    _policy: Policy

    def __init__(
        self,
        name: str,
        types: Optional[Union[list["FeastObject"], "FeastObject"]] = None,
        with_subclasses: bool = True,
        name_pattern: Optional[str] = None,
        required_tags: Optional[dict[str, str]] = None,
        actions: Union[list[AuthzedAction], AuthzedAction] = AuthzedAction.ALL,
        policy: Policy = AllowAll,
    ):
        from feast.feast_object import ALL_RESOURCE_TYPES

        if not types:
            types = ALL_RESOURCE_TYPES
        for t in types if isinstance(types, list) else [types]:
            if t not in ALL_RESOURCE_TYPES:
                raise ValueError(f"{t} is not one of the managed types")
        if actions is None or not actions:
            raise ValueError("The list 'actions' must be non-empty.")
        if not policy:
            raise ValueError("The list 'policy' must be non-empty.")
        self._name = name
        self._types = types if isinstance(types, list) else [types]
        self._with_subclasses = with_subclasses
        self._name_pattern = _normalize_name_pattern(name_pattern)
        self._required_tags = _normalize_required_tags(required_tags)
        self._actions = actions if isinstance(actions, list) else [actions]
        self._policy = policy

    def __eq__(self, other):
        if not isinstance(other, Permission):
            raise TypeError("Comparisons should only involve Permission class objects.")

        if (
            self.name != other.name
            or self.with_subclasses != other.with_subclasses
            or self.name_pattern != other.name_pattern
            or self.required_tags != other.required_tags
            or self.policy != other.policy
            or self.actions != other.actions
        ):
            return False

        if set(self.types) != set(other.types):
            return False

        return True

    _global_decision_strategy: DecisionStrategy = DecisionStrategy.UNANIMOUS

    @staticmethod
    def get_global_decision_strategy() -> DecisionStrategy:
        """
        The global decision strategy to be applied when multiple permissions match an execution request.
        """
        return Permission._global_decision_strategy

    @staticmethod
    def set_global_decision_strategy(global_decision_strategy: DecisionStrategy):
        """
        Define the global decision strategy to be applied when multiple permissions match an execution request.
        """
        Permission._global_decision_strategy = global_decision_strategy

    @property
    def name(self) -> str:
        return self._name

    @property
    def types(self) -> list["FeastObject"]:
        return self._types

    @property
    def with_subclasses(self) -> bool:
        return self._with_subclasses

    @property
    def name_pattern(self) -> Optional[str]:
        return self._name_pattern

    @property
    def required_tags(self) -> Optional[dict[str, str]]:
        return self._required_tags

    @property
    def actions(self) -> list[AuthzedAction]:
        return self._actions

    @property
    def policy(self) -> Policy:
        return self._policy

    def match_resource(self, resource: "FeastObject") -> bool:
        """
        Returns:
            `True` when the given resource matches the type, name and tags filters defined in the permission.
        """
        return resource_match_config(
            resource=resource,
            expected_types=self.types,
            with_subclasses=self.with_subclasses,
            name_pattern=self.name_pattern,
            required_tags=self.required_tags,
        )

    def match_actions(self, requested_actions: list[AuthzedAction]) -> bool:
        """
        Returns:
            `True` when the given actions are included in the permitted actions.
        """
        return actions_match_config(
            allowed_actions=self.actions,
            requested_actions=requested_actions,
        )

    @staticmethod
    def from_proto(permission_proto: PermissionProto) -> Any:
        """
        Converts permission config in protobuf spec to a Permission class object.

        Args:
            permission_proto: A protobuf representation of a Permission.

        Returns:
            A Permission class object.
        """

        types = [
            get_type_class_from_permission_type(
                _PERMISSION_TYPES[PermissionProto.Type.Name(t)]
            )
            for t in permission_proto.types
        ]
        actions = [
            AuthzedAction[PermissionProto.AuthzedAction.Name(action)]
            for action in permission_proto.actions
        ]

        permission = Permission(
            permission_proto.name,
            types,
            permission_proto.with_subclasses,
            permission_proto.name_pattern or None,
            dict(permission_proto.required_tags),
            actions,
            Policy.from_proto(permission_proto.policy),
        )

        return permission

    def to_proto(self) -> PermissionProto:
        """
        Converts a PermissionProto object to its protobuf representation.
        """
        types = [
            PermissionProto.Type.Value(
                re.sub(r"([a-z])([A-Z])", r"\1_\2", t.__name__).upper()  # type: ignore[union-attr]
            )
            for t in self.types
        ]

        actions = [
            PermissionProto.AuthzedAction.Value(action.name) for action in self.actions
        ]

        permission_proto = PermissionProto(
            name=self.name,
            types=types,
            with_subclasses=self.with_subclasses,
            name_pattern=self.name_pattern if self.name_pattern is not None else None,
            required_tags=self.required_tags,
            actions=actions,
            policy=self.policy.to_proto(),
        )

        return permission_proto


def _normalize_name_pattern(name_pattern: Optional[str]):
    if name_pattern is not None:
        return name_pattern.strip()
    return None


def _normalize_required_tags(required_tags: Optional[dict[str, str]]):
    if required_tags:
        return {
            k.strip(): v.strip() if isinstance(v, str) else v
            for k, v in required_tags.items()
        }
    return None


def get_type_class_from_permission_type(permission_type: str):
    module_name, config_class_name = permission_type.rsplit(".", 1)
    return import_class(module_name, config_class_name)


_PERMISSION_TYPES = {
    "FEATURE_VIEW": "feast.feature_view.FeatureView",
    "ON_DEMAND_FEATURE_VIEW": "feast.on_demand_feature_view.OnDemandFeatureView",
    "BATCH_FEATURE_VIEW": "feast.batch_feature_view.BatchFeatureView",
    "STREAM_FEATURE_VIEW": "feast.stream_feature_view.StreamFeatureView",
    "ENTITY": "feast.entity.Entity",
    "FEATURE_SERVICE": "feast.feature_service.FeatureService",
    "DATA_SOURCE": "feast.data_source.DataSource",
    "VALIDATION_REFERENCE": "feast.saved_dataset.ValidationReference",
    "SAVED_DATASET": "feast.saved_dataset.SavedDataset",
    "PERMISSION": "feast.permissions.permission.Permission",
}
