import logging
from abc import ABC
from typing import Optional, Union, get_args

from feast.feast_object import FeastObject
from feast.permissions.action import AuthzedAction
from feast.permissions.decision import DecisionStrategy
from feast.permissions.matcher import actions_match_config, resource_match_config
from feast.permissions.policy import AllowAll, Policy

logger = logging.getLogger(__name__)


"""
Constant to refer to all the managed types.
"""
ALL_RESOURCE_TYPES = list(get_args(FeastObject))


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
    _types: list[FeastObject]
    _with_subclasses: bool
    _name_pattern: Optional[str]
    _required_tags: Optional[dict[str, str]]
    _actions: list[AuthzedAction]
    _policy: Policy

    def __init__(
        self,
        name: str,
        types: Union[list[FeastObject], FeastObject] = ALL_RESOURCE_TYPES,
        with_subclasses: bool = True,
        name_pattern: Optional[str] = None,
        required_tags: Optional[dict[str, str]] = None,
        actions: Union[list[AuthzedAction], AuthzedAction] = AuthzedAction.ALL,
        policy: Policy = AllowAll,
    ):
        if not types:
            raise ValueError("The list 'types' must be non-empty.")
        for t in types if isinstance(types, list) else [types]:
            if t not in get_args(FeastObject):
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
    def types(self) -> list[FeastObject]:
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

    def match_resource(self, resource: FeastObject) -> bool:
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