import logging
from contextvars import ContextVar
from typing import List, Optional, Union

from feast.feast_object import FeastObject
from feast.permissions.enforcer import enforce_policy
from feast.permissions.permission import AuthzedAction, Permission
from feast.permissions.role_manager import RoleManager

logger = logging.getLogger(__name__)


class SecurityManager:
    """
    The security manager holds references to the security components (role manager, policy enforces) and the configured permissions.
    It is accessed and defined using the global functions :func:`_get_security_manager` and :func:`_set_security_manager`
    """

    def __init__(
        self,
        role_manager: RoleManager,
        permissions: list[Permission] = [],
    ):
        self._role_manager: RoleManager = role_manager
        self._permissions: list[Permission] = permissions
        self._current_user: ContextVar[Optional[str]] = ContextVar(
            "current_user", default=None
        )

    def set_current_user(self, user: str):
        self._current_user.set(user)

    @property
    def role_manager(self) -> RoleManager:
        return self._role_manager

    @property
    def current_user(self) -> Optional[str]:
        return self._current_user.get()

    @property
    def permissions(self) -> list[Permission]:
        return self._permissions

    def assert_permissions(
        self,
        resource: FeastObject,
        actions: Union[AuthzedAction, List[AuthzedAction]],
    ):
        """
        TODO ADD DOCSTRING
        """
        result, explain = enforce_policy(
            role_manager=self._role_manager,
            permissions=self._permissions,
            user=self.current_user if self.current_user is not None else "",
            resource=resource,
            actions=actions if isinstance(actions, list) else [actions],
        )
        if not result:
            raise PermissionError(explain)


"""
Global instance.
"""
_sm: Optional[SecurityManager] = None


"""
Return the global instance of `SecurityManager`.
"""


def get_security_manager() -> Optional[SecurityManager]:
    global _sm
    return _sm


"""
Initializes the global instance of `SecurityManager`.
"""


def set_security_manager(sm: SecurityManager):
    global _sm
    _sm = sm
