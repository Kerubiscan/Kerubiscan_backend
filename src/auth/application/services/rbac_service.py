from typing import List, Set
from src.auth.domain.entities import Role, Permission

# Map each Role to its explicitly allowed Permissions
ROLE_PERMISSIONS = {
    Role.READER: [
        Permission.ASSET_READ,
        Permission.AUDIT_READ,
    ],
    Role.SECURITY_ANALYST: [
        Permission.ASSET_READ,
        Permission.ASSET_WRITE,
        Permission.ASSET_DELETE,
        Permission.AUDIT_READ,
    ],
    Role.SYSTEMS_ADMINISTRATOR: [
        Permission.ASSET_READ,
        Permission.ASSET_WRITE,
        Permission.ASSET_DELETE,
        Permission.SECRET_READ,
        Permission.SECRET_WRITE,
        Permission.SECRET_DELETE,
        Permission.AUDIT_READ,
    ],
    Role.ADMINISTRATOR: [
        Permission.ASSET_READ,
        Permission.ASSET_WRITE,
        Permission.ASSET_DELETE,
        Permission.SECRET_READ,
        Permission.SECRET_WRITE,
        Permission.SECRET_DELETE,
        Permission.AUDIT_READ,
        Permission.USER_READ,
        Permission.USER_WRITE,
    ]
}

class RBACService:
    @staticmethod
    def resolve_permissions(roles: List[str]) -> Set[Permission]:
        """
        Given a list of role strings (e.g., from a JWT), resolve the union
        of all allowed permissions.
        """
        user_permissions = set()
        for role_str in roles:
            try:
                role_enum = Role(role_str)
                if role_enum in ROLE_PERMISSIONS:
                    user_permissions.update(ROLE_PERMISSIONS[role_enum])
            except ValueError:
                # Role string is not in our Role enum, ignore or log
                pass
        return user_permissions
