"""Every API route must require authentication (static check, no running app needed)."""
import ast
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src"
AUTH_DEPENDENCIES = {"get_current_user", "require_permissions", "require_role"}
PUBLIC_ROUTES = set()  # e.g. {("main.py", "health_check")} — /health is declared on `app`, not on a router


def _routes():
    for path in SRC.glob("*/adapters/inbound/api/*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8-sig"))
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for deco in node.decorator_list:
                if (isinstance(deco, ast.Call) and isinstance(deco.func, ast.Attribute)
                        and isinstance(deco.func.value, ast.Name) and deco.func.value.id == "router"
                        and deco.func.attr in {"get", "post", "put", "patch", "delete"}):
                    yield path, node
                    break


def _has_auth(func) -> bool:
    for default in func.args.defaults + func.args.kw_defaults:
        if isinstance(default, ast.Call) and getattr(default.func, "id", None) == "Depends" and default.args:
            dep = default.args[0]
            name = dep.func.id if isinstance(dep, ast.Call) and isinstance(dep.func, ast.Name) else getattr(dep, "id", None)
            if name in AUTH_DEPENDENCIES:
                return True
    return False


def test_every_route_requires_authentication():
    routes = list(_routes())
    assert len(routes) > 50
    missing = [f"{p.relative_to(SRC)}:{f.lineno} {f.name}" for p, f in routes
               if (p.name, f.name) not in PUBLIC_ROUTES and not _has_auth(f)]
    assert not missing, "Routes without authentication:\n" + "\n".join(missing)


def test_every_keycloak_role_grants_permissions():
    """Each realm role of realm-export.json must be known by the RBAC (name mismatch = no access)."""
    import json
    from src.auth.application.services.rbac_service import RBACService
    realm = json.loads((SRC.parent / "realm-export.json").read_text(encoding="utf-8-sig"))
    roles = [r["name"] for r in realm.get("roles", {}).get("realm", [])]
    app_roles = [r for r in roles if not r.startswith(("default-roles-", "offline_access", "uma_authorization"))]
    assert app_roles
    unknown = [r for r in app_roles if not RBACService.resolve_permissions([r])]
    assert not unknown, f"Keycloak roles without any permission: {unknown}"


def test_system_administrator_can_scan():
    from src.auth.application.services.rbac_service import RBACService
    from src.auth.domain.entities import Permission
    assert Permission.SCAN_EXECUTE in RBACService.resolve_permissions(["System Administrator"])


def test_launching_a_scan_requires_scan_execute():
    from src.auth.application.services.rbac_service import RBACService
    from src.auth.domain.entities import Permission
    assert Permission.SCAN_EXECUTE not in RBACService.resolve_permissions(["Reader"])
    assert Permission.SCAN_EXECUTE in RBACService.resolve_permissions(["Security Analyst"])
