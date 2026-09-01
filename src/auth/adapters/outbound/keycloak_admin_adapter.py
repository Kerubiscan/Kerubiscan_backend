from keycloak import KeycloakAdmin
from src.core.config import settings

def get_keycloak_admin():
    return KeycloakAdmin(
        server_url=settings.KEYCLOAK_SERVER_URL,
        client_id=settings.KEYCLOAK_CLIENT_ID,
        realm_name=settings.KEYCLOAK_REALM_NAME,
        client_secret_key=settings.KEYCLOAK_CLIENT_SECRET,
        verify=True
    )

class KeycloakAdminAdapter:
    def __init__(self):
        self.admin = get_keycloak_admin()

    def get_users(self):
        return self.admin.get_users()

    def create_user(self, username: str, email: str, first_name: str, last_name: str, enabled: bool = True, password: str = None):
        payload = {
            "username": username,
            "email": email,
            "firstName": first_name,
            "lastName": last_name,
            "enabled": enabled
        }
        if password:
            payload["credentials"] = [{"type": "password", "value": password, "temporary": False}]
            
        return self.admin.create_user(payload)

    def assign_role(self, user_id: str, role_name: str):
        role = self.admin.get_realm_role(role_name)
        if role:
            self.admin.assign_realm_roles(user_id, [role])
