import os
from keycloak import KeycloakAdmin

def main():
    admin = KeycloakAdmin(
        server_url="http://keycloak:8080",
        username="admin",
        password="admin",
        realm_name="kimia",
        verify=True
    )
    
    # Get the client ID for kimia-backend
    clients = admin.get_clients()
    backend_client = next((c for c in clients if c["clientId"] == "kimia-backend"), None)
    
    if not backend_client:
        print("kimia-backend client not found")
        return
        
    # Get the service account user for the client
    service_account = admin.get_client_service_account_user(backend_client["id"])
    if not service_account:
        print("Service account not found")
        return
        
    # Get the realm-management client
    realm_mgmt_client = next((c for c in clients if c["clientId"] == "realm-management"), None)
    if not realm_mgmt_client:
        print("realm-management client not found")
        return
        
    # Get the roles we need to assign
    roles_to_assign = ["manage-users", "view-users", "query-users", "manage-realm"]
    client_roles = admin.get_client_roles(realm_mgmt_client["id"])
    
    roles_objects = [r for r in client_roles if r["name"] in roles_to_assign]
    
    # Assign the roles
    admin.assign_client_role(
        user_id=service_account["id"],
        client_id=realm_mgmt_client["id"],
        roles=roles_objects
    )
    print("Successfully assigned roles to service account!")

if __name__ == "__main__":
    main()
