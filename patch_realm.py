import json

def patch():
    with open("realm-export.json", "r", encoding="utf-8") as f:
        data = json.load(f)
        
    if "users" not in data:
        data["users"] = []
        
    # Check if the service account already exists
    sa_user = next((u for u in data["users"] if u.get("username") == "service-account-kimia-backend"), None)
    
    if not sa_user:
        sa_user = {
            "username": "service-account-kimia-backend",
            "enabled": True,
            "totp": False,
            "emailVerified": False,
            "serviceAccountClientId": "kimia-backend",
            "credentials": [],
            "disableableCredentialTypes": [],
            "requiredActions": [],
            "realmRoles": [
                "default-roles-kimia"
            ],
            "clientRoles": {
                "realm-management": [
                    "manage-users",
                    "view-users",
                    "query-users"
                ]
            }
        }
        data["users"].append(sa_user)
    else:
        if "clientRoles" not in sa_user:
            sa_user["clientRoles"] = {}
        if "realm-management" not in sa_user["clientRoles"]:
            sa_user["clientRoles"]["realm-management"] = []
            
        roles = sa_user["clientRoles"]["realm-management"]
        for role in ["manage-users", "view-users", "query-users"]:
            if role not in roles:
                roles.append(role)
                
    with open("realm-export.json", "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
        
    print("Patched realm-export.json successfully")

if __name__ == "__main__":
    patch()
