from typing import Protocol, Dict, Any

class VaultPort(Protocol):
    def store_secret(self, path: str, secret_data: Dict[str, Any]) -> bool:
        """Stores a dictionary of secrets at the specified path."""
        ...
        
    def get_secret(self, path: str) -> Dict[str, Any]:
        """Retrieves a dictionary of secrets from the specified path."""
        ...
        
    def delete_secret(self, path: str) -> bool:
        """Deletes the secret at the specified path."""
        ...
