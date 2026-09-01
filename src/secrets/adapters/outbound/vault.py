import hvac
import os
import logging
from typing import Dict, Any
from src.core.config import settings
from src.secrets.ports.outbound.vault import VaultPort

logger = logging.getLogger(__name__)

class VaultAdapter(VaultPort):
    def __init__(self):
        # We read from environment variables to connect to Vault
        self.vault_url = os.getenv("VAULT_URL", "http://vault:8200")
        self.vault_token = os.getenv("VAULT_TOKEN", "root")
        
        self.client = hvac.Client(url=self.vault_url, token=self.vault_token)
        
        # Verify connection
        try:
            if not self.client.is_authenticated():
                logger.error("Vault client failed to authenticate")
        except Exception as e:
            logger.error(f"Could not connect to Vault: {str(e)}")

    def store_secret(self, path: str, secret_data: Dict[str, Any]) -> bool:
        """Stores a dictionary of secrets at the specified path inside the secret/ engine."""
        try:
            # Vault KV V2 engine requires data dict wrapper
            self.client.secrets.kv.v2.create_or_update_secret(
                path=path,
                secret=secret_data
            )
            return True
        except Exception as e:
            logger.error(f"Failed to write secret to Vault at {path}: {str(e)}")
            return False

    def get_secret(self, path: str) -> Dict[str, Any]:
        """Retrieves a dictionary of secrets from the specified path."""
        try:
            read_response = self.client.secrets.kv.v2.read_secret_version(path=path)
            return read_response['data']['data']
        except Exception as e:
            logger.error(f"Failed to read secret from Vault at {path}: {str(e)}")
            return {}

    def delete_secret(self, path: str) -> bool:
        """Deletes the secret at the specified path."""
        try:
            self.client.secrets.kv.v2.delete_metadata_and_all_versions(path=path)
            return True
        except Exception as e:
            logger.error(f"Failed to delete secret from Vault at {path}: {str(e)}")
            return False
