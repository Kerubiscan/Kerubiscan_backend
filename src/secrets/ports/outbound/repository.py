from typing import Protocol, List, Optional
from src.secrets.domain.entities import CredentialEntity
from src.secrets.domain.models import CredentialType

class CredentialRepositoryPort(Protocol):
    def get_by_id(self, credential_id: int) -> Optional[CredentialEntity]:
        ...
        
    def get_by_asset(self, asset_id: int) -> List[CredentialEntity]:
        ...
        
    def create(self, name: str, asset_id: int, credential_type: CredentialType, vault_path: str) -> CredentialEntity:
        ...
        
    def delete(self, credential_id: int) -> bool:
        ...
