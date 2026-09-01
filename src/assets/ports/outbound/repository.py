from typing import Protocol, List, Optional
from src.assets.domain.entities import AssetEntity
from src.assets.domain.models import AssetCreate, AssetUpdate

class AssetRepositoryPort(Protocol):
    def get_all(self, skip: int = 0, limit: int = 100, include_deleted: bool = False) -> tuple[List[AssetEntity], int]:
        ...
        
    def get_by_id(self, asset_id: int, include_deleted: bool = False) -> Optional[AssetEntity]:
        ...
        
    def create(self, asset: AssetCreate) -> AssetEntity:
        ...
        
    def update(self, asset_id: int, asset: AssetUpdate) -> Optional[AssetEntity]:
        ...
        
    def delete(self, asset_id: int) -> bool:
        ...
