from sqlalchemy.orm import Session
from sqlalchemy import select, func
from typing import List, Optional, Tuple
from src.assets.ports.outbound.repository import AssetRepositoryPort
from src.assets.domain.entities import AssetEntity
from src.assets.domain.models import AssetCreate, AssetUpdate

class AssetRepository(AssetRepositoryPort):
    def __init__(self, db: Session):
        self.db = db

    def get_all(self, skip: int = 0, limit: int = 100, include_deleted: bool = False, company_id: Optional[int] = None, network_zone: Optional[str] = None) -> Tuple[List[AssetEntity], int]:
        query = select(AssetEntity)
        if not include_deleted:
            query = query.where(AssetEntity.is_deleted == False)
            
        if company_id is not None:
            query = query.where(AssetEntity.company_id == company_id)
            
        if network_zone:
            query = query.where(AssetEntity.network_zone == network_zone)
            
        total = self.db.execute(select(func.count()).select_from(query.subquery())).scalar_one()
        
        query = query.offset(skip).limit(limit)
        results = self.db.execute(query).scalars().all()
        return list(results), total

    def get_by_id(self, asset_id: str, include_deleted: bool = False, lock: bool = False) -> Optional[AssetEntity]:
        query = select(AssetEntity).where(AssetEntity.id == asset_id)
        if not include_deleted:
            query = query.where(AssetEntity.is_deleted == False)
        if lock:
            query = query.with_for_update()
        return self.db.execute(query).scalar_one_or_none()
        
    def get_by_ip_and_name(self, ip_address: str, name: str) -> Optional[AssetEntity]:
        query = select(AssetEntity).where(AssetEntity.ip_address == ip_address, AssetEntity.name == name, AssetEntity.is_deleted == False)
        return self.db.execute(query).scalar_one_or_none()

    def create(self, asset_in: AssetCreate) -> AssetEntity:
        db_asset = AssetEntity(
            name=asset_in.name,
            ip_address=str(asset_in.ip_address),
            criticality=asset_in.criticality,
            environment=asset_in.environment,
            asset_type=asset_in.asset_type,
            network_zone=asset_in.network_zone,
            cpe=asset_in.cpe,
            description=asset_in.description
        )
        self.db.add(db_asset)
        self.db.commit()
        self.db.refresh(db_asset)
        return db_asset

    def update(self, asset_id: str, asset_in: AssetUpdate) -> Optional[AssetEntity]:
        db_asset = self.get_by_id(asset_id, lock=True)
        if not db_asset:
            return None
            
        update_data = asset_in.model_dump(exclude_unset=True)
        for field, value in update_data.items():
            if field == 'ip_address' and value is not None:
                setattr(db_asset, field, str(value))
            else:
                setattr(db_asset, field, value)
                
        self.db.commit()
        self.db.refresh(db_asset)
        return db_asset

    def delete(self, asset_id: str) -> bool:
        db_asset = self.get_by_id(asset_id, lock=True)
        if not db_asset:
            return False
            
        db_asset.is_deleted = True
        self.db.commit()
        return True
