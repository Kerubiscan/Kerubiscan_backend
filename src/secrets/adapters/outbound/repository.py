from sqlalchemy.orm import Session
from sqlalchemy import select
from typing import List, Optional
from src.secrets.ports.outbound.repository import CredentialRepositoryPort
from src.secrets.domain.entities import CredentialEntity
from src.secrets.domain.models import CredentialType

class CredentialRepository(CredentialRepositoryPort):
    def __init__(self, db: Session):
        self.db = db

    def get_by_id(self, credential_id: int) -> Optional[CredentialEntity]:
        query = select(CredentialEntity).where(CredentialEntity.id == credential_id)
        return self.db.execute(query).scalar_one_or_none()

    def get_all(self, skip: int = 0, limit: int = 100) -> tuple[List[CredentialEntity], int]:
        from sqlalchemy import func
        total = self.db.execute(select(func.count()).select_from(CredentialEntity)).scalar_one()
        query = select(CredentialEntity).offset(skip).limit(limit)
        results = self.db.execute(query).scalars().all()
        return list(results), total
        
    def get_by_asset(self, asset_id: int) -> List[CredentialEntity]:
        query = select(CredentialEntity).where(CredentialEntity.asset_id == asset_id)
        return list(self.db.execute(query).scalars().all())

    def create(self, name: str, asset_id: int, credential_type: CredentialType, vault_path: str) -> CredentialEntity:
        db_credential = CredentialEntity(
            name=name,
            asset_id=asset_id,
            credential_type=credential_type.value,
            vault_path=vault_path
        )
        self.db.add(db_credential)
        self.db.commit()
        self.db.refresh(db_credential)
        return db_credential

    def delete(self, credential_id: int) -> bool:
        db_credential = self.get_by_id(credential_id)
        if not db_credential:
            return False
            
        self.db.delete(db_credential)
        self.db.commit()
        return True
