from sqlalchemy.orm import Session
from sqlalchemy import select, func
from typing import List, Tuple, Optional
from src.policies.domain.entities import PolicyEntity

class PolicyRepository:
    def __init__(self, db: Session):
        self.db = db

    def get_all(self, skip: int = 0, limit: int = 100, company_id: Optional[str] = None) -> Tuple[List[PolicyEntity], int]:
        query = select(PolicyEntity)
        if company_id is not None:
            query = query.where(PolicyEntity.company_id == company_id)
            
        total = self.db.execute(select(func.count()).select_from(query.subquery())).scalar_one()
        query = query.offset(skip).limit(limit)
        results = self.db.execute(query).scalars().all()
        return list(results), total

    def create(self, policy_in) -> PolicyEntity:
        entity = PolicyEntity(**policy_in.model_dump())
        self.db.add(entity)
        self.db.commit()
        self.db.refresh(entity)
        return entity

    def get_by_id(self, policy_id: int) -> Optional[PolicyEntity]:
        return self.db.execute(select(PolicyEntity).where(PolicyEntity.id == policy_id)).scalar_one_or_none()

    def update(self, policy_id: int, policy_in) -> Optional[PolicyEntity]:
        entity = self.get_by_id(policy_id)
        if not entity:
            return None
        update_data = policy_in.model_dump(exclude_unset=True)
        for key, value in update_data.items():
            setattr(entity, key, value)
        self.db.commit()
        self.db.refresh(entity)
        return entity

    def delete(self, policy_id: int) -> bool:
        entity = self.get_by_id(policy_id)
        if not entity:
            return False
        self.db.delete(entity)
        self.db.commit()
        return True
