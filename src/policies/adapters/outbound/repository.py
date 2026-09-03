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
