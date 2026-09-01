from sqlalchemy.orm import Session
from sqlalchemy import select, func
from typing import List, Tuple, Optional
from src.scheduling.domain.entities import ScheduleEntity

class ScheduleRepository:
    def __init__(self, db: Session):
        self.db = db

    def get_all(self, skip: int = 0, limit: int = 100, company_id: Optional[int] = None) -> Tuple[List[ScheduleEntity], int]:
        query = select(ScheduleEntity)
        if company_id is not None:
            query = query.where(ScheduleEntity.company_id == company_id)
            
        total = self.db.execute(select(func.count()).select_from(query.subquery())).scalar_one()
        query = query.offset(skip).limit(limit)
        results = self.db.execute(query).scalars().all()
        return list(results), total

    def create(self, schedule_in) -> ScheduleEntity:
        entity = ScheduleEntity(**schedule_in.model_dump())
        self.db.add(entity)
        self.db.commit()
        self.db.refresh(entity)
        return entity
