from sqlalchemy.orm import Session
from sqlalchemy import select, func
from typing import List, Tuple, Optional
from src.vulnerabilities.domain.entities import VulnerabilityEntity, VulnerabilityHistoryEntity
from src.assets.domain.entities import AssetEntity

class VulnerabilityRepository:
    def __init__(self, db: Session):
        self.db = db

    def get_all(self, skip: int = 0, limit: int = 100, company_id: Optional[int] = None, network_zone: Optional[str] = None, asset_id: Optional[int] = None) -> Tuple[List[VulnerabilityEntity], int]:
        query = select(VulnerabilityEntity)
        
        if asset_id is not None:
            query = query.where(VulnerabilityEntity.asset_id == asset_id)

        if company_id is not None or network_zone is not None:
            query = query.join(AssetEntity, VulnerabilityEntity.asset_id == AssetEntity.id)
            
            if company_id is not None:
                query = query.where(AssetEntity.company_id == company_id)
            if network_zone:
                query = query.where(AssetEntity.network_zone == network_zone)

        total = self.db.execute(select(func.count()).select_from(query.subquery())).scalar_one()
        
        query = query.offset(skip).limit(limit)
        results = self.db.execute(query).scalars().all()
        return list(results), total

    def update_status(self, vuln_id: int, status: str, changed_by: str) -> Optional[VulnerabilityEntity]:
        vuln = self.db.query(VulnerabilityEntity).filter(VulnerabilityEntity.id == vuln_id).first()
        if vuln:
            previous_status = vuln.status
            if previous_status != status:
                vuln.status = status
                
                # Add history record
                history_record = VulnerabilityHistoryEntity(
                    vulnerability_id=vuln.id,
                    previous_status=previous_status,
                    new_status=status,
                    changed_by=changed_by
                )
                self.db.add(history_record)
                
                self.db.commit()
                self.db.refresh(vuln)
        return vuln

    def get_history(self, vuln_id: int) -> List[VulnerabilityHistoryEntity]:
        return self.db.query(VulnerabilityHistoryEntity)\
            .filter(VulnerabilityHistoryEntity.vulnerability_id == vuln_id)\
            .order_by(VulnerabilityHistoryEntity.changed_at.desc())\
            .all()
