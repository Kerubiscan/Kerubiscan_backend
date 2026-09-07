from sqlalchemy.orm import Session
from sqlalchemy import select, func
from typing import List, Tuple, Optional
from src.vulnerabilities.domain.entities import VulnerabilityEntity, VulnerabilityHistoryEntity
from src.vulnerabilities.domain.models import VulnerabilityResponse
from src.assets.domain.entities import AssetEntity


class VulnerabilityRepository:
    def __init__(self, db: Session):
        self.db = db

    def get_all(self, skip: int = 0, limit: int = 100, company_id: Optional[str] = None, network_zone: Optional[str] = None, asset_id: Optional[str] = None):
        query = self.db.query(VulnerabilityEntity, AssetEntity)\
            .outerjoin(AssetEntity, VulnerabilityEntity.asset_id == AssetEntity.id)


        if asset_id is not None:
            query = query.filter(VulnerabilityEntity.asset_id == asset_id)
        if company_id is not None:
            query = query.filter(AssetEntity.company_id == company_id)
        if network_zone is not None:
            query = query.filter(AssetEntity.network_zone == network_zone)

        total = query.count()
        rows = query.offset(skip).limit(limit).all()

        results = []
        for vuln, asset in rows:
            resp = VulnerabilityResponse(
                id=vuln.id,
                asset_id=vuln.asset_id,
                cve_id=vuln.cve_id,
                title=vuln.title,
                description=vuln.description,
                remediation=vuln.remediation,
                cvss_base_score=vuln.cvss_base_score,
                cvss_vector=vuln.cvss_vector,
                contextual_risk_score=vuln.contextual_risk_score,
                source_engine=vuln.source_engine,
                severity=vuln.severity,
                status=vuln.status,
                first_detected_at=vuln.first_detected_at,
                last_seen_at=vuln.last_seen_at,
                ip_address=asset.ip_address if asset else None,
                asset_name=asset.name if asset else None,
                company_id=asset.company_id if asset else None,
                network_zone=asset.network_zone if asset else None,
                last_scan_raw_output=asset.last_scan_raw_output if asset else None,
            )
            results.append(resp)
        return results, total

    def update_status(self, vuln_id: str, status: str, changed_by: str) -> Optional[VulnerabilityEntity]:
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

    def get_history(self, vuln_id: str) -> List[VulnerabilityHistoryEntity]:
        return self.db.query(VulnerabilityHistoryEntity)\
            .filter(VulnerabilityHistoryEntity.vulnerability_id == vuln_id)\
            .order_by(VulnerabilityHistoryEntity.changed_at.desc())\
            .all()

    def get_by_id(self, vuln_id: str) -> Optional[VulnerabilityEntity]:
        return self.db.query(VulnerabilityEntity).filter(VulnerabilityEntity.id == vuln_id).first()

