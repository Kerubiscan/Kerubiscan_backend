from sqlalchemy.orm import Session
from sqlalchemy import select, func, desc, asc
from typing import List, Dict, Any
from datetime import datetime, timedelta

from src.vulnerabilities.domain.entities import VulnerabilityEntity
from src.vulnerabilities.domain.models import VulnStatus, VulnSeverity
from src.assets.domain.entities import AssetEntity
from src.scans.domain.entities import ScanEntity
from src.scheduling.domain.entities import ScheduleEntity

class DashboardRepository:
    def __init__(self, db: Session):
        self.db = db

    def get_kpis(self) -> Dict[str, int]:
        # Count vulnerabilities by severity that are NOT fixed or false positives
        query = select(VulnerabilityEntity.severity, func.count(VulnerabilityEntity.id))\
            .where(VulnerabilityEntity.status.not_in([VulnStatus.FIXED, VulnStatus.FALSE_POSITIVE]))\
            .group_by(VulnerabilityEntity.severity)
            
        results = self.db.execute(query).all()
        
        kpis = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0
        }
        
        for severity, count in results:
            kpis[severity.value.lower()] = count
            
        return kpis

    def get_distribution_chart(self) -> List[Dict[str, Any]]:
        kpis = self.get_kpis()
        return [
            {"name": "Critical", "value": kpis["critical"], "color": "var(--status-critical)"},
            {"name": "High", "value": kpis["high"], "color": "var(--status-high)"},
            {"name": "Medium", "value": kpis["medium"], "color": "var(--status-medium)"},
            {"name": "Low", "value": kpis["low"], "color": "var(--status-low)"},
            {"name": "Info", "value": kpis["info"], "color": "var(--status-info)"},
        ]

    def get_over_time_chart(self) -> List[Dict[str, Any]]:
        # In a real app, we'd query historical snapshots or aggregate VulnerabilityHistoryEntity.
        # For simplicity, we'll group by the date part of first_detected_at for the last 7 days.
        seven_days_ago = datetime.utcnow() - timedelta(days=7)
        
        # We need a raw query to extract date in sqlite/postgres compatible way, 
        # but func.date is usually supported in Postgres and SQLite
        query = select(
            func.date(VulnerabilityEntity.first_detected_at).label("date"),
            VulnerabilityEntity.severity,
            func.count(VulnerabilityEntity.id).label("count")
        ).where(VulnerabilityEntity.first_detected_at >= seven_days_ago)\
         .group_by(func.date(VulnerabilityEntity.first_detected_at), VulnerabilityEntity.severity)\
         .order_by("date")

        results = self.db.execute(query).all()

        # Build time series dictionary
        time_series = {}
        for d in range(7):
            dt = (seven_days_ago + timedelta(days=d)).date().isoformat()
            # We map to the french keys because the frontend expects it or we can change frontend to english
            # Let's change frontend to english later, and output english here.
            time_series[dt] = {
                "name": (seven_days_ago + timedelta(days=d)).strftime("%d %b"),
                "Critical": 0,
                "High": 0,
                "Medium": 0,
                "Low": 0,
                "Info": 0
            }

        for row in results:
            date_str = str(row.date)
            if date_str in time_series:
                sev = row.severity.value
                time_series[date_str][sev] = row.count
                
        return list(time_series.values())

    def get_assets_by_os(self) -> List[Dict[str, Any]]:
        query = select(AssetEntity.operating_system, func.count(AssetEntity.id))\
            .group_by(AssetEntity.operating_system)
            
        results = self.db.execute(query).all()
        
        # Calculate total
        total = sum([count for _, count in results])
        if total == 0:
            return []
            
        colors = ["var(--status-info)", "var(--status-low)", "var(--status-high)", "var(--status-critical)", "#8b5cf6"]
        
        out = []
        for i, (os, count) in enumerate(results):
            os_name = os if os else "Unknown"
            percentage = f"{int((count / total) * 100)}%"
            out.append({
                "name": os_name,
                "count": count,
                "percentage": percentage,
                "color": colors[i % len(colors)]
            })
            
        return out

    def get_latest_scan(self) -> Dict[str, Any]:
        scan = self.db.query(ScanEntity).order_by(desc(ScanEntity.created_at)).first()
        if not scan:
            return None
            
        return {
            "name": scan.name,
            "target": scan.target,
            "date": scan.created_at.strftime("%d %b %Y, %H:%M"),
            "status": scan.status.value,
            "vulnerabilities": scan.vulnerabilities_found or 0
        }

    def get_recent_vulnerabilities(self) -> List[Dict[str, Any]]:
        query = self.db.query(VulnerabilityEntity, AssetEntity)\
            .join(AssetEntity, VulnerabilityEntity.asset_id == AssetEntity.id)\
            .order_by(desc(VulnerabilityEntity.first_detected_at))\
            .limit(5)
            
        results = query.all()
        
        out = []
        for vuln, asset in results:
            badge_class = "bg-status-info/10 text-status-info border border-status-info/20"
            if vuln.severity == VulnSeverity.CRITICAL:
                badge_class = "bg-status-critical/10 text-status-critical border border-status-critical/20"
            elif vuln.severity == VulnSeverity.HIGH:
                badge_class = "bg-status-high/10 text-status-high border border-status-high/20"
            elif vuln.severity == VulnSeverity.MEDIUM:
                badge_class = "bg-status-medium/10 text-status-medium border border-status-medium/20"
            elif vuln.severity == VulnSeverity.LOW:
                badge_class = "bg-status-low/10 text-status-low border border-status-low/20"

            out.append({
                "severity": vuln.severity.value,
                "name": vuln.title,
                "target": asset.ip_address,
                "service": "Unknown", # We'll just leave it as Unknown since we don't track port level in current entity
                "port": "-",
                "date": vuln.first_detected_at.strftime("%d %b %Y, %H:%M"),
                "badgeClass": badge_class
            })
            
        return out

    def get_scheduled_scans(self) -> List[Dict[str, Any]]:
        scans = self.db.query(ScheduleEntity).order_by(asc(ScheduleEntity.created_at)).limit(3).all()
        return [
            {
                "name": s.name,
                "time": s.frequency
            } for s in scans
        ]
