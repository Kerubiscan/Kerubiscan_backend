from sqlalchemy.orm import Session
from sqlalchemy import select, func, desc, asc
from typing import List, Dict, Any, Optional, Tuple
from datetime import date, datetime, time, timedelta, timezone

from src.vulnerabilities.domain.entities import VulnerabilityEntity
from src.vulnerabilities.domain.models import VulnStatus, VulnSeverity
from src.assets.domain.entities import AssetEntity
from src.scans.domain.entities import ScanEntity
from src.scheduling.domain.entities import ScheduleEntity

def _local_tz():
    """The server's time zone (TZ), the one of the reports and the logs."""
    return datetime.now().astimezone().tzinfo


def day_bounds(day: date) -> Tuple[datetime, datetime]:
    """[start, end) of a local calendar day, in UTC (dates are stored in UTC)."""
    start = datetime.combine(day, time.min, tzinfo=_local_tz())
    return start.astimezone(timezone.utc), (start + timedelta(days=1)).astimezone(timezone.utc)


def _as_utc(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


class DashboardRepository:
    def __init__(self, db: Session):
        self.db = db

    def _kpis_of_day(self, day: date) -> Dict[str, int]:
        """Vulnerabilities found on a past day (first detection), as the over-time chart counts them."""
        start, end = day_bounds(day)
        rows = self.db.execute(
            select(VulnerabilityEntity.severity, func.count(VulnerabilityEntity.id))
            .where(VulnerabilityEntity.first_detected_at >= start, VulnerabilityEntity.first_detected_at < end)
            .group_by(VulnerabilityEntity.severity)).all()
        kpis = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for severity, count in rows:
            kpis[severity.value.lower()] = count
        return kpis

    def get_kpis(self, day: Optional[date] = None) -> Dict[str, int]:
        if day is not None:
            return self._kpis_of_day(day)
        # User requested: Dashboard should reflect the latest scan regardless of status
        # And if the latest scan is deleted, the dashboard should show zero
        _, latest_scan = self._latest_scan()
        if not latest_scan or latest_scan.is_deleted:
            return {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

        max_seen = self.db.query(func.max(VulnerabilityEntity.last_seen_at)).scalar()
        
        query = select(VulnerabilityEntity.severity, func.count(VulnerabilityEntity.id))
        
        if max_seen:
            threshold = max_seen - timedelta(minutes=30)
            query = query.where(VulnerabilityEntity.last_seen_at >= threshold)
            
        query = query.group_by(VulnerabilityEntity.severity)
            
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

    def get_distribution_chart(self, day: Optional[date] = None) -> List[Dict[str, Any]]:
        kpis = self.get_kpis(day)
        return [
            {"name": "Critical", "value": kpis["critical"], "color": "var(--status-critical)"},
            {"name": "High", "value": kpis["high"], "color": "var(--status-high)"},
            {"name": "Medium", "value": kpis["medium"], "color": "var(--status-medium)"},
            {"name": "Low", "value": kpis["low"], "color": "var(--status-low)"},
            {"name": "Info", "value": kpis["info"], "color": "var(--status-info)"},
        ]

    def get_over_time_chart(self, days: int = 14) -> List[Dict[str, Any]]:
        """Vulnerabilities found per local day (first detection) over the last `days` days. Each point
        carries its date ("date": YYYY-MM-DD): clicking it shows the dashboard of that day."""
        tz = _local_tz()
        today = datetime.now(tz).date()
        first = today - timedelta(days=days - 1)
        start, _ = day_bounds(first)
        series = {}
        for d in range(days):
            day = first + timedelta(days=d)
            series[day] = {"name": day.strftime("%d %b"), "date": day.isoformat(),
                           "Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
        rows = self.db.execute(select(VulnerabilityEntity.first_detected_at, VulnerabilityEntity.severity)
                               .where(VulnerabilityEntity.first_detected_at >= start)).all()
        for detected_at, severity in rows:
            day = _as_utc(detected_at).astimezone(tz).date()
            if day in series:
                series[day][severity.value] += 1
        return list(series.values())

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

    def _latest_scan(self):
        """(time of its latest run, scan) for the scan that ran last. A rerun keeps its row and
        created_at, so ordering by creation showed an older scan, at its first run's time."""
        from src.scans.application.services.progress import last_run_at
        recent = self.db.query(ScanEntity).order_by(desc(ScanEntity.updated_at)).limit(20).all()
        dated = [(t, s) for t, s in ((last_run_at(s), s) for s in recent) if t]
        return max(dated, key=lambda d: d[0]) if dated else (None, None)

    def get_latest_scan(self) -> Dict[str, Any]:
        ran_at, scan = self._latest_scan()
        if not scan:
            return None

        return {
            "id": scan.id,
            "name": scan.name,
            "target": scan.target,
            "zone": scan.network_zone,
            # Stored in UTC: shown in the server's time zone, like the reports and the logs
            "date": ran_at.astimezone().strftime("%d %b %Y, %H:%M"),
            "status": scan.status.value,
            "vulnerabilities": scan.vulnerabilities_found or 0
        }

    def get_scans_of_day(self, day: date) -> List[Dict[str, Any]]:
        """Scans that ran on a local day (their latest run started or ended that day), most recent
        first, with their network zone so the dashboard can group them by zone."""
        from src.scans.application.services.progress import run_window
        start, end = day_bounds(day)
        candidates = self.db.query(ScanEntity).filter(
            ScanEntity.is_deleted == False,  # noqa: E712
            ScanEntity.updated_at >= start - timedelta(days=1)).all()
        out = []
        for scan in candidates:
            began, finished = run_window(scan)
            moments = [m for m in (began, finished) if m]
            if not any(start <= m < end for m in moments):
                continue
            out.append({
                "id": scan.id,
                "name": scan.name,
                "target": scan.target,
                "zone": scan.network_zone,
                "engine": scan.scanner_engine.value if scan.scanner_engine else None,
                "status": scan.status.value,
                "time": (began or finished).astimezone().strftime("%H:%M"),
                "vulnerabilities": scan.vulnerabilities_found or 0,
                "_at": began or finished,
            })
        out.sort(key=lambda r: r["_at"], reverse=True)
        for row in out:
            del row["_at"]
        return out

    def get_recent_vulnerabilities(self, day: Optional[date] = None) -> List[Dict[str, Any]]:
        query = self.db.query(VulnerabilityEntity, AssetEntity)\
            .join(AssetEntity, VulnerabilityEntity.asset_id == AssetEntity.id)
        if day is not None:
            start, end = day_bounds(day)
            query = query.filter(VulnerabilityEntity.first_detected_at >= start,
                                 VulnerabilityEntity.first_detected_at < end)\
                .order_by(desc(VulnerabilityEntity.cvss_base_score), desc(VulnerabilityEntity.first_detected_at))
        else:
            query = query.order_by(desc(VulnerabilityEntity.first_detected_at))
        query = query.limit(5)
            
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
                "service": vuln.service if vuln.service else "Unknown",
                "port": str(vuln.port) if vuln.port else "-",
                "date": _as_utc(vuln.first_detected_at).astimezone().strftime("%d %b %Y, %H:%M"),
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
