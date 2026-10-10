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


_BADGES = {
    VulnSeverity.CRITICAL: "bg-status-critical/10 text-status-critical border border-status-critical/20",
    VulnSeverity.HIGH: "bg-status-high/10 text-status-high border border-status-high/20",
    VulnSeverity.MEDIUM: "bg-status-medium/10 text-status-medium border border-status-medium/20",
    VulnSeverity.LOW: "bg-status-low/10 text-status-low border border-status-low/20",
}


def _vuln_row(vuln: VulnerabilityEntity, asset: AssetEntity) -> Dict[str, Any]:
    return {
        "severity": vuln.severity.value,
        "name": vuln.title,
        "target": asset.ip_address,
        "service": vuln.service if vuln.service else "Unknown",
        "port": str(vuln.port) if vuln.port else "-",
        "date": _as_utc(vuln.first_detected_at).astimezone().strftime("%d %b %Y, %H:%M"),
        "badgeClass": _BADGES.get(vuln.severity, "bg-status-info/10 text-status-info border border-status-info/20"),
    }


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

    def _scan_findings(self, scan_id: str) -> List[Tuple[VulnerabilityEntity, AssetEntity]]:
        """Findings of one scan: its engine's findings on the assets it covers (as in its report)."""
        from src.scans.application.services.scan_assets import scan_assets
        scan = self.db.query(ScanEntity).filter(ScanEntity.id == scan_id, ScanEntity.is_deleted == False).first()  # noqa: E712
        if not scan:
            return []
        engine = scan.scanner_engine.value if scan.scanner_engine else None
        pairs = []
        for asset in scan_assets(self.db, scan):
            query = self.db.query(VulnerabilityEntity).filter(VulnerabilityEntity.asset_id == asset.id)
            if engine:
                query = query.filter(VulnerabilityEntity.source_engine == engine)
            seen = set()
            for vuln in query.all():
                if (vuln.title, vuln.port) not in seen:
                    seen.add((vuln.title, vuln.port))
                    pairs.append((vuln, asset))
        return pairs

    def get_kpis(self, day: Optional[date] = None, scan_id: Optional[str] = None) -> Dict[str, int]:
        if scan_id:
            kpis = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
            for vuln, _ in self._scan_findings(scan_id):
                kpis[vuln.severity.value.lower()] += 1
            return kpis
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

    def get_distribution_chart(self, day: Optional[date] = None, scan_id: Optional[str] = None) -> List[Dict[str, Any]]:
        kpis = self.get_kpis(day, scan_id)
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

    def get_recent_vulnerabilities(self, day: Optional[date] = None, scan_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Latest findings; of a past day (most severe first); or of one scan (its 10 most severe)."""
        if scan_id:
            rank = {VulnSeverity.CRITICAL: 0, VulnSeverity.HIGH: 1, VulnSeverity.MEDIUM: 2,
                    VulnSeverity.LOW: 3, VulnSeverity.INFO: 4}
            pairs = sorted(self._scan_findings(scan_id),
                           key=lambda p: (rank.get(p[0].severity, 5), -(p[0].cvss_base_score or 0), p[0].title))
            return [_vuln_row(v, a) for v, a in pairs[:10]]
        query = self.db.query(VulnerabilityEntity, AssetEntity)\
            .join(AssetEntity, VulnerabilityEntity.asset_id == AssetEntity.id)
        if day is not None:
            start, end = day_bounds(day)
            query = query.filter(VulnerabilityEntity.first_detected_at >= start,
                                 VulnerabilityEntity.first_detected_at < end)\
                .order_by(desc(VulnerabilityEntity.cvss_base_score), desc(VulnerabilityEntity.first_detected_at))
        else:
            query = query.order_by(desc(VulnerabilityEntity.first_detected_at))
        return [_vuln_row(v, a) for v, a in query.limit(5).all()]

    def get_scheduled_scans(self) -> List[Dict[str, Any]]:
        scans = self.db.query(ScheduleEntity).order_by(asc(ScheduleEntity.created_at)).limit(3).all()
        return [
            {
                "name": s.name,
                "time": s.frequency
            } for s in scans
        ]
