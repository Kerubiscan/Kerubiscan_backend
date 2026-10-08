"""Assets and findings covered by a scan (shared by the API reports and the workers)."""
import ipaddress
from typing import List

from sqlalchemy.orm import Session

from src.assets.domain.entities import AssetEntity
from src.scans.domain.entities import ScanEntity
from src.scans.domain.targets import InvalidTargetError, parse_target, split_targets


def scan_assets(db: Session, scan: ScanEntity) -> List[AssetEntity]:
    """Assets covered by a scan: same company, not deleted, matching each target.

    A domain target matches the asset that holds the domain (or, for assets created before the
    domain fix, the asset named after it); a network target matches the assets inside it.
    """
    base = db.query(AssetEntity).filter(AssetEntity.company_id == scan.company_id, AssetEntity.is_deleted == False)  # noqa: E712
    found = {}
    for raw in split_targets(scan.target):
        try:
            target = parse_target(raw)
        except InvalidTargetError:
            continue
        if target.kind == "cidr":
            network = ipaddress.ip_network(target.host, strict=False)
            for asset in base.all():
                for value in (asset.ip_address, asset.resolved_ip):
                    try:
                        if value and ipaddress.ip_address(value) in network:
                            found[asset.id] = asset
                            break
                    except ValueError:
                        pass
        else:
            for asset in base.filter((AssetEntity.ip_address == target.host) | (AssetEntity.name == target.host)).all():
                found[asset.id] = asset
    return list(found.values())


def count_scan_findings(db: Session, scan: ScanEntity) -> int:
    """Findings of the scan's engine on the scan's assets.

    Recomputed after each stored result: adding up per target counted the same findings twice
    when a target was retried.
    """
    from src.vulnerabilities.domain.entities import VulnerabilityEntity
    asset_ids = [a.id for a in scan_assets(db, scan)]
    if not asset_ids:
        return 0
    engine = scan.scanner_engine.value if scan.scanner_engine else None
    q = db.query(VulnerabilityEntity).filter(VulnerabilityEntity.asset_id.in_(asset_ids))
    if engine:
        q = q.filter(VulnerabilityEntity.source_engine == engine)
    return q.count()
