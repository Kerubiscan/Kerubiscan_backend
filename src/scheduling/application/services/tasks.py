from src.core.celery_app import celery_app
import logging
from datetime import datetime
from sqlalchemy.orm import Session
from src.core.database import SessionLocal
from src.scheduling.domain.entities import ScheduleEntity
from src.scans.domain.entities import ScanEntity, ScanType, ScanStatus, ScannerEngine
from src.scans.application.services.tasks import run_discovery_scan, run_vulnerability_scan
from src.notifications.application.services.smtp import send_alert_email

logger = logging.getLogger(__name__)

@celery_app.task
def check_scheduled_scans():
    logger.info("Checking scheduled scans...")
    db: Session = SessionLocal()
    try:
        now = datetime.now() # Container local time (typically UTC)
        current_day_str = now.strftime("%A") + "s" # e.g., "Mondays"
        current_day_num = str(now.day)
        current_time_str = now.strftime("%H:%M")

        schedules = db.query(ScheduleEntity).filter(ScheduleEntity.status == "Active").all()
        for sched in schedules:
            try:
                freq = sched.frequency
                should_run = False
                
                # freq format: "Daily at HH:MM" or "Mondays at HH:MM" or "1 of Month at HH:MM"
                if "at " in freq:
                    parts = freq.split("at ")
                    day_part = parts[0].strip()
                    time_part = parts[1].strip()
                    
                    if time_part == current_time_str:
                        if day_part == "Daily":
                            should_run = True
                        elif day_part == current_day_str:
                            should_run = True
                        elif "of Month" in day_part and day_part.split(" ")[0] == current_day_num:
                            should_run = True

                if should_run:
                    logger.info(f"Triggering scheduled scan: {sched.name}")
                    
                    # 1. Create Scan Entity
                    s_type = ScanType.DISCOVERY if sched.scan_type.upper() == "DISCOVERY" else ScanType.VULNERABILITY
                    
                    # Map scanner engine safely
                    engine_str = sched.scanner_engine.upper() if sched.scanner_engine else "OPENVAS"
                    if engine_str in ScannerEngine.__members__:
                        s_engine = ScannerEngine[engine_str]
                    else:
                        s_engine = ScannerEngine.OPENVAS

                    scan = ScanEntity(
                        company_id=sched.company_id,
                        name=f"Scheduled: {sched.name}",
                        target=sched.target,
                        network_zone=sched.network_zone,
                        scan_type=s_type,
                        scanner_engine=s_engine,
                        status=ScanStatus.IN_PROGRESS,
                        recurrence_rule=sched.frequency
                    )
                    db.add(scan)
                    db.commit()
                    db.refresh(scan)
                    
                    # 2. Email on Start
                    admin_email = "admin@kerubiscan.local"
                    try:
                        send_alert_email(
                            to_email=admin_email,
                            subject=f"Scheduled Scan Started: {sched.name}",
                            content=f"The scheduled scan '{sched.name}' targeting {sched.target} has automatically started."
                        )
                    except Exception as e:
                        logger.error(f"Failed to send start email: {e}")

                    # 3. Enqueue
                    if s_type == ScanType.DISCOVERY:
                        run_discovery_scan.delay(scan.id, sched.target, sched.network_zone or "Internal", sched.company_id)
                    else:
                        config_id = "daba56c8-73ec-11df-a475-002264764cea"
                        run_vulnerability_scan.delay(scan.id, sched.target, sched.target, config_id)

                    # Update next run display string
                    if sched.frequency.startswith("Daily"):
                        sched.next_run = f"Tomorrow, {time_part}"
                    elif "of Month" in sched.frequency:
                        sched.next_run = f"{day_part.split(' ')[0]}th of next month, {time_part}"
                    else:
                        sched.next_run = f"Next {day_part.replace('s', '')}, {time_part}"
                        
                    db.commit()
            except Exception as e:
                logger.error(f"Failed to process schedule {sched.id}: {e}")
                
    except Exception as e:
        logger.error(f"Error checking scheduled scans: {e}")
    finally:
        db.close()
