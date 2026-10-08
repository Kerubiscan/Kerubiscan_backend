import os
from celery import Celery
from src.core.config import settings

celery_app = Celery(
    "kimia_worker",
    broker=settings.REDIS_URL,
    backend=settings.REDIS_URL
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone=os.getenv("TZ", "UTC"),
    enable_utc=(os.getenv("TZ", "UTC") == "UTC"),
    task_track_started=True,
    task_time_limit=3600 * 24, # 24 hours max for scans
    task_ignore_result=True, # Prevent Redis memory bloat from useless task returns
    # A scan is acknowledged only once finished, so a worker crash/restart re-queues it.
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    worker_prefetch_multiplier=1,
    # Must exceed the longest task, otherwise Redis re-delivers running scans and they run twice.
    broker_transport_options={"visibility_timeout": 3600 * 26},
    # Long scans get their own queue so that scheduling, OpenVAS polling and parsing are never
    # stuck behind them (a schedule fired late used to be skipped).
    task_routes={
        "run_vulnerability_scan": {"queue": "scans"},
        "run_discovery_scan": {"queue": "scans"},
        # Templates/scripts live in the scanning container's filesystem: update them there
        "update_nuclei_templates": {"queue": "scans"},
        "update_nmap_scripts": {"queue": "scans"},
        "update_zap_addons": {"queue": "scans"},
    },
)

from celery.schedules import crontab

celery_app.conf.beat_schedule = {
    'check-scheduled-scans-every-minute': {
        'task': 'src.scheduling.application.services.tasks.check_scheduled_scans',
        'schedule': crontab(minute='*'),
    },
    'update-nuclei-templates-daily': {
        'task': 'update_nuclei_templates',
        'schedule': crontab(hour=0, minute=0), # Run daily at midnight
    },
    # Closes or resumes scan targets whose follow-up was lost (see watchdog.py)
    'scan-watchdog-every-10-minutes': {
        'task': 'scan_watchdog',
        'schedule': crontab(minute='*/10'),
    },
    # Data retention (replaces the former purge on every API restart)
    'cleanup-old-data-daily': {
        'task': 'cleanup_old_data',
        'schedule': crontab(hour=3, minute=30),
    },
}

celery_app.autodiscover_tasks([
    'src.scans.application.services.tasks',
    'src.vulnerabilities.application.services.tasks',
    'src.scheduling.application.services.tasks',
    'src.scans.application.services.watchdog',
])

# Import for its side effect: connects the worker shutdown handler (kills scanner children)
import src.scans.application.services.worker_signals  # noqa: E402,F401
