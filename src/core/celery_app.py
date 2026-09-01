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
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_time_limit=3600 * 24, # 24 hours max for scans
)

from celery.schedules import crontab

celery_app.conf.beat_schedule = {
    'check-scheduled-scans-every-minute': {
        'task': 'src.scheduling.application.services.tasks.check_scheduled_scans',
        'schedule': crontab(minute='*'),
    },
}

celery_app.autodiscover_tasks([
    'src.scans.application.services.tasks',
    'src.vulnerabilities.application.services.tasks',
    'src.scheduling.application.services.tasks'
])
