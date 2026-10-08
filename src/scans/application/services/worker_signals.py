"""Clean shutdown of scan workers.

On `docker compose stop` (SIGTERM), Celery does a warm shutdown: it stops consuming and waits for
running tasks. Scanner children run in their own session, so they would survive as orphans. Here
they are killed, and the target being scanned is marked INTERRUPTED (the task is acked, not rerun;
its results so far are kept). Messages reserved but not started are requeued by Celery itself.
"""
import logging

from celery.signals import worker_shutting_down

logger = logging.getLogger(__name__)


@worker_shutting_down.connect
def _on_shutdown(**kwargs):
    from src.scans.adapters.outbound.base_adapter import kill_all_running
    killed = kill_all_running()
    if killed:
        logger.warning(f"Worker shutting down: killed {killed} running scanner process(es)")
