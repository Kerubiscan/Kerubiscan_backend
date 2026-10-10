"""Clean shutdown of scan workers.

On `docker compose stop` (SIGTERM), Celery does a warm shutdown: it stops consuming and waits for
running tasks. Scanner children run in their own session, so they would survive as orphans. Here
they are killed, and the target being scanned is marked INTERRUPTED (the task is acked, not rerun;
its results so far are kept). Messages reserved but not started are requeued by Celery itself.

The Stop button revokes the running task with terminate=True: Celery sends SIGTERM to the worker
child running it. By default the child died at once, and the scanner it had started (in its own
session) went on scanning as an orphan: Nuclei kept running after "Stop". The child now turns
SIGTERM into SystemExit, so the task unwinds and the adapters kill their scanner (run_process,
the ZAP adapter's finally) on the way out.
"""
import logging
import signal

from celery.signals import worker_process_init, worker_shutting_down

logger = logging.getLogger(__name__)


@worker_shutting_down.connect
def _on_shutdown(**kwargs):
    from src.scans.adapters.outbound.base_adapter import kill_all_running
    killed = kill_all_running()
    if killed:
        logger.warning(f"Worker shutting down: killed {killed} running scanner process(es)")


def _terminate(signum, frame):
    raise SystemExit(f"Task terminated (signal {signum}): stopping its scanner")


@worker_process_init.connect
def _on_child_start(**kwargs):
    signal.signal(signal.SIGTERM, _terminate)
