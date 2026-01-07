"""Local async fallback for report generation.

Used when Celery broker/worker is unavailable (common in dev on Windows).
Stores task status/results in Django cache and runs work in a small thread pool.
"""

from __future__ import annotations

import logging
import uuid
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Dict, Optional

from django.core.cache import cache

logger = logging.getLogger(__name__)

_TASK_KEY_PREFIX = "reports:local_task:"
_TASK_TTL_SECONDS = 60 * 60  # 1 hour

_executor = ThreadPoolExecutor(max_workers=2)


def _task_key(task_id: str) -> str:
    return f"{_TASK_KEY_PREFIX}{task_id}"


def _set(task_id: str, payload: Dict[str, Any]) -> None:
    cache.set(_task_key(task_id), payload, timeout=_TASK_TTL_SECONDS)


def get_local_task_status(task_id: str) -> Optional[Dict[str, Any]]:
    """Return cached status for a local fallback task, or None if unknown."""
    if not task_id.startswith("local:"):
        return None
    return cache.get(_task_key(task_id))


def enqueue_local_report_generation(
    *,
    scan_id: str,
    report_type: str,
    company_name: str,
    requested_by_id: Optional[str] = None,
) -> str:
    """Queue report generation in-process and return a task_id compatible with the API."""
    task_id = f"local:{uuid.uuid4()}"

    _set(
        task_id,
        {
            "task_id": task_id,
            "status": "pending",
            "message": "Report generation is queued (local)",
        },
    )

    def _run() -> None:
        from .services import get_report_service

        _set(
            task_id,
            {
                "task_id": task_id,
                "status": "processing",
                "message": "Report is being generated (local)",
            },
        )

        try:
            service = get_report_service()
            result = service.generate_report(scan_id=scan_id, report_type=report_type, company_name=company_name)

            # Best-effort audit log
            try:
                from .tasks import _create_audit_log

                _create_audit_log(scan_id, result, requested_by_id)
            except Exception:
                logger.warning(
                    "Local report audit log failed (best-effort)",
                    extra={"task_id": task_id, "scan_id": scan_id},
                    exc_info=True,
                )

                try:
                    from observability.metrics import security_metrics

                    security_metrics.record_internal_error(component="reports", operation="audit_log")
                except Exception:
                    logger.debug("Failed to record audit log metric", exc_info=True)

            _set(
                task_id,
                {
                    "task_id": task_id,
                    "status": "completed",
                    "report": result.to_dict(),
                },
            )
        except Exception as e:
            logger.error("Local report generation failed", exc_info=True)
            _set(
                task_id,
                {
                    "task_id": task_id,
                    "status": "failed",
                    "error": str(e),
                },
            )

    _executor.submit(_run)
    return task_id
