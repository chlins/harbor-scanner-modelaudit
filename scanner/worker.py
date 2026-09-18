"""Background worker: fetches the model, runs ModelAudit and stores the reports."""

from __future__ import annotations

import logging
import shutil
import tempfile
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from scanner.api.models import (
    MIME_MODEL_SECURITY_RAW,
    MIME_MODEL_SECURITY_REPORT,
    MIME_SBOM_REPORT,
    SCAN_TYPE_MODEL_SECURITY,
    SCAN_TYPE_SBOM,
    ScanRequest,
)
from scanner.config import Settings
from scanner.modelaudit_runner import runner
from scanner.registry.client import RegistryClient, RegistryError
from scanner.store import STATUS_FAILED, STATUS_PENDING, JobStore

log = logging.getLogger(__name__)


class Worker:
    def __init__(self, store: JobStore, settings: Settings):
        self.store = store
        self.settings = settings
        self._pool = ThreadPoolExecutor(max_workers=max(1, settings.job_queue_workers), thread_name_prefix="scan")
        self._inflight: set[str] = set()
        self._lock = threading.Lock()

    def submit(self, job_id: str, request: ScanRequest) -> None:
        with self._lock:
            self._inflight.add(job_id)
        self._pool.submit(self._run_safe, job_id, request)

    def shutdown(self) -> None:
        self._pool.shutdown(wait=False, cancel_futures=True)

    @property
    def inflight(self) -> int:
        with self._lock:
            return len(self._inflight)

    # -- internals ------------------------------------------------------------------------

    def _run_safe(self, job_id: str, request: ScanRequest) -> None:
        try:
            self.run(job_id, request)
        except Exception as e:  # never let a worker thread die silently
            log.exception("scan %s failed", job_id)
            self.store.set_status(job_id, STATUS_FAILED, str(e))
        finally:
            with self._lock:
                self._inflight.discard(job_id)

    def run(self, job_id: str, request: ScanRequest) -> None:
        s = self.settings
        self.store.set_status(job_id, STATUS_PENDING)
        Path(s.scratch_dir).mkdir(parents=True, exist_ok=True)
        workdir = Path(tempfile.mkdtemp(prefix=f"{job_id}-", dir=s.scratch_dir))
        try:
            log.info(
                "scan %s: fetching %s@%s from %s",
                job_id,
                request.artifact.repository,
                request.artifact.digest,
                request.registry.url,
            )
            try:
                with RegistryClient(request.registry, timeout=s.registry_timeout) as client:
                    model = client.fetch_model(
                        request.artifact.repository,
                        request.artifact.digest,
                        workdir / "model",
                        max_size=s.modelaudit_max_size,
                    )
            except RegistryError as e:
                self.store.set_status(job_id, STATUS_FAILED, str(e))
                return

            log.info("scan %s: %d files, %d bytes, running modelaudit", job_id, len(model.files), model.total_size)
            raw = runner.run_modelaudit(model, timeout=s.modelaudit_timeout, max_total_size=s.modelaudit_max_size)

            reports: dict[str, str] = {}
            if request.wants(SCAN_TYPE_MODEL_SECURITY):
                report = runner.convert_report(model, raw, min_severity=s.modelaudit_min_severity)
                reports[MIME_MODEL_SECURITY_REPORT] = report.model_dump_json()
                if s.modelaudit_keep_raw:
                    reports[MIME_MODEL_SECURITY_RAW] = _dumps(raw)
                log.info("scan %s: %d findings, severity %s", job_id, report.summary.total, report.severity)
            if request.wants(SCAN_TYPE_SBOM):
                bom = runner.generate_sbom(model, raw)
                reports[MIME_SBOM_REPORT] = runner.convert_sbom(bom).model_dump_json()
                log.info("scan %s: sbom with %d components", job_id, len(bom.get("components", [])))

            self.store.set_reports(job_id, reports)
        finally:
            shutil.rmtree(workdir, ignore_errors=True)


def _dumps(obj) -> str:
    import json

    return json.dumps(obj, default=str)
