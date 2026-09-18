"""HTTP API implementing the Harbor pluggable scanner adapter spec v1."""

from __future__ import annotations

import logging
import uuid
from contextlib import asynccontextmanager

from fastapi import APIRouter, FastAPI, Request, Response
from fastapi.responses import JSONResponse

from scanner.api.models import (
    MIME_ADAPTER_METADATA,
    MIME_ERROR,
    MIME_MODEL_MANIFEST,
    MIME_MODEL_SECURITY_RAW,
    MIME_MODEL_SECURITY_REPORT,
    MIME_SBOM_REPORT,
    MIME_SCAN_RESPONSE,
    SCAN_TYPE_MODEL_SECURITY,
    SCAN_TYPE_SBOM,
    Capability,
    Metadata,
    ScanRequest,
)
from scanner.config import Settings
from scanner.modelaudit_runner.runner import adapter_scanner_info
from scanner.store import STATUS_FAILED, STATUS_FINISHED, Job, JobStore
from scanner.worker import Worker

log = logging.getLogger(__name__)

REFRESH_AFTER_HEADER = "Refresh-After"


def error(status: int, message: str) -> JSONResponse:
    return JSONResponse(status_code=status, content={"error": {"message": message}}, media_type=MIME_ERROR)


def metadata() -> Metadata:
    return Metadata(
        scanner=adapter_scanner_info(),
        capabilities=[
            Capability(
                type=SCAN_TYPE_MODEL_SECURITY,
                consumes_mime_types=[MIME_MODEL_MANIFEST],
                produces_mime_types=[MIME_MODEL_SECURITY_REPORT, MIME_MODEL_SECURITY_RAW],
            ),
            Capability(
                type=SCAN_TYPE_SBOM,
                consumes_mime_types=[MIME_MODEL_MANIFEST],
                produces_mime_types=[MIME_SBOM_REPORT],
            ),
        ],
        properties={
            "harbor.scanner-adapter/scanner-type": "model",
            "harbor.scanner-adapter/registry-authorization-type": "Bearer",
            "harbor.scanner-adapter/vulnerability-database-updated-at": "",
        },
    )


def _accepted_mime(request: Request) -> str:
    accept = request.headers.get("accept", "")
    for part in accept.split(","):
        p = part.strip()
        if p in (MIME_MODEL_SECURITY_REPORT, MIME_MODEL_SECURITY_RAW, MIME_SBOM_REPORT):
            return p
    # Harbor always sends an explicit Accept; default to the model report for curl users
    return MIME_MODEL_SECURITY_REPORT


def build_router(store: JobStore, worker: Worker) -> APIRouter:
    router = APIRouter(prefix="/api/v1")

    @router.get("/metadata")
    def get_metadata() -> Response:
        return Response(metadata().model_dump_json(), media_type=MIME_ADAPTER_METADATA)

    @router.post("/scan", status_code=202)
    async def post_scan(request: Request) -> Response:
        try:
            body = await request.json()
            req = ScanRequest.model_validate(body)
        except Exception as e:
            return error(422, f"invalid scan request: {e}")
        if req.artifact.mime_type and req.artifact.mime_type != MIME_MODEL_MANIFEST:
            return error(422, f"unsupported artifact mime type {req.artifact.mime_type!r}, only models are supported")
        job_id = str(uuid.uuid4())
        store.create(Job(id=job_id, request=req.model_dump()))
        worker.submit(job_id, req)
        log.info("accepted scan %s for %s@%s", job_id, req.artifact.repository, req.artifact.digest)
        return Response(status_code=202, content=f'{{"id":"{job_id}"}}', media_type=MIME_SCAN_RESPONSE)

    @router.get("/scan/{scan_id}/report")
    def get_report(scan_id: str, request: Request) -> Response:
        job = store.get(scan_id)
        if job is None:
            return error(404, f"scan {scan_id} not found")
        if job.status == STATUS_FAILED:
            return error(500, job.error or "scan failed")
        if job.status != STATUS_FINISHED:
            return Response(status_code=302, headers={REFRESH_AFTER_HEADER: "15", "Location": str(request.url)})
        mime = _accepted_mime(request)
        report = job.reports.get(mime)
        if report is None:
            return error(404, f"no report of type {mime!r} for scan {scan_id}")
        return Response(report, media_type=mime)

    return router


def create_app(settings: Settings, store: JobStore | None = None) -> FastAPI:
    from scanner.store import new_store

    store = store or new_store(settings.redis_url, settings.redis_namespace, settings.job_ttl)
    worker = Worker(store, settings)

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        yield
        worker.shutdown()

    app = FastAPI(title="harbor-scanner-modelaudit", docs_url=None, redoc_url=None, lifespan=lifespan)
    app.state.store = store
    app.state.worker = worker
    app.include_router(build_router(store, worker))

    @app.get("/probe/healthy")
    def healthy() -> dict:
        return {"status": "ok"}

    @app.get("/probe/ready")
    def ready() -> Response:
        ping = getattr(store, "ping", None)
        if ping and not ping():
            return error(503, "redis unavailable")
        return JSONResponse({"status": "ok", "inflight": worker.inflight})

    return app
