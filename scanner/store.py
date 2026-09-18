"""Job store: keeps scan requests and their reports keyed by scan id.

The Redis backend lets several adapter replicas share state; the in-memory backend is for
single replica deployments and tests.
"""

from __future__ import annotations

import json
import threading
import time
from dataclasses import asdict, dataclass, field
from typing import Any

STATUS_QUEUED = "Queued"
STATUS_PENDING = "Pending"
STATUS_FINISHED = "Finished"
STATUS_FAILED = "Failed"


@dataclass
class Job:
    id: str
    request: dict[str, Any]
    status: str = STATUS_QUEUED
    error: str = ""
    # mime type -> report json string
    reports: dict[str, str] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

    @classmethod
    def from_json(cls, data: str) -> Job:
        return cls(**json.loads(data))


class JobStore:
    def create(self, job: Job) -> None:
        raise NotImplementedError

    def get(self, job_id: str) -> Job | None:
        raise NotImplementedError

    def update(self, job: Job) -> None:
        raise NotImplementedError

    def set_status(self, job_id: str, status: str, error: str = "") -> None:
        job = self.get(job_id)
        if job is None:
            return
        job.status = status
        job.error = error
        job.updated_at = time.time()
        self.update(job)

    def set_reports(self, job_id: str, reports: dict[str, str]) -> None:
        job = self.get(job_id)
        if job is None:
            return
        job.reports = reports
        job.status = STATUS_FINISHED
        job.updated_at = time.time()
        self.update(job)


class MemoryJobStore(JobStore):
    def __init__(self, ttl: int = 3600):
        self._jobs: dict[str, Job] = {}
        self._lock = threading.Lock()
        self._ttl = ttl

    def _sweep(self) -> None:
        now = time.time()
        for k in [
            k
            for k, j in self._jobs.items()
            if j.status in (STATUS_FINISHED, STATUS_FAILED) and now - j.updated_at > self._ttl
        ]:
            del self._jobs[k]

    def create(self, job: Job) -> None:
        with self._lock:
            self._sweep()
            self._jobs[job.id] = job

    def get(self, job_id: str) -> Job | None:
        with self._lock:
            j = self._jobs.get(job_id)
            return Job.from_json(j.to_json()) if j else None

    def update(self, job: Job) -> None:
        with self._lock:
            self._jobs[job.id] = job


class RedisJobStore(JobStore):
    def __init__(self, url: str, namespace: str, ttl: int = 3600):
        import redis

        self._r = redis.Redis.from_url(url)
        self._ns = namespace
        self._ttl = ttl

    def _key(self, job_id: str) -> str:
        return f"{self._ns}:job:{job_id}"

    def create(self, job: Job) -> None:
        # queued/pending jobs live long enough for the longest scan; refreshed on update
        self._r.set(self._key(job.id), job.to_json(), ex=max(self._ttl, 24 * 3600))

    def get(self, job_id: str) -> Job | None:
        data = self._r.get(self._key(job_id))
        return Job.from_json(data) if data else None

    def update(self, job: Job) -> None:
        ex = self._ttl if job.status in (STATUS_FINISHED, STATUS_FAILED) else max(self._ttl, 24 * 3600)
        self._r.set(self._key(job.id), job.to_json(), ex=ex)

    def ping(self) -> bool:
        try:
            return bool(self._r.ping())
        except Exception:
            return False


def new_store(redis_url: str, namespace: str, ttl: int) -> JobStore:
    if redis_url:
        return RedisJobStore(redis_url, namespace, ttl)
    return MemoryJobStore(ttl)
