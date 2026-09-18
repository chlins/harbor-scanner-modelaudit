"""Tests for the registry client and the HTTP API, using an in-process fake registry."""

from __future__ import annotations

import hashlib
import json
import pickle
import time
from pathlib import Path

import httpx
import pytest
import respx
from fastapi.testclient import TestClient

from scanner.api.app import create_app
from scanner.api.models import (
    MIME_MODEL_MANIFEST,
    MIME_MODEL_SECURITY_RAW,
    MIME_MODEL_SECURITY_REPORT,
    MIME_SBOM_REPORT,
    Registry,
)
from scanner.config import Settings
from scanner.registry.client import NotAModelError, RegistryClient, RegistryError, SizeLimitExceededError
from scanner.store import MemoryJobStore

REG = "http://registry.test"
REPO = "library/model"


class Evil:
    def __reduce__(self):
        import os

        return (os.system, ("echo pwned",))


def _digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def fake_model(mock: respx.MockRouter, *, files: dict[str, bytes] | None = None, artifact_type=MIME_MODEL_MANIFEST):
    files = files if files is not None else {"model.pkl": pickle.dumps(Evil()), "config.json": b'{"a":1}'}
    config = json.dumps({"descriptor": {"name": "m"}, "modelfs": {"type": "layers", "diffIds": []}}).encode()
    layers = []
    for path, data in files.items():
        layers.append(
            {
                "mediaType": "application/vnd.cncf.model.weight.v1.raw",
                "digest": _digest(data),
                "size": len(data),
                "annotations": {"org.cncf.model.filepath": path},
            }
        )
        mock.get(f"{REG}/v2/{REPO}/blobs/{_digest(data)}").mock(return_value=httpx.Response(200, content=data))
    manifest = {
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "artifactType": artifact_type,
        "config": {
            "mediaType": "application/vnd.cncf.model.config.v1+json",
            "digest": _digest(config),
            "size": len(config),
        },
        "layers": layers,
    }
    mock.get(f"{REG}/v2/{REPO}/blobs/{_digest(config)}").mock(return_value=httpx.Response(200, content=config))
    body = json.dumps(manifest).encode()
    mock.get(f"{REG}/v2/{REPO}/manifests/{_digest(body)}").mock(
        return_value=httpx.Response(200, content=body, headers={"Content-Type": manifest["mediaType"]})
    )
    return _digest(body), manifest


# --- registry client ------------------------------------------------------------------------


@respx.mock
def test_fetch_model(tmp_path: Path):
    digest, _ = fake_model(respx.mock)
    with RegistryClient(Registry(url=REG, authorization="Bearer x")) as c:
        model = c.fetch_model(REPO, digest, tmp_path / "m")
    assert {f.path for f in model.files} == {"model.pkl", "config.json"}
    assert (tmp_path / "m" / "model.pkl").exists()
    assert model.config["descriptor"]["name"] == "m"
    assert model.total_size == sum(f.size for f in model.files)
    # authorization header forwarded
    assert respx.calls.last.request.headers["Authorization"] == "Bearer x"


@respx.mock
def test_fetch_rejects_non_model(tmp_path: Path):
    digest, _ = fake_model(respx.mock, artifact_type="application/vnd.oci.image.config.v1+json")
    with RegistryClient(Registry(url=REG)) as c, pytest.raises(NotAModelError):
        c.fetch_model(REPO, digest, tmp_path / "m")


@respx.mock
def test_fetch_size_limit(tmp_path: Path):
    digest, _ = fake_model(respx.mock, files={"big.bin": b"x" * 100})
    with RegistryClient(Registry(url=REG)) as c, pytest.raises(SizeLimitExceededError):
        c.fetch_model(REPO, digest, tmp_path / "m", max_size=10)


@respx.mock
def test_fetch_rejects_path_traversal(tmp_path: Path):
    digest, _ = fake_model(respx.mock, files={"../../etc/passwd": b"root"})
    with RegistryClient(Registry(url=REG)) as c, pytest.raises(RegistryError):
        c.fetch_model(REPO, digest, tmp_path / "m")


@respx.mock
def test_fetch_digest_mismatch(tmp_path: Path):
    digest, manifest = fake_model(respx.mock, files={"a.bin": b"good"})
    respx.get(f"{REG}/v2/{REPO}/blobs/{manifest['layers'][0]['digest']}").mock(
        return_value=httpx.Response(200, content=b"evil")
    )
    with RegistryClient(Registry(url=REG)) as c, pytest.raises(RegistryError, match="digest mismatch"):
        c.fetch_model(REPO, digest, tmp_path / "m")


@respx.mock
def test_fetch_unauthorized(tmp_path: Path):
    respx.get(f"{REG}/v2/{REPO}/manifests/sha256:x").mock(return_value=httpx.Response(401))
    with RegistryClient(Registry(url=REG)) as c, pytest.raises(RegistryError, match="access denied"):
        c.fetch_model(REPO, "sha256:x", tmp_path / "m")


# --- HTTP API -------------------------------------------------------------------------------


@pytest.fixture
def client(tmp_path: Path):
    settings = Settings(scratch_dir=str(tmp_path / "scratch"), modelaudit_timeout=120)
    app = create_app(settings, store=MemoryJobStore())
    with TestClient(app) as c:
        yield c


def test_metadata(client: TestClient):
    r = client.get("/api/v1/metadata")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("application/vnd.scanner.adapter.metadata+json")
    md = r.json()
    assert md["scanner"]["name"] == "ModelAudit"
    types = {c["type"]: c for c in md["capabilities"]}
    assert set(types) == {"model-security", "sbom"}
    assert types["model-security"]["consumes_mime_types"] == [MIME_MODEL_MANIFEST]
    assert MIME_MODEL_SECURITY_REPORT in types["model-security"]["produces_mime_types"]
    assert MIME_SBOM_REPORT in types["sbom"]["produces_mime_types"]
    assert md["properties"]["harbor.scanner-adapter/scanner-type"] == "model"


def test_probes(client: TestClient):
    assert client.get("/probe/healthy").json() == {"status": "ok"}
    assert client.get("/probe/ready").status_code == 200


def test_scan_rejects_bad_request(client: TestClient):
    r = client.post("/api/v1/scan", json={"artifact": {}})
    assert r.status_code == 422
    assert "error" in r.json()
    r = client.post(
        "/api/v1/scan",
        json={
            "registry": {"url": REG},
            "artifact": {
                "repository": REPO,
                "digest": "sha256:x",
                "mime_type": "application/vnd.oci.image.manifest.v1+json",
            },
        },
    )
    assert r.status_code == 422


def test_report_not_found(client: TestClient):
    assert client.get("/api/v1/scan/nope/report").status_code == 404


def _wait(client: TestClient, scan_id: str, mime: str, timeout: float = 120) -> httpx.Response:
    deadline = time.time() + timeout
    while time.time() < deadline:
        r = client.get(f"/api/v1/scan/{scan_id}/report", headers={"Accept": mime}, follow_redirects=False)
        if r.status_code != 302:
            return r
        assert r.headers["Refresh-After"]
        time.sleep(0.2)
    raise AssertionError("scan did not finish")


@respx.mock
def test_scan_end_to_end(client: TestClient):
    digest, _ = fake_model(respx.mock)
    r = client.post(
        "/api/v1/scan",
        json={
            "registry": {"url": REG, "authorization": "Bearer t"},
            "artifact": {"repository": REPO, "digest": digest, "mime_type": MIME_MODEL_MANIFEST},
            "enabled_capabilities": [
                {"type": "model-security", "produces_mime_types": [MIME_MODEL_SECURITY_REPORT]},
                {"type": "sbom", "produces_mime_types": [MIME_SBOM_REPORT]},
            ],
        },
    )
    assert r.status_code == 202, r.text
    assert r.headers["content-type"].startswith("application/vnd.scanner.adapter.scan.response+json")
    scan_id = r.json()["id"]

    rep = _wait(client, scan_id, MIME_MODEL_SECURITY_REPORT)
    assert rep.status_code == 200, rep.text
    report = rep.json()
    assert report["scanner"]["name"] == "ModelAudit"
    assert report["severity"] == "Critical"
    assert report["summary"]["critical"] >= 1
    assert any(f["file"] == "model.pkl" for f in report["findings"])

    raw = client.get(f"/api/v1/scan/{scan_id}/report", headers={"Accept": MIME_MODEL_SECURITY_RAW})
    assert raw.status_code == 200 and "issues" in raw.json()

    sbom = client.get(f"/api/v1/scan/{scan_id}/report", headers={"Accept": MIME_SBOM_REPORT})
    assert sbom.status_code == 200
    body = sbom.json()
    assert body["media_type"] == "application/vnd.cyclonedx+json"
    assert body["sbom"]["bomFormat"] == "CycloneDX"
    assert {c["name"] for c in body["sbom"]["components"]} >= {"model.pkl", "config.json"}


@respx.mock
def test_scan_failure_is_reported(client: TestClient):
    respx.get(f"{REG}/v2/{REPO}/manifests/sha256:missing").mock(return_value=httpx.Response(404))
    r = client.post(
        "/api/v1/scan",
        json={"registry": {"url": REG}, "artifact": {"repository": REPO, "digest": "sha256:missing"}},
    )
    scan_id = r.json()["id"]
    rep = _wait(client, scan_id, MIME_MODEL_SECURITY_REPORT)
    assert rep.status_code == 500
    assert "not found" in rep.json()["error"]["message"]
