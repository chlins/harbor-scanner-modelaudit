"""Minimal OCI distribution client used to fetch a ModelPack artifact into a scratch directory."""

from __future__ import annotations

import hashlib
import logging
import os
import posixpath
from dataclasses import dataclass, field
from pathlib import Path

import httpx

from scanner.api.models import ANNOTATION_FILEPATH, MIME_MODEL_MANIFEST, MIME_OCI_MANIFEST, Registry

log = logging.getLogger(__name__)

ACCEPT_MANIFESTS = ", ".join(
    [
        MIME_OCI_MANIFEST,
        "application/vnd.oci.image.index.v1+json",
        "application/vnd.docker.distribution.manifest.v2+json",
    ]
)


class RegistryError(Exception):
    pass


class NotAModelError(RegistryError):
    pass


class SizeLimitExceededError(RegistryError):
    pass


@dataclass
class LayerFile:
    digest: str
    size: int
    media_type: str
    path: str  # relative path inside the model, from the filepath annotation
    local_path: Path | None = None


@dataclass
class FetchedModel:
    repository: str
    digest: str
    artifact_type: str
    manifest: dict
    config: dict
    root: Path
    files: list[LayerFile] = field(default_factory=list)

    @property
    def total_size(self) -> int:
        return sum(f.size for f in self.files)


def _safe_relative_path(raw: str) -> str:
    """Normalise a filepath annotation and reject anything escaping the model root."""
    p = posixpath.normpath(raw.strip().lstrip("/"))
    if p in ("", ".") or p.startswith("../") or p == ".." or "\x00" in p or posixpath.isabs(p):
        raise RegistryError(f"unsafe layer file path {raw!r}")
    return p


class RegistryClient:
    def __init__(self, registry: Registry, *, timeout: int = 300):
        base = registry.url.rstrip("/")
        if not base.startswith(("http://", "https://")):
            base = ("http://" if registry.insecure else "https://") + base
        self.base = base
        headers = {}
        if registry.authorization:
            headers["Authorization"] = registry.authorization
        self._client = httpx.Client(
            headers=headers,
            timeout=httpx.Timeout(timeout, connect=30),
            verify=not registry.insecure,
            follow_redirects=True,
        )

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> RegistryClient:
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # -- API ------------------------------------------------------------------------------

    def get_manifest(self, repository: str, reference: str) -> tuple[dict, str]:
        url = f"{self.base}/v2/{repository}/manifests/{reference}"
        resp = self._client.get(url, headers={"Accept": ACCEPT_MANIFESTS})
        self._raise(resp, f"manifest {repository}@{reference}")
        return resp.json(), resp.headers.get("Content-Type", "")

    def get_blob_json(self, repository: str, digest: str) -> dict:
        url = f"{self.base}/v2/{repository}/blobs/{digest}"
        resp = self._client.get(url)
        self._raise(resp, f"blob {digest}")
        try:
            return resp.json()
        except ValueError:
            return {}

    def download_blob(self, repository: str, digest: str, dest: Path, expected_size: int) -> int:
        """Stream a blob to dest, verify size and digest, return bytes written."""
        url = f"{self.base}/v2/{repository}/blobs/{digest}"
        algo, _, expected_hex = digest.partition(":")
        hasher = hashlib.new(algo)
        written = 0
        dest.parent.mkdir(parents=True, exist_ok=True)
        with self._client.stream("GET", url) as resp:
            self._raise(resp, f"blob {digest}")
            with open(dest, "wb") as fh:
                for chunk in resp.iter_bytes(1024 * 1024):
                    fh.write(chunk)
                    hasher.update(chunk)
                    written += len(chunk)
        if expected_size and written != expected_size:
            raise RegistryError(f"blob {digest}: size mismatch, expected {expected_size} got {written}")
        if hasher.hexdigest() != expected_hex:
            raise RegistryError(f"blob {digest}: digest mismatch")
        return written

    # -- high level -----------------------------------------------------------------------

    def fetch_model(self, repository: str, digest: str, root: Path, *, max_size: int = 0) -> FetchedModel:
        manifest, content_type = self.get_manifest(repository, digest)
        artifact_type = manifest.get("artifactType") or manifest.get("config", {}).get("mediaType", "")
        if artifact_type != MIME_MODEL_MANIFEST and content_type.split(";")[0].strip() != MIME_MODEL_MANIFEST:
            raise NotAModelError(f"artifact {repository}@{digest} is not a model (artifactType={artifact_type!r})")

        files: list[LayerFile] = []
        for layer in manifest.get("layers", []):
            annotations = layer.get("annotations") or {}
            rel = annotations.get(ANNOTATION_FILEPATH)
            if not rel:
                # no path: still scan it, name it by digest
                rel = layer["digest"].replace(":", "_")
            if rel.endswith("/"):
                # directory marker layer, nothing to download
                continue
            files.append(
                LayerFile(
                    digest=layer["digest"],
                    size=int(layer.get("size", 0)),
                    media_type=layer.get("mediaType", ""),
                    path=_safe_relative_path(rel),
                )
            )

        total = sum(f.size for f in files)
        if max_size and total > max_size:
            raise SizeLimitExceededError(f"model size {total} bytes exceeds the limit of {max_size} bytes")

        config = {}
        cfg = manifest.get("config") or {}
        if cfg.get("digest"):
            try:
                config = self.get_blob_json(repository, cfg["digest"])
            except RegistryError as e:  # config is optional for scanning
                log.warning("failed to read model config: %s", e)

        root.mkdir(parents=True, exist_ok=True)
        for f in files:
            dest = (root / f.path).resolve()
            if os.path.commonpath([root.resolve(), dest]) != str(root.resolve()):
                raise RegistryError(f"layer path {f.path!r} escapes the scratch directory")
            log.info("downloading %s (%s, %d bytes)", f.path, f.digest, f.size)
            self.download_blob(repository, f.digest, dest, f.size)
            f.local_path = dest

        return FetchedModel(
            repository=repository,
            digest=digest,
            artifact_type=artifact_type,
            manifest=manifest,
            config=config,
            root=root,
            files=files,
        )

    # -- helpers --------------------------------------------------------------------------

    @staticmethod
    def _raise(resp: httpx.Response, what: str) -> None:
        if resp.status_code == 401 or resp.status_code == 403:
            raise RegistryError(f"access denied when fetching {what} (HTTP {resp.status_code})")
        if resp.status_code == 404:
            raise RegistryError(f"{what} not found")
        if resp.status_code >= 400:
            raise RegistryError(f"failed to fetch {what}: HTTP {resp.status_code}")
