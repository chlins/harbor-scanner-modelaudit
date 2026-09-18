"""Harbor pluggable scanner adapter API types (v1) and the model security report."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

# --- MIME types ---------------------------------------------------------------------------

MIME_OCI_MANIFEST = "application/vnd.oci.image.manifest.v1+json"
MIME_DOCKER_MANIFEST = "application/vnd.docker.distribution.manifest.v2+json"
# ModelPack / CNCF model manifest artifact type; Harbor sends it as the artifact mime type
MIME_MODEL_MANIFEST = "application/vnd.cncf.model.manifest.v1+json"

MIME_ADAPTER_METADATA = "application/vnd.scanner.adapter.metadata+json; version=1.0"
MIME_SCAN_REQUEST = "application/vnd.scanner.adapter.scan.request+json; version=1.0"
MIME_SCAN_RESPONSE = "application/vnd.scanner.adapter.scan.response+json; version=1.0"
MIME_ERROR = "application/vnd.scanner.adapter.error+json; version=1.0"

# Reports produced by this adapter
MIME_MODEL_SECURITY_REPORT = "application/vnd.security.model.report+json; version=1.0"
MIME_MODEL_SECURITY_RAW = "application/vnd.scanner.adapter.model.report.raw"
MIME_SBOM_REPORT = "application/vnd.security.sbom.report+json; version=1.0"

MEDIA_TYPE_CYCLONEDX = "application/vnd.cyclonedx+json"

SCAN_TYPE_MODEL_SECURITY = "model-security"
SCAN_TYPE_SBOM = "sbom"

# Layer annotation carrying the file path in ModelPack artifacts
ANNOTATION_FILEPATH = "org.cncf.model.filepath"


# --- Adapter metadata ---------------------------------------------------------------------


class Scanner(BaseModel):
    name: str
    vendor: str
    version: str


class Capability(BaseModel):
    type: str
    consumes_mime_types: list[str]
    produces_mime_types: list[str]


class Metadata(BaseModel):
    scanner: Scanner
    capabilities: list[Capability]
    properties: dict[str, str] = Field(default_factory=dict)


# --- Scan request / response --------------------------------------------------------------


class Registry(BaseModel):
    url: str
    authorization: str = ""
    insecure: bool = False


class Artifact(BaseModel):
    repository: str
    digest: str
    tag: str = ""
    mime_type: str = ""
    size: int = 0


class EnabledCapability(BaseModel):
    type: str = SCAN_TYPE_MODEL_SECURITY
    produces_mime_types: list[str] = Field(default_factory=list)
    parameters: dict[str, Any] = Field(default_factory=dict)


class ScanRequest(BaseModel):
    registry: Registry
    artifact: Artifact
    enabled_capabilities: list[EnabledCapability] = Field(default_factory=list)

    def wants(self, scan_type: str) -> bool:
        if not self.enabled_capabilities:
            return scan_type == SCAN_TYPE_MODEL_SECURITY
        return any(c.type == scan_type for c in self.enabled_capabilities)


class ScanResponse(BaseModel):
    id: str


class ErrorBody(BaseModel):
    message: str


class ErrorResponse(BaseModel):
    error: ErrorBody


# --- Model security report ----------------------------------------------------------------

SEVERITY_NONE = "None"
SEVERITY_LOW = "Low"
SEVERITY_MEDIUM = "Medium"
SEVERITY_HIGH = "High"
SEVERITY_CRITICAL = "Critical"

SEVERITY_ORDER = [SEVERITY_NONE, SEVERITY_LOW, SEVERITY_MEDIUM, SEVERITY_HIGH, SEVERITY_CRITICAL]

# ModelAudit severities -> Harbor severities. "debug" is dropped.
MODELAUDIT_SEVERITY_MAP = {
    "critical": SEVERITY_CRITICAL,
    "warning": SEVERITY_MEDIUM,
    "info": SEVERITY_LOW,
}


def max_severity(severities: list[str]) -> str:
    best = SEVERITY_NONE
    for s in severities:
        if SEVERITY_ORDER.index(s) > SEVERITY_ORDER.index(best):
            best = s
    return best


class Finding(BaseModel):
    id: str
    severity: str
    message: str
    why: str = ""
    file: str = ""
    location: str = ""
    scanner: str = ""
    details: dict[str, Any] = Field(default_factory=dict)
    links: list[str] = Field(default_factory=list)


class Summary(BaseModel):
    total: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    files_scanned: int = 0
    bytes_scanned: int = 0
    scanners: list[str] = Field(default_factory=list)


class ModelSecurityReport(BaseModel):
    generated_at: str
    scanner: Scanner
    severity: str = SEVERITY_NONE
    summary: Summary = Field(default_factory=Summary)
    findings: list[Finding] = Field(default_factory=list)


class SBOMReport(BaseModel):
    """Envelope Harbor expects for the sbom scan type."""

    generated_at: str
    scanner: Scanner
    vendor_attributes: dict[str, Any] = Field(default_factory=dict)
    media_type: str = MEDIA_TYPE_CYCLONEDX
    sbom: dict[str, Any] = Field(default_factory=dict)
