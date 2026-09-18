"""Runs ModelAudit against a fetched model and converts its output to Harbor reports."""

from __future__ import annotations

import json
import logging
import re
from datetime import UTC, datetime
from importlib.metadata import version as pkg_version
from pathlib import Path
from typing import Any

from scanner import __version__
from scanner.api.models import (
    MEDIA_TYPE_CYCLONEDX,
    MODELAUDIT_SEVERITY_MAP,
    SEVERITY_ORDER,
    Finding,
    ModelSecurityReport,
    SBOMReport,
    Scanner,
    Summary,
    max_severity,
)
from scanner.registry.client import FetchedModel

log = logging.getLogger(__name__)

SCANNER_DOCS = "https://www.promptfoo.dev/docs/model-audit/scanners/"


def modelaudit_version() -> str:
    try:
        return pkg_version("modelaudit")
    except Exception:  # pragma: no cover
        return "unknown"


def scanner_info() -> Scanner:
    return Scanner(name="ModelAudit", vendor="Promptfoo", version=modelaudit_version())


def adapter_scanner_info() -> Scanner:
    """Identity reported in /metadata: the adapter version plus the engine version."""
    return Scanner(name="ModelAudit", vendor="Promptfoo", version=f"{modelaudit_version()} (adapter {__version__})")


# --- running ------------------------------------------------------------------------------


def run_modelaudit(model: FetchedModel, *, timeout: int, max_total_size: int = 0) -> dict[str, Any]:
    """Scan the model directory and return the ModelAudit result as a plain dict (its JSON shape)."""
    from modelaudit.core import scan_model_directory_or_file

    result = scan_model_directory_or_file(
        str(model.root),
        timeout=timeout,
        max_total_size=max_total_size,
        skip_file_types=False,
    )
    return _to_dict(result)


def generate_sbom(model: FetchedModel, raw_result: dict[str, Any]) -> dict[str, Any]:
    """Generate a CycloneDX BOM for the model directory.

    ModelAudit uses absolute scratch paths as bom-refs; they are rewritten to paths relative
    to the model root, and the model artifact itself is added as the root component so the
    BOM describes "this OCI artifact" and not a temporary directory.
    """
    from modelaudit.integrations.sbom_generator import generate_sbom as ma_generate_sbom

    payload = ma_generate_sbom([str(model.root)], raw_result)
    bom = json.loads(payload)
    return _normalize_sbom(bom, model)


def _normalize_sbom(bom: dict[str, Any], model: FetchedModel) -> dict[str, Any]:
    prefix = str(model.root).rstrip("/") + "/"

    def rel(ref: Any) -> Any:
        if isinstance(ref, str) and ref.startswith(prefix):
            return ref[len(prefix) :]
        return ref

    for component in bom.get("components", []) or []:
        component["bom-ref"] = rel(component.get("bom-ref"))
        if component.get("name"):
            component["name"] = rel(component["name"])
    for dep in bom.get("dependencies", []) or []:
        dep["ref"] = rel(dep.get("ref"))
        if "dependsOn" in dep:
            dep["dependsOn"] = [rel(d) for d in dep["dependsOn"]]

    metadata = bom.setdefault("metadata", {})
    metadata.setdefault(
        "component",
        {
            "type": "machine-learning-model",
            "bom-ref": f"{model.repository}@{model.digest}",
            "name": model.repository,
            "version": model.digest,
            "properties": [
                {"name": "oci:artifactType", "value": model.artifact_type},
                {"name": "oci:digest", "value": model.digest},
            ],
        },
    )
    return bom


def _to_dict(result: Any) -> dict[str, Any]:
    if isinstance(result, dict):
        return result
    for attr in ("to_dict", "model_dump"):
        fn = getattr(result, attr, None)
        if callable(fn):
            try:
                return fn(mode="json") if attr == "model_dump" else fn()
            except TypeError:
                return fn()
    return json.loads(json.dumps(result, default=str))


# --- converting ---------------------------------------------------------------------------

_RULE_SANITIZE = re.compile(r"[^A-Z0-9-]")


def rule_id(issue: dict[str, Any]) -> str:
    """Mirror ModelAudit's SARIF rule id derivation so ids are stable across outputs."""
    code = issue.get("rule_code")
    if isinstance(code, str) and code:
        return code
    itype = issue.get("type")
    if isinstance(itype, str) and itype:
        return "MA" + itype.replace(" ", "-").upper()
    base = str(issue.get("message", ""))[:30].replace(" ", "-").replace(":", "").upper()
    return "MA-" + _RULE_SANITIZE.sub("", base)


def relative_file(location: str | None, root: Path) -> tuple[str, str]:
    """Split a ModelAudit location ("<abs path>", "<abs path> (pos 28)", "<path>:layer") into
    (file relative to the model root, extra position text)."""
    if not location:
        return "", ""
    loc = str(location)
    root_str = str(root).rstrip("/") + "/"
    # locations look like "/tmp/x/model.pkl", "/tmp/x/model.pkl (pos 28)", "/tmp/x/a.zip:inner.pkl"
    m = re.match(r"^(?P<path>\S+?)(?P<rest>(\s+\(.*\))|(:[^/\\].*))?$", loc)
    path = m.group("path") if m else loc
    rest = (m.group("rest") or "").strip() if m else ""
    if path.startswith(root_str):
        path = path[len(root_str) :]
    elif path == str(root).rstrip("/"):
        path = ""
    return path, rest.strip("() ")


def _strip_root(value: Any, root: Path) -> Any:
    """Replace the scratch directory prefix in any string so reports never leak adapter paths."""
    prefix = str(root).rstrip("/") + "/"
    if isinstance(value, str):
        return value.replace(prefix, "")
    if isinstance(value, dict):
        return {k: _strip_root(v, root) for k, v in value.items()}
    if isinstance(value, list):
        return [_strip_root(v, root) for v in value]
    return value


def convert_report(model: FetchedModel, raw: dict[str, Any], *, min_severity: str = "warning") -> ModelSecurityReport:
    min_rank = _rank(MODELAUDIT_SEVERITY_MAP.get(min_severity.lower(), "Medium"))
    findings: list[Finding] = []
    for issue in raw.get("issues", []) or []:
        details = issue.get("details") or {}
        if isinstance(details, dict) and details.get("supporting_rule_code") is True:
            continue
        sev = MODELAUDIT_SEVERITY_MAP.get(str(issue.get("severity", "")).lower())
        if not sev or _rank(sev) < min_rank:
            continue
        file, pos = relative_file(issue.get("location"), model.root)
        scanner_name = ""
        if isinstance(details, dict):
            scanner_name = str(details.get("scanner") or details.get("scanner_name") or "")
        if not scanner_name:
            # e.g. "pickle_check" -> "pickle"
            scanner_name = re.sub(r"_check$", "", str(issue.get("type") or ""))
        findings.append(
            Finding(
                id=rule_id(issue),
                severity=sev,
                message=str(issue.get("message", "")),
                why=str(issue.get("why") or ""),
                file=file,
                location=pos,
                scanner=scanner_name,
                details=_strip_root(_json_safe(details), model.root) if isinstance(details, dict) else {},
                links=[SCANNER_DOCS],
            )
        )

    findings.sort(key=lambda f: (-_rank(f.severity), f.file, f.id))
    summary = Summary(
        total=len(findings),
        critical=sum(f.severity == "Critical" for f in findings),
        high=sum(f.severity == "High" for f in findings),
        medium=sum(f.severity == "Medium" for f in findings),
        low=sum(f.severity == "Low" for f in findings),
        files_scanned=int(raw.get("files_scanned") or len(model.files)),
        bytes_scanned=int(raw.get("bytes_scanned") or model.total_size),
        scanners=sorted({str(s) for s in raw.get("scanner_names", []) or []}),
    )
    return ModelSecurityReport(
        generated_at=_now(),
        scanner=scanner_info(),
        severity=max_severity([f.severity for f in findings]),
        summary=summary,
        findings=findings,
    )


def convert_sbom(bom: dict[str, Any]) -> SBOMReport:
    return SBOMReport(
        generated_at=_now(),
        scanner=scanner_info(),
        media_type=MEDIA_TYPE_CYCLONEDX,
        sbom=bom,
    )


def _rank(sev: str) -> int:
    return SEVERITY_ORDER.index(sev)


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _json_safe(d: dict[str, Any]) -> dict[str, Any]:
    return json.loads(json.dumps(d, default=str))
