"""Tests for the ModelAudit runner and report converters."""

from __future__ import annotations

from pathlib import Path

from scanner.api.models import SEVERITY_CRITICAL, SEVERITY_LOW, SEVERITY_MEDIUM, SEVERITY_NONE, max_severity
from scanner.modelaudit_runner import runner
from scanner.registry.client import FetchedModel, LayerFile


def _model(tmp_path: Path) -> FetchedModel:
    root = tmp_path / "model"
    root.mkdir()
    return FetchedModel(
        repository="library/m",
        digest="sha256:abc",
        artifact_type="application/vnd.cncf.model.manifest.v1+json",
        manifest={},
        config={},
        root=root,
        files=[LayerFile(digest="sha256:1", size=10, media_type="", path="model.pkl")],
    )


def test_max_severity():
    assert max_severity([]) == SEVERITY_NONE
    assert max_severity([SEVERITY_LOW, SEVERITY_CRITICAL, SEVERITY_MEDIUM]) == SEVERITY_CRITICAL


def test_rule_id():
    assert runner.rule_id({"rule_code": "MA-PICKLE-001"}) == "MA-PICKLE-001"
    assert runner.rule_id({"type": "pickle issue"}) == "MAPICKLE-ISSUE"
    assert runner.rule_id({"message": "Suspicious module: os.system"}).startswith("MA-SUSPICIOUS-MODULE")


def test_relative_file(tmp_path: Path):
    root = tmp_path / "model"
    assert runner.relative_file(f"{root}/model.pkl", root) == ("model.pkl", "")
    assert runner.relative_file(f"{root}/model.pkl (pos 28)", root) == ("model.pkl", "pos 28")
    assert runner.relative_file(f"{root}/a.zip:inner.pkl", root) == ("a.zip", ":inner.pkl")
    assert runner.relative_file(None, root) == ("", "")


def test_convert_report_maps_and_filters(tmp_path: Path):
    model = _model(tmp_path)
    raw = {
        "files_scanned": 2,
        "bytes_scanned": 123,
        "scanner_names": ["pickle", "text"],
        "issues": [
            {
                "severity": "critical",
                "message": "Suspicious module reference found: posix.system",
                "why": "os gives system access",
                "location": f"{model.root}/model.pkl (pos 28)",
                "details": {"scanner": "pickle", "module": "posix"},
                "rule_code": "MA-PICKLE-SYSTEM",
            },
            {
                "severity": "warning",
                "message": "Large text file",
                "location": f"{model.root}/vocab.txt",
                "type": "text_check",
                "details": {"context": f"{model.root}/vocab.txt", "nested": [f"{model.root}/x"]},
            },
            {"severity": "info", "message": "URL detected", "location": f"{model.root}/README.md"},
            {"severity": "debug", "message": "noise"},
            {"severity": "critical", "message": "supporting", "details": {"supporting_rule_code": True}},
        ],
    }
    report = runner.convert_report(model, raw, min_severity="warning")
    assert report.severity == SEVERITY_CRITICAL
    assert report.summary.total == 2
    assert report.summary.critical == 1 and report.summary.medium == 1 and report.summary.low == 0
    assert report.summary.files_scanned == 2 and report.summary.bytes_scanned == 123
    assert report.summary.scanners == ["pickle", "text"]
    first = report.findings[0]
    assert first.id == "MA-PICKLE-SYSTEM"
    assert first.severity == SEVERITY_CRITICAL
    assert first.file == "model.pkl" and first.location == "pos 28"
    assert first.scanner == "pickle"
    assert first.why == "os gives system access"
    assert first.links
    second = report.findings[1]
    assert second.scanner == "text"
    assert second.details == {"context": "vocab.txt", "nested": ["x"]}

    # info kept when min severity is info
    report = runner.convert_report(model, raw, min_severity="info")
    assert report.summary.total == 3 and report.summary.low == 1

    # no findings
    report = runner.convert_report(model, {"issues": []})
    assert report.severity == SEVERITY_NONE and report.summary.total == 0
    assert report.summary.files_scanned == 1 and report.summary.bytes_scanned == 10


def test_convert_sbom():
    r = runner.convert_sbom({"bomFormat": "CycloneDX", "components": []})
    assert r.media_type == "application/vnd.cyclonedx+json"
    assert r.sbom["bomFormat"] == "CycloneDX"
    assert r.scanner.name == "ModelAudit"


def test_run_modelaudit_on_malicious_pickle(tmp_path: Path):
    """End to end against the real ModelAudit engine with a pickle that calls os.system."""
    import pickle

    model = _model(tmp_path)

    class Evil:
        def __reduce__(self):
            import os

            return (os.system, ("echo pwned",))

    (model.root / "model.pkl").write_bytes(pickle.dumps(Evil()))
    (model.root / "config.json").write_text('{"model_type": "gpt2"}')
    model.files = [
        LayerFile(digest="sha256:1", size=1, media_type="", path="model.pkl"),
        LayerFile(digest="sha256:2", size=1, media_type="", path="config.json"),
    ]

    raw = runner.run_modelaudit(model, timeout=120)
    assert raw["files_scanned"] >= 1
    report = runner.convert_report(model, raw)
    assert report.severity == SEVERITY_CRITICAL, [f.message for f in report.findings]
    assert any(f.file == "model.pkl" for f in report.findings)
    assert any("system" in f.message.lower() or "os" in f.message.lower() for f in report.findings)

    bom = runner.generate_sbom(model, raw)
    assert bom["bomFormat"] == "CycloneDX"
    names = {c["name"] for c in bom["components"]}
    assert "model.pkl" in names
