# harbor-scanner-modelaudit

A [Harbor](https://goharbor.io) pluggable scanner adapter that scans AI model artifacts
(ModelPack / CNCF model spec) with [ModelAudit](https://www.promptfoo.dev/docs/model-audit/)
and produces:

- a **model security report** (`application/vnd.security.model.report+json; version=1.0`):
  findings such as unsafe pickle opcodes, embedded executables, Keras Lambda layers,
  Jinja template injection, leaked credentials, suspicious network patterns;
- a **CycloneDX 1.6 SBOM** (`application/vnd.security.sbom.report+json; version=1.0`, media
  type `application/vnd.cyclonedx+json`) listing every model file with hash, size and license.

It implements the [pluggable scanner adapter API](https://github.com/goharbor/pluggable-scanner-spec)
v1 and is registered in Harbor like any other scanner. Harbor routes model artifacts to it and
container images to the image scanner (Trivy) based on the declared capabilities.

## How it works

```
Harbor core ──POST /api/v1/scan──▶ adapter ──GET manifest + raw layers──▶ Harbor registry
                                     │
                                     ├─ modelaudit.core.scan_model_directory_or_file(dir)
                                     ├─ modelaudit.integrations.sbom_generator.generate_sbom
                                     ▼
Harbor core ◀─GET /api/v1/scan/{id}/report (Accept: <mime>)─ adapter
```

Layers of a ModelPack artifact are raw files named by the `org.cncf.model.filepath`
annotation, so the adapter streams them into a scratch directory (no untar) and runs
ModelAudit on that directory. Nothing is ever loaded with an ML framework.

## Run

```bash
docker run --rm -p 8080:8080 \
  -e SCANNER_REDIS_URL=redis://redis:6379 \
  ghcr.io/chlins/harbor-scanner-modelaudit:latest

curl -s http://localhost:8080/api/v1/metadata | jq
```

Then in Harbor (2.17+): Administration → Interrogation Services → New Scanner, endpoint
`http://<adapter>:8080`. Keep Trivy as the default scanner; Harbor picks ModelAudit for
model artifacts automatically.

## Configuration

| Variable | Default | Description |
| --- | --- | --- |
| `SCANNER_API_SERVER_ADDR` | `0.0.0.0:8080` | Listen address |
| `SCANNER_LOG_LEVEL` | `info` | Log level |
| `SCANNER_REDIS_URL` | *(empty)* | Redis URL for the job store; empty uses an in-memory store (single replica only) |
| `SCANNER_REDIS_NAMESPACE` | `harbor.scanner.modelaudit:store` | Key prefix |
| `SCANNER_JOB_TTL` | `3600` | Seconds a finished report is kept |
| `SCANNER_JOB_QUEUE_WORKERS` | `1` | Concurrent scans per replica |
| `SCANNER_REGISTRY_TIMEOUT` | `300` | Seconds per blob request |
| `SCANNER_SCRATCH_DIR` | `/tmp/scanner` | Where models are downloaded during a scan |
| `SCANNER_MODELAUDIT_TIMEOUT` | `3600` | Seconds allowed for one ModelAudit run |
| `SCANNER_MODELAUDIT_MAX_SIZE` | `0` | Max total bytes per artifact (`0` = unlimited); larger models fail the scan |
| `SCANNER_MODELAUDIT_MIN_SEVERITY` | `warning` | Lowest ModelAudit severity kept in the report (`info` findings such as URLs in a README are only in the raw report) |
| `SCANNER_MODELAUDIT_KEEP_RAW` | `true` | Also expose the raw ModelAudit JSON as `application/vnd.scanner.adapter.model.report.raw` |

Severity mapping: ModelAudit `critical → Critical`, `warning → Medium`, `info → Low`,
`debug` dropped.

## Development

```bash
uv venv -p 3.12 && uv pip install -e ".[dev]"
ruff check . && pytest
SCANNER_LOG_LEVEL=debug harbor-scanner-modelaudit
```

## License

Apache-2.0. ModelAudit is MIT licensed.
