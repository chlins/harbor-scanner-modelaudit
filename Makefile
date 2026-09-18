IMAGE ?= goharbor/harbor-scanner-modelaudit
TAG   ?= dev

.PHONY: setup lint fmt test build build-full run

setup:
	uv venv -p 3.12 .venv && uv pip install -e ".[dev]"

lint:
	.venv/bin/ruff check . && .venv/bin/ruff format --check .

fmt:
	.venv/bin/ruff format . && .venv/bin/ruff check --fix .

test:
	.venv/bin/pytest -q

build:
	docker build -t $(IMAGE):$(TAG) .

build-full:
	docker build --build-arg MODELAUDIT_EXTRAS=all -t $(IMAGE):$(TAG)-full .

run:
	SCANNER_LOG_LEVEL=debug .venv/bin/harbor-scanner-modelaudit
