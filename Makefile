SHELL := /bin/bash
PY ?= python3
VENV ?= .venv
BIN := $(VENV)/bin
PORT ?= 8000
export PYTHONPATH := $(CURDIR)
.DEFAULT_GOAL := help
.PHONY: help setup setup-full flink-test run dev train train-quick evaluate benchmark talkingdata test test-fast cov lint format verify demo simulate clean docker-up docker-down docker-build deploy package all

help:  ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-14s\033[0m %s\n",$$1,$$2}'

setup:  ## Create venv, install deps, train the first model
	bash scripts/setup.sh

setup-full: ## setup + optional integrations (SHAP, LangGraph, Postgres, Redis, Neo4j, Kafka clients, embedded test servers)
	bash scripts/setup.sh --full

run: ## Start the platform (UIs at http://localhost:$(PORT), API docs at /docs)
	bash scripts/run.sh

dev: ## Start with auto-reload
	RELOAD=1 bash scripts/run.sh

train: ## Train + register models (full dataset)
	bash scripts/train.sh

train-quick: ## Train a small model fast
	bash scripts/train.sh --quick

evaluate: ## Full evaluation -> reports/EVALUATION.md, metrics.json, plots
	bash scripts/evaluate.sh

benchmark: ## Throughput / latency benchmark -> reports/benchmark.json
	bash scripts/evaluate.sh --benchmark-only

talkingdata: ## Benchmark on Kaggle TalkingData sample (data/raw/train_sample.csv)
	$(BIN)/python -m aegis.data.talkingdata

test: ## Full test suite
	bash scripts/test.sh

flink-test: ## Flink parity test (needs `pip install apache-flink` in a separate venv + Java; set FLINK_PY)
	AEGIS_FLINK_PYTHON=$(FLINK_PY) $(BIN)/python -m pytest tests/test_flink.py

test-fast: ## Unit tests only
	$(BIN)/python -m pytest tests/test_unit.py

cov: ## Tests with coverage
	$(BIN)/python -m pytest --cov=aegis --cov-report=term-missing

lint: ## Lint (ruff)
	$(BIN)/ruff check aegis tests scripts

format: ## Auto-format / fix
	$(BIN)/ruff check --fix aegis tests scripts

verify: ## End-to-end smoke test against a real server process
	bash scripts/verify.sh

demo: ## Scripted attack demo (needs `make run` in another terminal)
	$(BIN)/python scripts/demo.py --url http://localhost:$(PORT)

simulate: ## Start a bot attack against the running server (ATTACK=click_farm to change)
	$(BIN)/python scripts/demo.py --url http://localhost:$(PORT) --only $(or $(ATTACK),bot)

clean: ## Remove caches, db, generated reports (keeps models)
	rm -rf .pytest_cache .ruff_cache .coverage htmlcov data/processed/*.pkl data/*.db* reports/*.png reports/*.json reports/EVALUATION.md
	find . -name __pycache__ -type d -prune -exec rm -rf {} +

docker-build: ## Build the image
	docker compose -f docker/docker-compose.yml build

docker-up: ## Start app (+ optional PROFILES="kafka postgres redis neo4j monitoring")
	docker compose -f docker/docker-compose.yml $(foreach p,$(PROFILES) $(PROFILE),--profile $(p)) up -d --build

docker-down: ## Stop containers
	docker compose -f docker/docker-compose.yml --profile kafka --profile postgres --profile redis --profile neo4j --profile monitoring down

deploy: ## Placeholder: build + tag image for your registry (set IMAGE=...)
	@test -n "$(IMAGE)" || (echo "set IMAGE=registry/name:tag" && exit 1)
	docker build -f docker/Dockerfile -t $(IMAGE) . && echo "built $(IMAGE); push with: docker push $(IMAGE)"

package: ## Build the distributable zip in dist/
	bash scripts/package.sh

all: setup test evaluate ## setup + test + evaluate
