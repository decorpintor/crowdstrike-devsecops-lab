# CrowdStrike Falcon DevSecOps Automation Lab

A mock-first endpoint security automation project built with Python, FastAPI, Docker, Kubernetes, and GitHub Actions.

## Overview

This lab demonstrates how a DevSecOps engineer can normalize endpoint alerts, prioritize incidents, produce security summaries, monitor service metrics, and integrate automated security checks into a CI/CD pipeline.

**Important:** The current implementation uses synthetic alerts. It does not connect to a live CrowdStrike Falcon tenant or represent mock events as real detections.

## Architecture

```text
Synthetic endpoint alerts
          |
          v
FastAPI security triage API
          |
          +--> Alert validation and risk scoring
          +--> Incident summaries
          +--> Prometheus-format metrics
          |
          v
Docker container
          |
          v
Local Kubernetes deployment
          |
          v
GitHub Actions security pipeline
  pytest -> Bandit -> Docker build -> Trivy
```

## Technologies

- Python and FastAPI
- Docker and Docker Compose
- Kubernetes
- GitHub Actions
- Pytest and Bandit
- Trivy container vulnerability scanning
- Prometheus-compatible metrics

## Features

- Mock endpoint alert ingestion
- Severity classification and risk scoring
- Duplicate alert rejection
- JSON incident summaries
- Health and readiness endpoints
- Container hardening and Kubernetes security contexts
- Automated application tests and vulnerability scanning

## Run locally

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt
pytest -q
uvicorn app.main:app --reload
```

Open `http://localhost:8000/docs`.

## Run with Docker

```bash
docker compose up --build -d
curl http://localhost:8000/summary
curl http://localhost:8000/metrics
docker compose down
```

## Deploy to Kubernetes

```bash
docker build -t crowdstrike-devsecops-lab:local .
kubectl apply -f k8s/namespace.yaml
kubectl apply -f k8s/deployment.yaml
kubectl -n security-lab rollout status deployment/falcon-triage-api
kubectl -n security-lab port-forward svc/falcon-triage-api 8000:8000
```

## Security practices

- Non-root container execution
- Read-only container filesystem
- Dropped Linux capabilities
- Disabled privilege escalation
- Kubernetes health probes and resource limits
- Least-privilege GitHub Actions permissions
- Automated static analysis and container vulnerability scanning

## Limitations and future work

The starter stores alerts in memory and uses illustrative risk scoring. It does not perform endpoint isolation, process termination, or other response actions.

Future improvements include authenticated CrowdStrike Falcon API integration, durable storage, alert deduplication across restarts, authentication and authorization, audit logging, policy-as-code, and approval-gated response automation.

Any future Falcon integration will use authorized credentials, the minimum necessary API scopes, and sanitized test fixtures.

## Portfolio evidence

Include screenshots of the API documentation, sample incident summary, running Kubernetes workload, passing automated tests, CI results, and container scan findings.

## Resume description

Built a mock-first endpoint security automation platform using Python, Docker, Kubernetes, and GitHub Actions. Implemented alert validation, risk scoring, security metrics, hardened container deployment, automated tests, and static and container vulnerability scanning, with a design prepared for future authorized CrowdStrike Falcon API integration.
