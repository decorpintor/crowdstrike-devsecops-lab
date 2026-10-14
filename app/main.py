
from datetime import datetime, timezone
from typing import Literal

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, ConfigDict, Field

app = FastAPI(
    title="CrowdStrike DevSecOps Lab",
    version="1.0.0",
    description="Mock-first endpoint security triage API",
)

Severity = Literal["low", "medium", "high", "critical"]


class AlertIn(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    alert_id: str = Field(
        min_length=3, max_length=80,
        pattern=r"^[A-Za-z0-9_.-]+$"
    )
    host_name: str = Field(min_length=1, max_length=120)
    detection_name: str = Field(min_length=3, max_length=200)
    category: str = Field(min_length=2, max_length=80)
    source: Literal["mock", "crowdstrike"] = "mock"
    observed_at: datetime | None = None
    tags: list[str] = Field(default_factory=list, max_length=20)


class Alert(AlertIn):
    received_at: datetime
    risk_score: int = Field(ge=0, le=100)
    severity: Severity
    status: Literal["new", "triaged"] = "triaged"


def score_alert(alert: AlertIn) -> tuple[int, Severity]:
    text = f"{alert.detection_name} {alert.category}".lower()
    score = 15

    if any(word in text for word in (
        "ransomware", "credential theft", "privilege escalation"
    )):
        score += 65
    elif any(word in text for word in (
        "malware", "powershell", "persistence", "suspicious"
    )):
        score += 40
    else:
        score += 10

    if any(
        tag.lower() in ("production", "critical-asset")
        for tag in alert.tags
    ):
        score += 15

    score = min(score, 100)

    if score >= 85:
        severity = "critical"
    elif score >= 65:
        severity = "high"
    elif score >= 40:
        severity = "medium"
    else:
        severity = "low"

    return score, severity


def build_alert(data: AlertIn) -> Alert:
    score, severity = score_alert(data)
    now = datetime.now(timezone.utc)

    values = data.model_dump()
    values["observed_at"] = data.observed_at or now

    return Alert(
        **values,
        received_at=now,
        risk_score=score,
        severity=severity,
    )


SEED_ALERTS = [
    AlertIn(
        alert_id="mock-1001",
        host_name="win-lab-01",
        detection_name="Suspicious PowerShell activity",
        category="execution",
        tags=["workstation"],
    ),
    AlertIn(
        alert_id="mock-1002",
        host_name="linux-lab-01",
        detection_name="Possible credential theft",
        category="credential-access",
        tags=["production"],
    ),
    AlertIn(
        alert_id="mock-1003",
        host_name="win-lab-02",
        detection_name="Unusual persistence mechanism",
        category="persistence",
        tags=["critical-asset"],
    ),
    AlertIn(
        alert_id="mock-1004",
        host_name="linux-lab-02",
        detection_name="Unrecognized software inventory change",
        category="configuration",
        tags=["workstation"],
    ),
]

alerts: dict[str, Alert] = {
    item.alert_id: build_alert(item) for item in SEED_ALERTS
}
request_count = 0


@app.middleware("http")
async def count_requests(request, call_next):
    global request_count
    response = await call_next(request)
    request_count += 1
    return response


@app.get("/")
def root():
    return {
        "service": "crowdstrike-devsecops-lab",
        "mode": "mock",
        "docs": "/docs",
    }


@app.get("/healthz")
def healthz():
    return {"status": "ok"}


@app.get("/readyz")
def readyz():
    return {
        "status": "ready",
        "mode": "mock",
        "falcon_connected": False,
    }


@app.get("/alerts", response_model=list[Alert])
def list_alerts(
    severity: Severity | None = None,
    limit: int = 100,
):
    if not 1 <= limit <= 500:
        raise HTTPException(
            status_code=400,
            detail="limit must be between 1 and 500",
        )

    results = list(alerts.values())

    if severity:
        results = [
            alert for alert in results
            if alert.severity == severity
        ]

    return sorted(
        results,
        key=lambda alert: alert.risk_score,
        reverse=True,
    )[:limit]


@app.post("/alerts", response_model=Alert, status_code=201)
def ingest_alert(payload: AlertIn):
    if payload.alert_id in alerts:
        raise HTTPException(
            status_code=409,
            detail="alert_id already exists",
        )

    # Never pretend that mock data came from a real Falcon tenant.
    if payload.source == "crowdstrike":
        raise HTTPException(
            status_code=501,
            detail="Live Falcon integration is not configured",
        )

    result = build_alert(payload)
    alerts[result.alert_id] = result
    return result


@app.get("/summary")
def summary():
    items = list(alerts.values())

    counts = {
        severity: sum(
            1 for alert in items if alert.severity == severity
        )
        for severity in ("low", "medium", "high", "critical")
    }

    return {
        "mode": "mock",
        "falcon_connected": False,
        "total_alerts": len(items),
        "by_severity": counts,
        "high_or_critical": counts["high"] + counts["critical"],
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/metrics", include_in_schema=False)
def metrics():
    items = list(alerts.values())

    lines = [
        "# HELP devsecops_alerts_total Current number of demo alerts",
        "# TYPE devsecops_alerts_total gauge",
        f"devsecops_alerts_total {len(items)}",
        "# HELP devsecops_requests_total HTTP requests served",
        "# TYPE devsecops_requests_total counter",
        f"devsecops_requests_total {request_count}",
    ]

    for severity in ("low", "medium", "high", "critical"):
        count = sum(
            1 for alert in items if alert.severity == severity
        )
        lines.append(
            f'devsecops_alerts_by_severity'
            f'{{severity="{severity}"}} {count}'
        )

    from fastapi.responses import PlainTextResponse
    return PlainTextResponse("\n".join(lines) + "\n")
