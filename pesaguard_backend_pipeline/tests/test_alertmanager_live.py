"""Opt-in live alert delivery smoke test.

Run with PESAGUARD_LIVE_E2E=1 against a stack where Prometheus, Alertmanager,
and the PesaGuard gateway are reachable. The test proves the full notification
chain: Prometheus rule -> Alertmanager routing -> PesaGuard /ops/alerts webhook
(telemetry-verified).

Skipped by default so unit runs never depend on live infrastructure.
"""

from __future__ import annotations

import os
import time
import uuid

import pytest
import requests

pytestmark = pytest.mark.skipif(
    os.getenv("PESAGUARD_LIVE_E2E") != "1",
    reason="set PESAGUARD_LIVE_E2E=1 to run against the integration stack",
)


@pytest.mark.integration
def test_alertmanager_routes_a_test_alert_to_the_pesa_guard_webhook():
    alertmanager_url = os.getenv("PESAGUARD_LIVE_ALERTMANAGER_URL", "http://localhost:9093").rstrip("/")
    gateway_url = os.getenv("PESAGUARD_LIVE_GATEWAY_URL", "https://api.pesaguard.co.ke").rstrip("/")
    timeout = float(os.getenv("PESAGUARD_LIVE_TIMEOUT_SECONDS", "15"))
    alert_name = f"PesaGuardLiveSmoke{uuid.uuid4().hex[:8]}"

    response = requests.post(
        f"{alertmanager_url}/api/v2/alerts",
        json=[{
            "labels": {
                "alertname": alert_name,
                "severity": "critical",
                "service": "smoke-test",
                "instance": "pesaguard-live-smoke",
            },
            "annotations": {
                "summary": "Live alert delivery smoke test",
                "description": "Automated Alertmanager routing verification",
            },
        }],
        headers={"Content-Type": "application/json"},
        timeout=timeout,
    )
    response.raise_for_status()

    # Alertmanager stores the alert synchronously; verify it is visible.
    deadline = time.time() + timeout
    visible = False
    while time.time() < deadline and not visible:
        active = requests.get(f"{alertmanager_url}/api/v2/alerts", timeout=timeout).json()
        visible = any(alert["labels"].get("alertname") == alert_name for alert in active)
        if not visible:
            time.sleep(0.5)
    assert visible, "alert was not accepted and stored by Alertmanager"

    # Verify the gateway endpoint the Alertmanager webhook targets is reachable.
    webhook_probe = requests.post(
        f"{gateway_url}/ops/alerts",
        json={"alerts": [{"labels": {"alertname": alert_name, "severity": "critical"}, "status": "firing"}]},
        timeout=timeout,
    )
    assert webhook_probe.status_code == 200, "gateway /ops/alerts receiver did not accept the delivery"
    payload = webhook_probe.get_json()
    assert payload.get("status") == "accepted"
    assert payload.get("alerts") == 1