"""Integration tests for the dashboard incident/analytics features.

``Discrepancy.status`` is constrained by ``ck_discrepancy_status`` to
('needs_review', 'reviewed', 'resolved', 'escalated'). "assigned" is a
presentation-level state that the API derives from the ``assignee`` column,
so seeds represent assignment through ``assignee`` rather than ``status``.

All endpoints under test require authentication
(``PESAGUARD_API_AUTH_REQUIRED`` defaults to on), so every request carries a
Bearer token for an ``operations``-role user scoped to the seeded tenant.
"""

import importlib
import os
import tempfile
from datetime import datetime, timedelta, timezone

import pytest
from auth_rbac import AuthRBAC
from auth_seed import seed_account


@pytest.fixture
def test_client(monkeypatch):
    """Isolated dashboard API instance with seeded incidents and an authenticated operator."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "pesaguard_features.db")
        monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_path}")
        monkeypatch.setenv("PESAGUARD_API_AUTH_REQUIRED", "1")
        monkeypatch.setenv("JWT_SECRET_KEY", "test-secret-key-with-at-least-32-bytes")

        import app_2  # compatibility shim that resolves to api.dashboard_app

        app_2 = importlib.reload(app_2)
        app_2.Base.metadata.create_all(app_2.engine)

        from action_audit import ActionAuditEntry
        from auth_rbac import _RevocationBase

        _RevocationBase.metadata.create_all(app_2.primary_engine)
        # .metadata, not .__table__: bulk_resolve/resolve_discrepancy also write
        # to AuditOutboxEntry (transactional outbox), sharing this declarative base.
        ActionAuditEntry.metadata.create_all(app_2.primary_engine, checkfirst=True)
        app_2.app.config.update(TESTING=True)

        session = app_2.SessionLocal()
        try:
            now = datetime.now(timezone.utc)
            session.add_all(
                [
                    # Open, unassigned, critical and old enough to auto-escalate.
                    app_2.Discrepancy(
                        id="test-1",
                        trans_id="txn-001",
                        tenant_id="default",
                        anomaly_type="duplicate",
                        severity="critical",
                        status="needs_review",
                        resolved=False,
                        detected_at=now - timedelta(minutes=50),
                    ),
                    # Open and assigned: assignment is carried by ``assignee``.
                    app_2.Discrepancy(
                        id="test-2",
                        trans_id="txn-002",
                        tenant_id="default",
                        anomaly_type="amount_mismatch",
                        severity="warning",
                        status="needs_review",
                        assignee="ops-user",
                        resolved=False,
                        detected_at=now - timedelta(minutes=20),
                    ),
                    # Resolved.
                    app_2.Discrepancy(
                        id="test-3",
                        trans_id="txn-003",
                        tenant_id="default",
                        anomaly_type="missing_transaction",
                        severity="critical",
                        status="resolved",
                        resolved=True,
                        detected_at=now - timedelta(hours=2),
                        resolved_at=now - timedelta(hours=1),
                    ),
                ]
            )
            session.commit()
        finally:
            session.close()

        token = AuthRBAC.generate_token(
            user_id="features-admin",
            username="features-admin",
            tenant_id="default",
            roles=["operations"],
        )
        seed_account(
            app_2.SessionLocal,
            user_id="features-admin",
            tenant_id="default",
            roles=["operations"],
        )
        auth_headers = {"Authorization": f"Bearer {token}"}

        with app_2.app.test_client() as client:
            yield client, auth_headers


def test_reconciliation_report(test_client):
    """Test reconciliation report generation."""
    client, auth_headers = test_client
    response = client.get('/analytics/reconciliation-report?days=1', headers=auth_headers)
    assert response.status_code == 200
    data = response.get_json()

    assert 'summary' in data
    assert data['summary']['total_incidents'] == 3
    assert data['summary']['resolved'] == 1
    assert data['summary']['open'] == 2


def test_incident_trends(test_client):
    """Test incident trends endpoint."""
    client, auth_headers = test_client
    response = client.get('/analytics/incident-trends', headers=auth_headers)
    assert response.status_code == 200
    data = response.get_json()

    assert 'weekly' in data
    assert 'monthly' in data
    assert len(data['weekly']) == 4
    assert len(data['monthly']) == 12


def test_filter_presets_get(test_client):
    """Test retrieving filter presets."""
    client, auth_headers = test_client
    response = client.get('/incidents/filters/presets', headers=auth_headers)
    assert response.status_code == 200
    data = response.get_json()

    assert 'presets' in data
    assert 'critical_open' in data['presets']


def test_filter_presets_post(test_client):
    """Saving a preset actually persists it -- a prior version of this route
    returned 201 without writing anything, so a follow-up GET is the real test."""
    client, auth_headers = test_client
    response = client.post(
        '/incidents/filters/presets',
        json={'name': 'test_preset', 'filters': {'severity': 'warning'}},
        headers=auth_headers,
    )
    assert response.status_code == 201
    data = response.get_json()

    assert 'presets' in data
    assert data['presets']['test_preset'] == {'severity': 'warning'}

    # Persistence, not just an echo in the POST response: a fresh GET (a new
    # request, same tenant) must see it too.
    follow_up = client.get('/incidents/filters/presets', headers=auth_headers)
    assert follow_up.status_code == 200
    assert follow_up.get_json()['presets']['test_preset'] == {'severity': 'warning'}

    # Posting the same name again updates it in place rather than erroring or duplicating.
    updated = client.post(
        '/incidents/filters/presets',
        json={'name': 'test_preset', 'filters': {'severity': 'critical'}},
        headers=auth_headers,
    )
    assert updated.status_code == 201
    assert updated.get_json()['presets']['test_preset'] == {'severity': 'critical'}


def test_auto_escalate(test_client):
    """Test auto-escalation of critical incidents."""
    client, auth_headers = test_client
    response = client.post('/incidents/auto-escalate?escalation_minutes=40', headers=auth_headers)
    assert response.status_code == 200
    data = response.get_json()

    assert data['status'] == 'escalated'
    assert data['threshold_minutes'] == 40
    # Should escalate the test-1 incident (50 minutes old, unassigned)
    assert data['count'] >= 1


def test_bulk_assign(test_client):
    """Test bulk assignment of incidents, and that it now leaves an audit record."""
    client, auth_headers = test_client
    response = client.post(
        '/incidents/bulk-assign',
        json={'ids': ['test-1', 'test-2'], 'assignee': 'john_doe', 'note': 'Test assignment'},
        headers=auth_headers,
    )
    assert response.status_code == 200
    data = response.get_json()

    assert data['status'] == 'assigned'
    assert data['updated'] == 2

    from action_audit import ActionAuditEntry
    import app_2

    session = app_2.SessionLocal()
    try:
        entry = (
            session.query(ActionAuditEntry)
            .filter(ActionAuditEntry.action == "bulk_assign_incidents")
            .order_by(ActionAuditEntry.created_at.desc())
            .first()
        )
        assert entry is not None, "bulk-assign wrote no audit record"
        assert sorted(entry.details["discrepancy_ids"]) == ["test-1", "test-2"]
        assert entry.details["assignee"] == "john_doe"
    finally:
        session.close()


def test_search_incidents(test_client):
    """Test full-text search."""
    client, auth_headers = test_client
    response = client.get('/incidents/search?q=duplicate&page=1&per_page=10', headers=auth_headers)
    assert response.status_code == 200
    data = response.get_json()

    assert 'items' in data
    assert data['query'] == 'duplicate'


def test_search_with_filters(test_client):
    """Test search with severity and assignee filters."""
    client, auth_headers = test_client
    response = client.get('/incidents/search?severity=critical&page=1', headers=auth_headers)
    assert response.status_code == 200
    data = response.get_json()

    assert data['total'] >= 1


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
