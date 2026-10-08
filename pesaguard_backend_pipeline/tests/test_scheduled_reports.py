import importlib

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from models import Base, Report, Transaction


def _transaction(transaction_id, tenant_id):
    return Transaction(
        trans_id=transaction_id,
        tenant_id=tenant_id,
        trans_amount="10.00",
        msisdn="254700000000",
        business_short_code="123456",
        trans_time="20260912120000",
        raw_payload={"TransID": transaction_id},
    )


def test_scheduled_reports_count_and_discover_only_tenant_scoped_transactions(tmp_path, monkeypatch):
    database_url = f"sqlite:///{tmp_path / 'scheduled-reports.db'}"
    monkeypatch.setenv("DATABASE_URL", database_url)
    import operations.scheduled_reports as scheduled_reports

    scheduled_reports = importlib.reload(scheduled_reports)
    engine = create_engine(database_url)
    Base.metadata.create_all(engine)
    test_session_factory = sessionmaker(bind=engine, expire_on_commit=False)
    monkeypatch.setattr(scheduled_reports, "Session", test_session_factory)

    with test_session_factory() as session:
        session.add_all([
            _transaction("tenant-a-tx", "tenant-a"),
            _transaction("tenant-b-tx", "tenant-b"),
        ])
        session.commit()

    result = scheduled_reports.generate_report_for_tenant("tenant-a", days=1)

    assert result["status"] == "ok"
    assert result["summary"]["total_transactions_ingested"] == 1
    assert scheduled_reports.get_all_active_tenants() == ["tenant-a", "tenant-b"]
    with test_session_factory() as session:
        report = session.get(Report, result["report_id"])
        assert report.tenant_id == "tenant-a"
        assert report.content["summary"]["total_transactions_ingested"] == 1

    scheduled_reports.engine.dispose()
    engine.dispose()
