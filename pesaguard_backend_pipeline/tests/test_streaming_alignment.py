"""Test late arriving event flag."""
from reconciliation_engine import evaluate_transaction
from datetime import datetime, timezone, timedelta
from zoneinfo import ZoneInfo

def test_late_arriving_event():
    # 2 hours ago
    late_time = (datetime.now(ZoneInfo("Africa/Nairobi")) - timedelta(hours=2)).strftime("%Y%m%d%H%M%S")
    event = {
        "TransID": "LATE-1",
        "TransAmount": "100",
        "TransTime": late_time,
        "MSISDN": "254700000000"
    }
    
    result = evaluate_transaction(event, [], set())
    assert "late_arriving_event" in result["anomalies"]

def test_recent_event_not_late():
    # 5 minutes ago
    recent_time = (datetime.now(ZoneInfo("Africa/Nairobi")) - timedelta(minutes=5)).strftime("%Y%m%d%H%M%S")
    event = {
        "TransID": "RECENT-1",
        "TransAmount": "100",
        "TransTime": recent_time,
        "MSISDN": "254700000000"
    }
    
    result = evaluate_transaction(event, [], set())
    assert "late_arriving_event" not in result["anomalies"]
