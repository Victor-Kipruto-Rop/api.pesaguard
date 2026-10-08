import os
import sys
import tempfile
from contextlib import suppress

import pytest

# Tests must never inherit credentials or service endpoints from deployment files.
os.environ["PYTHON_DOTENV_DISABLED"] = "1"
os.environ.setdefault("PESAGUARD_API_URL", "http://localhost:5001")

TESTS_DIR = os.path.dirname(__file__)
PACKAGE_DIR = os.path.dirname(TESTS_DIR)
REPOSITORY_ROOT = os.path.dirname(PACKAGE_DIR)

for path in (REPOSITORY_ROOT, PACKAGE_DIR):
    if path not in sys.path:
        sys.path.insert(0, path)

if len(os.environ.get("JWT_SECRET_KEY", "").encode("utf-8")) < 32:
    os.environ["JWT_SECRET_KEY"] = "test-secret-key-with-at-least-32-bytes"
test_db_path = os.path.join(tempfile.gettempdir(), "pesaguard-test.sqlite3")
if os.path.exists(test_db_path):
    with suppress(PermissionError):
        os.remove(test_db_path)
os.environ.setdefault("PYTEST_TEST_DB_URL", f"sqlite:///{test_db_path}")

from test_config import configure_test_database  # noqa: E402


configure_test_database()

from app_4_advanced_features import engine  # noqa: E402
from auth_rbac import _RevocationBase  # noqa: E402
from action_audit import ActionAuditRecord, Base as AuditBase  # noqa: E402, F401
from models import Base  # noqa: E402


Base.metadata.create_all(engine)
AuditBase.metadata.create_all(engine)
_RevocationBase.metadata.create_all(engine)


@pytest.fixture(autouse=True)
def reset_in_memory_login_rate_limits():
    from app_4_advanced_features import _LOGIN_PROTECTION_LIMITERS
    from rate_limiter import _memory_limiter

    for limiter in _LOGIN_PROTECTION_LIMITERS.values():
        with limiter._memory._lock:
            limiter._memory.buckets.clear()
            limiter._memory.distinct_values.clear()
    with _memory_limiter._lock:
        _memory_limiter.buckets.clear()
        _memory_limiter.distinct_values.clear()
    yield


@pytest.fixture(autouse=True)
def restore_revocation_store():
    import auth_rbac

    previous_engine = auth_rbac._revocation_engine
    previous_session_factory = auth_rbac._RevocationSession
    previous_checked = auth_rbac._revocation_store_checked
    yield
    current_engine = auth_rbac._revocation_engine
    auth_rbac.configure_revocation_store(previous_engine, previous_session_factory)
    auth_rbac._revocation_store_checked = previous_checked
    if current_engine is not None and current_engine is not previous_engine:
        current_engine.dispose()
