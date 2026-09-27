"""PesaGuard backend package compatibility layer."""

import importlib
import os
import sys

PACKAGE_ROOT = os.path.dirname(__file__)
if PACKAGE_ROOT not in sys.path:
    sys.path.insert(0, PACKAGE_ROOT)

# Load deployment values before compatibility imports read configuration.
from . import environment as _environment
sys.modules.setdefault("environment", _environment)

# Provide stable top-level module aliases so the package and the legacy
# top-level imports resolve to the same module objects during tests and local runs.
for module_name in [
    "action_audit",
    "auth_rbac",
    "event_store",
    "export_routes",
    "health",
    "init_db",
    "logging_utils",
    "models",
    "observability",
    "producer",
    "rate_limiter",
    "security_helpers",
    "tenant_organization_service",
    "tenant_org_dashboard",
    "tenant_org_routes",
    "tenant_settings",
    "validators",
]:
    try:
        module = importlib.import_module(f"pesaguard_backend_pipeline.{module_name}")
    except ImportError:
        continue
    sys.modules.setdefault(module_name, module)

try:
    _communications = importlib.import_module("pesaguard_backend_pipeline.communications")
    sys.modules.setdefault("communications", _communications)
    # communications/models.py tries "from models import Base" then
    # "from pesaguard_backend_pipeline.models import Base" to land on one
    # canonical Base either way it's reached -- but that only works if the
    # module itself is loaded once. Aliasing the "communications" package
    # above doesn't also alias its "models" submodule under the bare dotted
    # key, so a later bare "import communications.models" (as most of the
    # test suite uses) still re-executed this file's class bodies a second
    # time, appending every Index() in __table_args__ a second time onto the
    # same shared table (extend_existing=True stops the table/columns
    # themselves from erroring on re-declaration, but not that). Alias the
    # submodule explicitly, the same way the loop above does for every other
    # module, and set it as an attribute too so `communications.models.X`
    # attribute access (not just `from communications.models import X`) sees
    # the same object.
    _communications_models = importlib.import_module("pesaguard_backend_pipeline.communications.models")
    sys.modules.setdefault("communications.models", _communications_models)
    _communications.models = _communications_models
except ImportError:
    pass
