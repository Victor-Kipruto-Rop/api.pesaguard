from pathlib import Path

import yaml

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]


def _workflow(path: str):
    # BaseLoader preserves Actions' `on` key and constructs scalar values only.
    return yaml.load(  # nosec B506
        (REPOSITORY_ROOT / path).read_text(encoding="utf-8"),
        Loader=yaml.BaseLoader,
    )


def test_release_promotes_only_staging_verified_digest_after_manual_request():
    workflow = _workflow(".github/workflows/release.yml")
    jobs = workflow["jobs"]
    staging = jobs["staging"]
    production = jobs["production"]

    assert "workflow_dispatch" in workflow["on"]
    assert workflow["on"]["workflow_dispatch"]["inputs"]["promote_production"]["default"] == "false"
    assert production["environment"] == "production"
    assert "staging" in production["needs"]
    assert "inputs.promote_production" in production["if"]
    assert "github.ref == 'refs/heads/main'" in production["if"]
    assert "github.event_name == 'workflow_dispatch'" in production["if"]

    expected_digest = "${{ needs.publish.outputs.image }}@${{ needs.publish.outputs.digest }}"
    for deployment in (staging, production):
        deploy_step = deployment["steps"][0]
        assert deploy_step["env"]["IMAGE_REF"] == expected_digest
        assert '--data-urlencode "imgURL=$IMAGE_REF"' in deploy_step["run"]
        health_step = deployment["steps"][-1]
        assert health_step["env"]["EXPECTED_REVISION"] == "${{ github.sha }}"
        assert 'payload.get("release") == os.environ["EXPECTED_REVISION"]' in health_step["run"]

    publish = jobs["publish"]
    build_step = next(step for step in publish["steps"] if step.get("id") == "build")
    assert "PESAGUARD_BUILD_REVISION=${{ github.sha }}" in build_step["with"]["build-args"]


def test_service_integration_uses_a_dedicated_kafka_gate():
    workflow = _workflow(".github/workflows/integration-services.yml")
    steps = workflow["jobs"]["integration"]["steps"]
    kafka_step = next(step for step in steps if step["name"] == "Verify broker-derived Kafka lag")

    assert kafka_step["env"]["PESAGUARD_RUN_KAFKA_INTEGRATION"] == "1"
    assert "PESAGUARD_LIVE_E2E" not in kafka_step["env"]
    assert kafka_step["run"] == "pytest -q pesaguard_backend_pipeline/tests/test_kafka_lag_live.py"


def test_ci_workflows_never_enable_unrestricted_webhook_sources():
    workflow_dir = REPOSITORY_ROOT / ".github" / "workflows"
    references = [
        path.relative_to(REPOSITORY_ROOT).as_posix()
        for path in workflow_dir.glob("*.yml")
        if "PESAGUARD_ALLOW_UNRESTRICTED_WEBHOOK_SOURCE" in path.read_text(encoding="utf-8")
    ]
    assert references == []


def test_ci_and_release_run_fatal_lint_and_undefined_name_checks():
    for path, job_name in ((".github/workflows/ci.yml", "test"), (".github/workflows/release.yml", "verify")):
        workflow = _workflow(path)
        steps = workflow["jobs"][job_name]["steps"]
        lint_step = next(
            step for step in steps if step.get("name") == "Check fatal lint errors and undefined names"
        )
        assert lint_step["run"] == "ruff check --select E9,F821 ."
