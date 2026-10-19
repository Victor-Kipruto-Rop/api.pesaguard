# GitLab Container Registry for PesaGuard Core API

## Purpose

GitHub remains the canonical repository. GitLab is a pull mirror used to build and publish versioned container images to the GitLab Container Registry. This pipeline does not deploy to Render, run production migrations, or change DNS.

## Repository mirror

1. Create a **private** GitLab project, for example `api-pesaguard`.
2. In GitLab, open **Settings → Repository → Mirroring repositories** and add the GitHub repository:
   `https://github.com/Victor-Kipruto-Rop/api.pesaguard.git`
3. Select **Pull** as the mirror direction. GitHub remains the source of truth.
4. For a private GitHub repository, use a GitHub fine-grained personal access token limited to this repository with **Contents: Read-only** and the minimum metadata permission GitHub requires. Enter the token only in GitLab's mirror credential field. Never store it in this repository, a CI variable, or a commit.
5. Enable pipeline triggering for mirror updates if the GitLab UI offers that setting. If the mirror updates without starting a pipeline, start a pipeline manually from **Build → Pipelines** or configure a separately secured GitHub-to-GitLab pipeline trigger.
6. Protect the GitLab default branch and keep it read-only to ordinary developers. Make changes in GitHub, then let the mirror synchronize them.

## Container registry and CI variables

The pipeline uses GitLab's built-in variables; do not create duplicate secrets for these:

- `CI_REGISTRY`
- `CI_REGISTRY_IMAGE`
- `CI_REGISTRY_USER`
- `CI_REGISTRY_PASSWORD`

Ensure the project's Container Registry is enabled and the runner can run Docker-in-Docker with TLS. On a self-managed runner, configure a trusted Docker executor and privileged mode according to GitLab's current runner documentation; do not enable privileged mode on an untrusted shared runner.

The image path is derived from `CI_REGISTRY_IMAGE`, so the exact registry hostname and project namespace are not hard-coded. The build uses `infra/docker/Dockerfile` and the repository root as its build context.

## Published tags

Successful build jobs publish:

- `$CI_REGISTRY_IMAGE:$CI_COMMIT_SHA` — immutable release identity; use this tag for audit and promotion.
- `$CI_REGISTRY_IMAGE:$CI_COMMIT_REF_SLUG` — convenience alias for the branch or Git tag; this alias can move.
- `$CI_REGISTRY_IMAGE:buildcache` — BuildKit layer cache, not a deployable release reference.

The image includes the source revision in `PESAGUARD_BUILD_REVISION` and the OCI revision/source labels. The pipeline scans the published SHA image for unfixed-excluded HIGH and CRITICAL vulnerabilities. A failed scan fails the pipeline and must block promotion. The image may already exist in the registry because scanning follows publishing; do not deploy it unless the pipeline is green.

## Security and production safety

- No application credentials are passed as Docker build arguments or copied into the image. `.dockerignore` excludes environment files.
- Do not add `.env`, production database URLs, Redis passwords, Daraja credentials, JWT keys, Sentry DSNs, or deployment hooks to GitLab CI variables for this image-only workflow.
- PostgreSQL, Redis, Kafka/Redpanda, email, and Daraja configuration remain runtime concerns supplied by the existing deployment platform.
- The API image runs the ASGI application from `pesaguard_backend_pipeline.fastapi_app:app` and listens on the container's `PORT` (default 5001). Its liveness probe is `/livez`; dependency readiness is `/health`.
- The same image can be used for an RQ worker only with the worker command configured explicitly by the deployment. Do not start an API and worker in one container.
- This pipeline does not connect to Render, change a Render service, apply Alembic migrations, or alter DNS. Keep the existing Render deployment on its current source/configuration until a separately reviewed migration plan is approved.

## First-run checklist

1. Create the private GitLab project and configure pull mirroring.
2. Merge `.gitlab-ci.yml` into GitHub's default branch so it appears in the mirror.
3. Verify the mirror has the same commit and `.gitlab-ci.yml`.
4. Start a pipeline for the default branch.
5. Confirm the build and registry push succeed.
6. Confirm the scan job succeeds. If it fails, review the finding and fix or formally assess it before promoting any image.
7. Verify the commit-SHA image exists in **Deploy → Container Registry**.
8. Do not connect this image to production until a separate staging deployment, health checks, migration/backup plan, and rollback procedure have passed.

## Troubleshooting

- **No pipeline after mirror sync:** check whether pipeline triggering on mirror updates is available/enabled. Otherwise run a manual pipeline or configure a protected pipeline trigger.
- **Docker daemon unavailable:** confirm the runner supports Docker-in-Docker, TLS service variables are intact, and runner security settings permit it.
- **Registry authentication fails:** confirm Container Registry is enabled and the job is using the built-in registry variables. Never print their values.
- **Scan fails:** a published image may remain in the registry. Treat a red pipeline as a failed release and do not deploy that tag.
- **Image cannot start:** validate the runtime command and required environment variables in staging. The container image alone does not provision PostgreSQL, Redis, or Kafka.
