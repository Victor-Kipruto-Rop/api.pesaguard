# GitLab Container Registry for PesaGuard Core API

## Purpose

GitHub remains the canonical repository. A GitHub Actions workflow pushes branches and tags to a private GitLab mirror, where GitLab CI builds and publishes versioned images to the GitLab Container Registry. This avoids relying on GitLab pull mirroring, which GitLab currently lists as a Premium/Ultimate feature. This pipeline does not deploy to Render, run production migrations, or change DNS.

## 1. Create the GitLab project

1. Create a **private** GitLab project named `api-pesaguard` (or another slug you choose).
2. Leave the repository empty; do not initialize it with a README or license, because GitHub is the source of truth.
3. Enable the project's Container Registry if it is not enabled by default.
4. Protect the default branch (normally `main`). In branch rules, allow the dedicated mirror identity to push mirrored refs while preventing ordinary developers from making direct edits. Ensure any protected-tag rules also allow the mirror identity to create the tags you intend to mirror.

## 2. Create a GitLab mirror token

Create a dedicated GitLab token for the mirror with the minimum permission required to push Git refs. A personal access token with the `write_repository` scope can be used; use a dedicated bot identity if you have one. The token's user must be allowed to push to the mirrored branches under your branch protection rules. Copy the token once and do not put it in source code.

In the GitHub repository **Settings → Secrets and variables → Actions**, add these repository secrets:

- `GITLAB_MIRROR_URL`: the clean URL, such as `https://gitlab.com/YOUR_NAMESPACE/api-pesaguard.git`. Do not include a username, token, query string, or other credentials in this URL.
- `GITLAB_MIRROR_USERNAME`: the GitLab username associated with the token.
- `GITLAB_MIRROR_TOKEN`: the GitLab token with `write_repository` permission.

The GitHub workflow `.github/workflows/mirror-to-gitlab.yml` reads these secrets at runtime. It mirrors branches and tags only, not GitHub pull-request refs. It does not print token values.

## 3. Merge the pipeline files to GitHub

Merge the reviewed pull request that adds:

- `.gitlab-ci.yml` — builds the Docker image, publishes to GitLab Container Registry, then scans the published image.
- `.github/workflows/mirror-to-gitlab.yml` — synchronizes GitHub branches and tags to GitLab.
- `docs/operations/GITLAB_CONTAINER_REGISTRY.md` — this runbook.

After merging, GitHub remains the source of truth. Push code to GitHub's `main` or `staging` branch, or push a version tag. The GitHub Actions workflow then updates the GitLab mirror, and the GitLab CI pipeline runs for the mirrored default branch, `staging`, or tags. You can also run the GitHub mirror workflow manually from **Actions → Mirror repository to GitLab → Run workflow**.

## 4. Container registry and CI variables

The pipeline uses GitLab's built-in variables; do not create duplicate secrets for these:

- `CI_REGISTRY`
- `CI_REGISTRY_IMAGE`
- `CI_REGISTRY_USER`
- `CI_REGISTRY_PASSWORD`

Ensure the GitLab runner can run Docker-in-Docker with TLS. The configuration uses pinned Docker CLI and daemon images. On a self-managed runner, configure a trusted Docker executor and privileged mode according to GitLab's current runner documentation; privileged mode weakens container isolation and should not be enabled on an untrusted runner.

The image path is derived from `CI_REGISTRY_IMAGE`, so the registry hostname and project namespace are not hard-coded. The build uses the existing `infra/docker/Dockerfile` and repository root as its build context.

## 5. Published tags

Successful build jobs publish:

- `$CI_REGISTRY_IMAGE:$CI_COMMIT_SHA` — immutable release identity; use this tag for audit and promotion.
- `$CI_REGISTRY_IMAGE:$CI_COMMIT_REF_SLUG` — convenience alias for the branch or Git tag; this alias can move.
- `$CI_REGISTRY_IMAGE:buildcache` — BuildKit layer cache, not a deployable release reference.

The image includes the source revision in `PESAGUARD_BUILD_REVISION` and OCI revision/source labels. The pipeline scans the published SHA image for HIGH and CRITICAL vulnerabilities, ignoring unfixed findings. A failed scan fails the pipeline and must block promotion. The image may already exist in the registry because scanning follows publishing; do not deploy it unless the pipeline is green.

## 6. Security and production safety

- No application credentials are passed as Docker build arguments or copied into the image. The existing `.dockerignore` excludes environment files.
- Do not add `.env`, production database URLs, Redis passwords, Daraja credentials, JWT keys, Sentry DSNs, or deployment hooks to GitLab CI variables for this image-only workflow.
- PostgreSQL, Redis, Kafka/Redpanda, email, and Daraja configuration remain runtime concerns supplied by the existing deployment platform.
- The API image runs `pesaguard_backend_pipeline.fastapi_app:app` and listens on the container's `PORT` (default 5001). Its liveness probe is `/livez`; dependency readiness is `/health`.
- The same image can be used for an RQ worker only with the worker command configured explicitly by the deployment. Do not start an API and worker in one container.
- This pipeline does not connect to Render, change a Render service, apply Alembic migrations, or alter DNS. Keep the existing Render deployment on its current source/configuration until a separately reviewed migration plan is approved.

## 7. First-run checklist

1. Create the private GitLab project and add the three GitHub Actions secrets.
2. Merge the reviewed PR into GitHub's default branch.
3. Run **Actions → Mirror repository to GitLab** manually once, and confirm its run succeeds.
4. Confirm GitLab contains the same commit and `.gitlab-ci.yml`.
5. Confirm the GitLab pipeline starts and the Docker build/push succeeds.
6. Confirm the image scan succeeds. If it fails, review and remediate or formally assess findings before promoting the image.
7. Verify the commit-SHA image exists under **Deploy → Container Registry**.
8. Do not connect this image to production until a separate staging deployment, health checks, migration/backup plan, and rollback procedure have passed.

## Troubleshooting

- **Mirror push fails:** check that `GITLAB_MIRROR_URL` is correct, the project already exists, and the token's account has permission to push to it. Do not paste the token into logs or chat.
- **GitLab pipeline does not start:** check that the default branch name matches the GitLab project's default branch, the GitLab project contains `.gitlab-ci.yml`, and CI/CD runners are enabled.
- **Docker daemon unavailable:** confirm the runner supports Docker-in-Docker, TLS service variables are intact, and runner security settings permit it.
- **Registry authentication fails:** confirm Container Registry is enabled and the job uses GitLab's built-in registry variables. Never print their values.
- **Scan fails:** a published image may remain in the registry. Treat a red pipeline as a failed release and do not deploy that tag.
- **Image cannot start:** validate runtime configuration in staging. The image alone does not provision PostgreSQL, Redis, or Kafka.
