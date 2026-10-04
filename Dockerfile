# Base image pinned by digest (the tag is for humans): a tag can be moved to a different image,
# a digest can't. Dependabot/Renovate will propose bumps as PRs that go through the CI gate.
FROM python:3.13-slim@sha256:3dd7cc108ec1493442514f5c2a871af6af0ec31d768ff6e378a93340c3b3db5f

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Dedicated unprivileged user with a numeric UID: a compromised app process is not root in the
# container, and Kubernetes can verify runAsNonRoot from a numeric UID (it can't from a name).
RUN groupadd --system --gid 10001 app \
 && useradd --system --uid 10001 --gid app --no-create-home app

# Dependencies first (cached layer), installed only if every package matches its locked hash:
# what was audited is exactly what ships. pip is then removed: the app never runs it, it carries
# its own vendored packages that the lockfile can't see (found by the image scan), and it would
# let an attacker with code execution install more tools.
COPY requirements.txt .
RUN pip install --require-hashes -r requirements.txt \
 && pip uninstall -y pip

COPY app/ ./app/

USER 10001:10001
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
