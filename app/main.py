"""xiezhi API: a small service built to practice secure-by-design engineering."""

from fastapi import FastAPI

# Interactive docs (/docs, /redoc, /openapi.json) are off: they expose the full API surface
# to anyone and aren't needed in production.
app = FastAPI(title="xiezhi", docs_url="/docs", redoc_url=None, openapi_url=None)


@app.get("/healthz")
def healthz() -> dict[str, str]:
    """Liveness check for the container platform (Kubernetes / ECS)."""
    return {"status": "ok"}
