FROM python:3.13-slim AS builder

COPY --from=ghcr.io/astral-sh/uv:0.7.2 /uv /uvx /usr/local/bin/

# Copy the entire repo so we have access to proto/ and fastapi-gateway/
WORKDIR /build
COPY . .

# Work directly at the final runtime path (/app) so that .venv shebangs
# point to /app/.venv/bin/python — the correct path in the runtime image.
WORKDIR /app
RUN cp -r /build/fastapi-gateway/. .

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    make \
    protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

# Install dependencies — venv created at /app/.venv with correct shebangs
RUN uv sync --frozen --no-dev

# Generate protobuf stubs using the same logic as local dev
RUN mkdir -p app/gen && \
    find app/gen -type f \( -name '*_pb2.py' -o -name '*_pb2_grpc.py' \) -delete && \
    touch app/gen/__init__.py && \
    UV_CACHE_DIR=/tmp/uv-cache uv run python -m grpc_tools.protoc -I/build/proto \
        --python_out=app/gen \
        --grpc_python_out=app/gen \
        /build/proto/*.proto && \
    find app/gen -name '*_pb2_grpc.py' -type f -exec sed -i -E 's/^import ([a-zA-Z0-9_]+_pb2) as /from . import \1 as /' {} +

# Create missing __init__.py files for package initialization
RUN touch __init__.py && \
    touch app/__init__.py

# ── Runtime ──────────────────────────────────────────────
FROM python:3.13-slim AS runtime

COPY --from=ghcr.io/astral-sh/uv:0.7.2 /uv /usr/local/bin/

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/app/.venv/bin:$PATH"

COPY --from=builder /app/.venv /app/.venv
COPY --from=builder /app /app

RUN uv run python -c "import app.gen.api_key_pb2; print('GEN OK')"

EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]