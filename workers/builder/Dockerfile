FROM docker:27-cli AS dockercli

FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    gcc \
    git \
    gnupg \
    g++ \
    tar \
    unzip \
    && rm -rf /var/lib/apt/lists/*

COPY --from=dockercli /usr/local/bin/docker /usr/local/bin/docker

RUN curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin
RUN curl -sSfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin
RUN curl -sSfL https://raw.githubusercontent.com/sigstore/cosign/main/install.sh | sh -s -- -b /usr/local/bin

COPY workers/builder/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Generate protos in the root so "from proto import ..." works
COPY proto/ /proto/
RUN mkdir -p proto && \
    python -m grpc_tools.protoc \
      -I/proto \
      --python_out=. \
      --grpc_python_out=. \
      /proto/create_tool.proto && \
    touch proto/__init__.py

COPY workers/builder/ .

CMD ["python", "-u", "worker_main.py"]
