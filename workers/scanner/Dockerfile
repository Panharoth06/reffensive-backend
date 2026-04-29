FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends gcc g++ && rm -rf /var/lib/apt/lists/*

COPY workers/scanner/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY proto/ /proto/
RUN mkdir -p proto && \
    python -m grpc_tools.protoc \
      -I/proto \
      --python_out=. \
      --grpc_python_out=. \
      /proto/tool.proto && \
    touch proto/__init__.py

COPY workers/scanner/ .

CMD ["python", "-u", "worker_main.py"]