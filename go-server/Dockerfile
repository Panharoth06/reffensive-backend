# FROM golang:1.26 AS builder
# WORKDIR /app

# COPY go.mod go.sum ./
# RUN go mod download

# COPY . .
# RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/go-server ./cmd

# FROM gcr.io/distroless/static-debian12:nonroot
# COPY --from=builder /out/go-server /go-server
# EXPOSE 50051
# USER nonroot:nonroot
# ENTRYPOINT ["/go-server"]

# syntax=docker/dockerfile:1.7

FROM golang:1.26-alpine AS builder

RUN apk add --no-cache protobuf protobuf-dev

WORKDIR /src

COPY proto ./proto
COPY go-server/go.mod go-server/go.sum ./go-server/

WORKDIR /src/go-server

RUN go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.36.11 && \
    go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.6.1

ENV PATH="/go/bin:${PATH}"
ARG GOPROXY=https://proxy.golang.org,https://goproxy.cn,https://goproxy.io,direct
ARG GOSUMDB=sum.golang.org
ENV GOPROXY=${GOPROXY}
ENV GOSUMDB=${GOSUMDB}

RUN set -eux; \
    i=1; \
    until [ "$i" -gt 5 ]; do \
      go mod download && break; \
      echo "go mod download failed (attempt ${i}/5), retrying..." >&2; \
      i=$((i+1)); \
      sleep 3; \
    done; \
    if [ "$i" -gt 5 ]; then \
      echo "go mod download failed after 5 attempts" >&2; \
      exit 1; \
    fi

RUN apk add --no-cache make bash git protoc protobuf-dev \
    && go install google.golang.org/protobuf/cmd/protoc-gen-go@latest \
    && go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest \
    && go install golang.org/x/vuln/cmd/govulncheck@latest \
    && ln -s /root/go/bin/protoc-gen-go /usr/bin/ \
    && ln -s /root/go/bin/protoc-gen-go-grpc /usr/bin/

WORKDIR /src

COPY Makefile ./

RUN make proto-go

WORKDIR /src/go-server

COPY go-server/ ./
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/go-server ./cmd
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/go-server ./cmd/server && \
    CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/sonarqube-worker ./cmd/sonarqube-worker

# ── runtime ───────────────────────────────────────────────────────────────
FROM swift:6.2.3-jammy AS runtime

ARG sonar_scanner_ver=7.2.0.5079

ENV DEBIAN_FRONTEND=noninteractive
ENV DOTNET_ROOT="/root/.dotnet"
ENV PATH="/root/.cargo/bin:/root/.dotnet:${PATH}"

RUN apt-get update && apt-get install -y --no-install-recommends \
        bash \
        build-essential \
        ca-certificates \
        curl \
        git \
        gnupg \
        libicu70 \
        libssl3 \
        maven \
        gradle \
        nodejs \
        npm \
        openjdk-17-jdk-headless \
        php-cli \
        python3 \
        python3-pip \
        python3-venv \
        ruby-full \
        unzip \
        wget \
        zlib1g \
    && rm -rf /var/lib/apt/lists/*

RUN python3 -m venv /opt/pip-tools && \
    /opt/pip-tools/bin/pip install --no-cache-dir --upgrade pip && \
    /opt/pip-tools/bin/pip install --no-cache-dir pip-audit && \
    ln -sf /opt/pip-tools/bin/pip-audit /usr/local/bin/pip-audit

RUN curl -fsSL https://getcomposer.org/installer -o /tmp/composer-setup.php && \
    php /tmp/composer-setup.php --install-dir=/usr/local/bin --filename=composer && \
    rm -f /tmp/composer-setup.php

RUN curl -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable && \
    cargo install cargo-audit --locked

RUN gem install bundler-audit --no-document

RUN curl -fsSL https://dot.net/v1/dotnet-install.sh -o /tmp/dotnet-install.sh && \
    bash /tmp/dotnet-install.sh --channel 8.0 --install-dir /root/.dotnet && \
    rm -f /tmp/dotnet-install.sh

RUN wget -qO- https://dl-ssl.google.com/linux/linux_signing_key.pub | gpg --dearmor -o /usr/share/keyrings/dart.gpg && \
    echo "deb [signed-by=/usr/share/keyrings/dart.gpg arch=amd64] https://storage.googleapis.com/download.dartlang.org/linux/debian stable main" > /etc/apt/sources.list.d/dart_stable.list && \
    apt-get update && apt-get install -y --no-install-recommends dart && \
    rm -rf /var/lib/apt/lists/*

RUN curl -fsSL -o /tmp/sonar-scanner.zip "https://binaries.sonarsource.com/Distribution/sonar-scanner-cli/sonar-scanner-cli-${sonar_scanner_ver}.zip" && \
    unzip -q /tmp/sonar-scanner.zip -d /opt && \
    ln -sf "/opt/sonar-scanner-${sonar_scanner_ver}/bin/sonar-scanner" /usr/local/bin/sonar-scanner && \
    rm -f /tmp/sonar-scanner.zip

COPY --from=builder /out/go-server /go-server
COPY --from=builder /out/sonarqube-worker /sonarqube-worker
COPY --from=builder /go/bin/govulncheck /usr/local/bin/govulncheck

EXPOSE 50051
ENTRYPOINT ["/go-server"]
