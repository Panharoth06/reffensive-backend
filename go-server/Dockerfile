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

FROM golang:1.26-alpine AS builder

RUN apk add --no-cache protobuf protobuf-dev

WORKDIR /src

COPY proto ./proto
COPY go-server/go.mod go-server/go.sum ./go-server/

WORKDIR /src/go-server

RUN go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.36.11 && \
    go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.6.1

ENV PATH="/go/bin:${PATH}"

RUN go mod download
ARG GOPROXY=https://proxy.golang.org,https://goproxy.cn,https://goproxy.io,direct
ARG GOSUMDB=sum.golang.org
ENV GOPROXY=${GOPROXY}
ENV GOSUMDB=${GOSUMDB}

COPY go.mod ./
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
    && ln -s /root/go/bin/protoc-gen-go /usr/bin/ \
    && ln -s /root/go/bin/protoc-gen-go-grpc /usr/bin/

WORKDIR /src

COPY Makefile ./

RUN make proto-go

WORKDIR /src/go-server

COPY . .
COPY go-server/ ./
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/go-server ./cmd
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/go-server ./cmd/server && \
    CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/sonarqube-worker ./cmd/sonarqube-worker

# ── runtime ───────────────────────────────────────────────────────────────
FROM alpine:3.23 AS runtime

ARG nmap_ver=7.98
ARG sonar_scanner_ver=7.2.0.5079
ARG dependency_check_ver=12.1.0

# Runtime libs nmap needs
RUN apk add --no-cache \
        ca-certificates \
        git \
        libgcc libstdc++ \
        libcrypto3 libssl3 \
        libpcap \
        libssh2 \
        lua5.4-libs \
        zlib \
        bash \
        curl \
        unzip \
        openjdk17-jre \
    && update-ca-certificates

# # Build nmap from source (same as your scanner Dockerfile)
# RUN apk add --no-cache --virtual .build-deps \
#         linux-headers openssl-dev libpcap-dev libssh2-dev \
#         lua5.4-dev pcre-dev zlib-dev \
#         autoconf automake g++ libtool make curl \
#     && curl -fL -o /tmp/nmap.tar.bz2 \
#         https://nmap.org/dist/nmap-${nmap_ver}.tar.bz2 \
#     && tar -xjf /tmp/nmap.tar.bz2 -C /tmp \
#     && cd /tmp/nmap* \
#     && sed -i '22,25d' libdnet-stripped/acconfig.h \
#     && autoreconf libpcre libdnet-stripped -ivf \
#     && ./configure \
#         --prefix=/usr \
#         --without-zenmap \
#         --without-nmap-update \
#         --with-liblua=/usr/lua5.4 \
#         --with-libpcap=yes --with-libpcre=yes \
#         --with-libssh2=yes --with-libz=yes --with-openssl=yes \
#     && make && make install \
#     && apk del .build-deps \
#     && rm -rf /var/cache/apk/* /tmp/nmap*

# Install Trivy - pre-download database to avoid download failures at runtime
RUN curl -sSfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin && \
    trivy image --download-db-only || echo "Warning: Could not download Trivy DB during build (offline mode will be used)"

# Install SonarQube Scanner
RUN curl -fsSL -o /tmp/sonar-scanner.zip "https://binaries.sonarsource.com/Distribution/sonar-scanner-cli/sonar-scanner-cli-${sonar_scanner_ver}.zip" && \
    unzip -q /tmp/sonar-scanner.zip -d /opt && \
    ln -sf "/opt/sonar-scanner-${sonar_scanner_ver}/bin/sonar-scanner" /usr/local/bin/sonar-scanner && \
    curl -fsSL -o /tmp/dependency-check.zip "https://github.com/jeremylong/DependencyCheck/releases/download/v${dependency_check_ver}/dependency-check-${dependency_check_ver}-release.zip" && \
    unzip -q /tmp/dependency-check.zip -d /opt && \
    ln -sf /opt/dependency-check/bin/dependency-check.sh /usr/local/bin/dependency-check.sh && \
    rm -f /tmp/sonar-scanner.zip /tmp/dependency-check.zip && \
    chmod +x /opt/dependency-check/bin/dependency-check.sh

# Pre-download OWASP Dependency-Check NVD database to avoid timeout at runtime
RUN mkdir -p /root/.m2/repository/org/owasp/dependency-check/data && \
    /opt/dependency-check/bin/dependency-check.sh --updateonly --data /root/.m2/repository/org/owasp/dependency-check/data 2>&1 || \
    echo "Warning: Could not pre-download NVD database (will retry at runtime)"

# Create cache directories with proper permissions
RUN mkdir -p /root/.cache/trivy && chmod -R 777 /root/.cache/trivy && \
    mkdir -p /root/.m2/repository/org/owasp/dependency-check/data && chmod -R 777 /root/.m2/repository

COPY --from=builder /out/go-server /go-server
COPY --from=builder /out/sonarqube-worker /sonarqube-worker

EXPOSE 50051
ENTRYPOINT ["/go-server"]
