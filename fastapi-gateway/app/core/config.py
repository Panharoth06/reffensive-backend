import os
from functools import lru_cache

try:
    from dotenv import load_dotenv
except Exception:
    def load_dotenv(*args, **kwargs):
        return False

load_dotenv(".env")

env = os.getenv("ENVIRONMENT", "development").strip().lower()

if env == "production":
    load_dotenv(".env.prod", override=True)
else:
    load_dotenv(".env.dev", override=True)


class Settings:
    def __init__(self) -> None:
        self.environment = os.getenv("ENVIRONMENT", "development").strip().lower()
        self.keycloak_issuer = os.getenv("KEYCLOAK_ISSUER", "").strip()
        self.keycloak_audience = os.getenv("KEYCLOAK_AUDIENCE", "").strip()
        self.keycloak_audiences = self._parse_csv(self.keycloak_audience)
        self.keycloak_jwks_url = os.getenv("KEYCLOAK_JWKS_URL", "").strip()
        fastapi_client_id_alias = os.getenv("KEYCLOAK_FAST_API_CLIENT_ID", "")
        fastapi_client_secret_alias = os.getenv("KEYCLOAK_FAST_API_CLIENT_SECRET", "")
        web_client_id_alias = os.getenv("KEYCLOAK_WEB_CLIENT_ID", "")
        web_client_secret_alias = os.getenv("KEYCLOAK_WEB_CLIENT_SECRET", "")

        self.keycloak_admin_client_id = os.getenv(
            "KEYCLOAK_ADMIN_CLIENT_ID",
            fastapi_client_id_alias or web_client_id_alias,
        ).strip()
        self.keycloak_admin_client_secret = os.getenv(
            "KEYCLOAK_ADMIN_CLIENT_SECRET",
            fastapi_client_secret_alias or web_client_secret_alias,
        ).strip()
        self.keycloak_admin_token = os.getenv("KEYCLOAK_ADMIN_TOKEN", "").strip()
        self.keycloak_web_client_id = os.getenv(
            "KEYCLOAK_WEB_CLIENT_ID",
            fastapi_client_id_alias or "platform-web",
        ).strip() or "platform-web"
        raw_web_client_ids = os.getenv("KEYCLOAK_WEB_CLIENT_IDS", "").strip()
        self.keycloak_web_client_ids = self._parse_csv(raw_web_client_ids) or [self.keycloak_web_client_id]
        self.keycloak_cli_client_id = os.getenv("KEYCLOAK_CLI_CLIENT_ID", "cli-client").strip() or "cli-client"
        self.keycloak_ci_client_prefix = os.getenv("KEYCLOAK_CI_CLIENT_PREFIX", "ci-").strip() or "ci-"

        self.github_oauth_client_id = os.getenv("GITHUB_OAUTH_CLIENT_ID", "").strip()
        self.github_oauth_client_secret = os.getenv("GITHUB_OAUTH_CLIENT_SECRET", "").strip()
        self.github_oauth_authorize_url = os.getenv(
            "GITHUB_OAUTH_AUTHORIZE_URL",
            "https://github.com/login/oauth/authorize",
        ).strip() or "https://github.com/login/oauth/authorize"
        self.github_oauth_token_url = os.getenv(
            "GITHUB_OAUTH_TOKEN_URL",
            "https://github.com/login/oauth/access_token",
        ).strip() or "https://github.com/login/oauth/access_token"
        self.github_oauth_api_base_url = os.getenv(
            "GITHUB_OAUTH_API_BASE_URL",
            "https://api.github.com",
        ).strip() or "https://api.github.com"
        self.github_oauth_redirect_uri = os.getenv(
            "GITHUB_OAUTH_REDIRECT_URI",
            "http://localhost:8000/integrations/github/callback",
        ).strip() or "http://localhost:8000/integrations/github/callback"
        self.github_oauth_scope = os.getenv(
            "GITHUB_OAUTH_SCOPE",
            "read:user user:email repo",
        ).strip() or "read:user user:email repo"
        self.github_oauth_state_secret = os.getenv(
            "GITHUB_OAUTH_STATE_SECRET",
            self.keycloak_admin_client_secret,
        ).strip()
        self.github_connect_success_redirect_url = os.getenv(
            "GITHUB_CONNECT_SUCCESS_REDIRECT_URL",
            "http://localhost:3000/dashboard?git=connected",
        ).strip() or "http://localhost:3000/dashboard?git=connected"
        self.github_connect_error_redirect_url = os.getenv(
            "GITHUB_CONNECT_ERROR_REDIRECT_URL",
            "http://localhost:3000/dashboard?git=error",
        ).strip() or "http://localhost:3000/dashboard?git=error"

        self.gitlab_oauth_client_id = os.getenv("GITLAB_OAUTH_CLIENT_ID", "").strip()
        self.gitlab_oauth_client_secret = os.getenv("GITLAB_OAUTH_CLIENT_SECRET", "").strip()
        self.gitlab_oauth_authorize_url = os.getenv(
            "GITLAB_OAUTH_AUTHORIZE_URL",
            "https://gitlab.com/oauth/authorize",
        ).strip() or "https://gitlab.com/oauth/authorize"
        self.gitlab_oauth_token_url = os.getenv(
            "GITLAB_OAUTH_TOKEN_URL",
            "https://gitlab.com/oauth/token",
        ).strip() or "https://gitlab.com/oauth/token"
        self.gitlab_oauth_api_base_url = os.getenv(
            "GITLAB_OAUTH_API_BASE_URL",
            "https://gitlab.com/api/v4",
        ).strip() or "https://gitlab.com/api/v4"
        self.gitlab_oauth_redirect_uri = os.getenv(
            "GITLAB_OAUTH_REDIRECT_URI",
            "http://localhost:8000/integrations/gitlab/callback",
        ).strip() or "http://localhost:8000/integrations/gitlab/callback"
        self.gitlab_oauth_scope = os.getenv(
            "GITLAB_OAUTH_SCOPE",
            "read_user read_api",
        ).strip() or "read_user read_api"
        self.gitlab_oauth_state_secret = os.getenv(
            "GITLAB_OAUTH_STATE_SECRET",
            self.keycloak_admin_client_secret,
        ).strip()
        self.gitlab_connect_success_redirect_url = os.getenv(
            "GITLAB_CONNECT_SUCCESS_REDIRECT_URL",
            "http://localhost:3000/dashboard?git=connected",
        ).strip() or "http://localhost:3000/dashboard?git=connected"
        self.gitlab_connect_error_redirect_url = os.getenv(
            "GITLAB_CONNECT_ERROR_REDIRECT_URL",
            "http://localhost:3000/dashboard?git=error",
        ).strip() or "http://localhost:3000/dashboard?git=error"

        sonar_base_url = os.getenv("SONARQUBE_BASE_URL", "").strip().rstrip("/")
        sonar_host = os.getenv("SONARQUBE_HOST", "").strip().rstrip("/")
        self.sonarqube_base_url = sonar_base_url or sonar_host
        self.sonarqube_host = self.sonarqube_base_url
        self.sonarqube_token = os.getenv("SONARQUBE_TOKEN", "").strip()
        self.sonar_scanner_bin = os.getenv("SONAR_SCANNER_BIN", "sonar-scanner").strip() or "sonar-scanner"
        self.trivy_bin = os.getenv("TRIVY_BIN", os.getenv("OSV_SCANNER_BIN", "trivy")).strip() or "trivy"
        self.trivy_scan_timeout_seconds = int(
            os.getenv("TRIVY_SCAN_TIMEOUT_SECONDS", os.getenv("OSV_SCAN_TIMEOUT_SECONDS", "600"))
        )
        self.sonar_scan_tmp_root = os.getenv("SONAR_SCAN_TMP_ROOT", "/tmp/aof-sonar").strip() or "/tmp/aof-sonar"
        self.sonar_scan_timeout_seconds = int(os.getenv("SONAR_SCAN_TIMEOUT_SECONDS", "1200"))
        self.sonar_ce_poll_timeout_seconds = int(os.getenv("SONAR_CE_POLL_TIMEOUT_SECONDS", "180"))
        self.report_pdf_timezone = os.getenv("REPORT_PDF_TIMEZONE", "UTC").strip() or "UTC"
        self.report_pdf_author = os.getenv("REPORT_PDF_AUTHOR", "Auto Offensive Platform").strip() or "Auto Offensive Platform"
        self.report_pdf_title_prefix = os.getenv("REPORT_PDF_TITLE_PREFIX", "Code Quality Report").strip() or "Code Quality Report"
        self.report_temp_dir = os.getenv("REPORT_TEMP_DIR", "/tmp/aof-reports").strip() or "/tmp/aof-reports"

        self.minio_endpoint = os.getenv("MINIO_ENDPOINT", "").strip()
        self.minio_access_key = os.getenv("MINIO_ACCESS_KEY", "").strip()
        self.minio_secret_key = os.getenv("MINIO_SECRET_KEY", "").strip()
        self.minio_bucket = os.getenv("MINIO_BUCKET", "aof-reports").strip() or "aof-reports"
        self.minio_region = os.getenv("MINIO_REGION", "us-east-1").strip() or "us-east-1"
        self.minio_use_ssl = self._env_bool("MINIO_USE_SSL", False)
        self.minio_secure_public_base_url = os.getenv("MINIO_PUBLIC_BASE_URL", "").strip().rstrip("/")
        self.minio_presigned_expiry_seconds = self._env_int("MINIO_PRESIGNED_EXPIRY_SECONDS", 3600, 60)

        self.grpc_server_addr = os.getenv("GRPC_SERVER_ADDR", "localhost:50051").strip() or "localhost:50051"
        self.redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0").strip() or "redis://localhost:6379/0"
        self.database_url = self._build_database_url()
        self.scan_executor_workers = int(os.getenv("SCAN_EXECUTOR_WORKERS", "4"))
        self.scan_stream_poll_interval = float(os.getenv("SCAN_STREAM_POLL_INTERVAL", "0.5"))

        if self.keycloak_issuer and not self.keycloak_jwks_url:
            self.keycloak_jwks_url = (
                f"{self.keycloak_issuer.rstrip('/')}/protocol/openid-connect/certs"
            )

    def _build_database_url(self) -> str:
        return os.getenv("DATABASE_URL", "").strip()

    def _parse_csv(self, raw: str) -> list[str]:
        if not raw:
            return []
        values = [part.strip() for part in raw.split(",")]
        return [value for value in values if value]

    def _env_bool(self, key: str, default: bool) -> bool:
        raw = os.getenv(key, "").strip().lower()
        if raw in {"1", "true", "yes", "on"}:
            return True
        if raw in {"0", "false", "no", "off"}:
            return False
        return default

    def _env_int(self, key: str, default: int, minimum: int) -> int:
        raw = os.getenv(key, "").strip()
        if not raw:
            return default
        try:
            value = int(raw)
        except ValueError:
            return default
        if value < minimum:
            return minimum
        return value


@lru_cache
def get_settings() -> Settings:
    return Settings()
