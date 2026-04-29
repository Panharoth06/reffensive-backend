# Dependencies Module

## Overview

The `dependencies` module is the authentication and authorization layer for the FastAPI gateway. It provides a composable set of FastAPI dependency-injectable functions that handle identity verification, user provisioning, role-based access control (RBAC), and resource-level permission checks.

## What It Does

The module implements a two-tier security model:

### 1. Authentication (`auth.py`)

Validates the identity of incoming requests through two mechanisms:

- **JWT Bearer Token Authentication** -- Parses JWT tokens issued by Keycloak (or dev-mode fallback), extracts claims including roles, scopes, and authorized party, and builds a `CurrentUser` object.
- **API Key Authentication** -- Validates API keys passed via the `X-API-Key` header or as a raw Bearer token value against the core service.

After authentication, the module ensures the user exists in the core gRPC service, auto-provisioning if necessary.

### 2. Authorization (`rbac.py` + `auth.py`)

Enforces access control at multiple levels:

- **Actor Type Enforcement** -- Restricts endpoints to specific client types: `web_user`, `cli_user`, or `api_key`.
- **Role-Based Access Control** -- Checks platform-level roles (`USER`, `ADMIN`) extracted from Keycloak realm or resource-level roles.
- **Resource-Level Permissions** -- Implements the self-or-admin pattern, allowing users to access their own resources or admins to act on behalf of others.
- **Scan-Specific Permissions** -- Specialized guards for scan endpoints that restrict access to non-admin users with the `USER` role, and block API keys from destructive scan operations.

## Why We Need It

Centralizing authentication and authorization in this module provides several critical benefits:

- **Consistency** -- All route handlers use the same identity and permission logic, eliminating duplicate or conflicting implementations across endpoints.
- **Separation of Concerns** -- Route handlers focus on business logic; security concerns are declaratively expressed via dependency injection.
- **Composability** -- Dependencies are factories that return other dependencies, enabling fine-grained access control by combining primitives (e.g., "web user with ADMIN role" or "any actor type with USER role").
- **Maintainability** -- Changes to auth flows, role extraction, or permission logic are made in one place and propagate to all consumers.

## When It Is Needed

Every protected endpoint in the FastAPI gateway consumes one or more dependencies from this module. Specifically:

| Scenario | Dependency Used |
|---|---|
| Verify any authenticated platform user | `require_platform_user` |
| Restrict to web users only | `require_web_user` |
| Restrict to web or CLI users with platform role | `require_web_or_cli_platform_user` |
| Admin-only web endpoints | `require_web_admin` |
| Basic scan endpoints (identity only, no role check) | `get_scan_current_user` |
| Scan endpoints with role enforcement | `require_scan_permission` |
| Destructive scan endpoints (no API keys) | `require_user_scan_permission` |
| API key management | `require_web_or_cli_platform_user` |
| User self-management or admin override | `ensure_self_or_admin`, `resolve_effective_user_id` |
| Category management (web only, no role check) | `require_web_user` |

## Architecture

### Authentication Flow

```mermaid
flowchart TD
    A[HTTP Request] --> B{X-API-Key header\nor raw Bearer token?}
    B -->|Yes| C[Validate API Key\nvia Core gRPC Service]
    B -->|No| D[Extract JWT Bearer Token]
    D --> E{Dev Mode?}
    E -->|Yes| F[Return Dev Claims]
    E -->|No| G{Keycloak Configured?}
    G -->|Yes| H[Verify Token via Keycloak]
    G -->|No| I[Parse JWT Without Verification]
    H --> J[Extract Claims:\nroles, scopes, azp]
    I --> J
    F --> J
    C --> K[Build CurrentUser\nactor_type = api_key]
    J --> L[Build CurrentUser\nactor_type = web_user / cli_user]
    L --> M{User Exists\nin Core Service?}
    M -->|No| N[Auto-Provision User]
    M -->|Yes| O[Return CurrentUser]
    N --> O
    K --> P{User Exists\nin Core Service?}
    P -->|No| Q[Raise 403]
    P -->|Yes| O
```

### Authorization Flow

```mermaid
flowchart TD
    A[Endpoint Requires Auth] --> B[get_current_user]
    B --> C{Actor Type Check}
    C -->|require_web_user| D[actor_type == web_user?]
    C -->|require_cli_user| E[actor_type == cli_user?]
    C -->|require_api_key_client| F[actor_type == api_key?]
    C -->|require_web_or_cli_user| G[actor_type in web_user, cli_user?]
    C -->|require_all_clients| H[any actor type?]
    D --> I{Pass?}
    E --> I
    F --> I
    G --> I
    H --> I
    I -->|No| J[403 Forbidden]
    I -->|Yes| K{Role Check Required?}
    K -->|No| L[Resource-Level Check?]
    K -->|Yes| M[has_any_role]
    M --> N{User has any\nrequired role?}
    N -->|No| J
    N -->|Yes| L
    L --> O{Self or Admin?}
    O -->|Self| P[Allow]
    O -->|Admin| P
    O -->|Other User, Not Admin| J
```

### Module Structure

```mermaid
flowchart LR
    subgraph Dependencies
        A[auth.py]
        B[rbac.py]
        C[__init__.py]
    end

    A -->|exports| A1[CurrentUser]
    A -->|exports| A2[get_current_user]
    A -->|exports| A3[require_*_user]
    A -->|exports| A4[require_scan_permission]

    B -->|uses| A
    B -->|exports| B1[require_roles]
    B -->|exports| B2[require_web_roles]
    B -->|exports| B3[ensure_self_or_admin]
    B -->|exports| B4[resolve_effective_user_id]

    C -->|re-exports| A
    C -->|re-exports| B

    style A fill:#1a1a2e,color:#e0e0e0
    style B fill:#16213e,color:#e0e0e0
    style C fill:#0f3460,color:#e0e0e0
    style A1 fill:#533483,color:#ffffff
    style A2 fill:#533483,color:#ffffff
    style A3 fill:#533483,color:#ffffff
    style A4 fill:#533483,color:#ffffff
    style B1 fill:#533483,color:#ffffff
    style B2 fill:#533483,color:#ffffff
    style B3 fill:#533483,color:#ffffff
    style B4 fill:#533483,color:#ffffff
```

## Key Components

### `CurrentUser` Dataclass

Represents an authenticated and resolved user identity.

| Field | Type | Description |
|---|---|---|
| `user_id` | `str` | Unique identifier from the identity provider |
| `azp` | `str` | Authorized party (client ID that issued the token) |
| `actor_type` | `ActorType` | One of `web_user`, `cli_user`, `api_key` |
| `roles` | `list[str]` | Normalized uppercase roles from Keycloak |
| `scopes` | `list[str]` | OAuth scopes from the token |
| `claims` | `dict` | Raw JWT claims |
| `project_id` | `str | None` | Associated project (for API key users) |
| `api_key_id` | `str | None` | API key identifier (for API key users) |
| `auth_method` | `str` | How the user was authenticated |

### Authentication Dependencies

| Dependency | Description |
|---|---|
| `get_current_user` | Primary entry point. Detects API key or JWT, builds `CurrentUser`, ensures user exists in core service |
| `get_current_claims` | Extracts raw JWT claims from HTTP Bearer credentials |

### Actor Type Restrictions

| Dependency | Allowed Actor Types |
|---|---|
| `require_web_user` | `web_user` only |
| `require_cli_user` | `cli_user` only |
| `require_api_key_client` | `api_key` only |
| `require_web_or_cli_user` | `web_user`, `cli_user` |
| `require_all_clients` | `web_user`, `cli_user`, `api_key` |

### Role-Based Access Control

| Dependency | Role Requirement | Actor Type Restriction |
|---|---|---|
| `require_platform_user` | `USER` or `ADMIN` | Any |
| `require_web_platform_user` | `USER` or `ADMIN` | `web_user` only |
| `require_web_or_cli_platform_user` | `USER` or `ADMIN` | `web_user`, `cli_user` |
| `require_web_admin` | `ADMIN` only | `web_user` only |

### Scan-Specific Permissions

| Dependency | Description |
|---|---|
| `require_scan_permission` | Allows API keys; requires `USER` or `ADMIN` role for web/CLI scan access |
| `require_user_scan_permission` | Same as above, but blocks API keys entirely (for destructive scan actions) |

### Resource-Level Helpers

| Helper | Description |
|---|---|
| `ensure_self_or_admin(current_user, target_user_id)` | Raises 403 unless the current user is accessing their own resources or is an `ADMIN` |
| `resolve_effective_user_id(current_user, requested_user_id)` | Returns the requested user ID if the current user is `ADMIN`; otherwise returns the current user's own ID |

## Usage Example

```python
from fastapi import APIRouter, Depends
from app.dependencies import CurrentUser, require_web_platform_user, ensure_self_or_admin

router = APIRouter()

@router.get("/users/{user_id}")
def get_user(
    user_id: str,
    current_user: CurrentUser = Depends(require_web_platform_user),
):
    ensure_self_or_admin(current_user, user_id)
    # ... business logic
```

## Router Consumption

Dependencies from this module are consumed across 9 router files:

| Router | Dependencies Used |
|---|---|
| `routers/apikey_router.py` | `CurrentUser`, `require_web_or_cli_platform_user` |
| `routers/auth.py` | `CurrentUser`, `require_platform_user` |
| `routers/project_router.py` | `CurrentUser`, `require_web_or_cli_platform_user` |
| `routers/category_router.py` | `CurrentUser`, `require_web_user` |
| `routers/users.py` | `CurrentUser`, `PLATFORM_ROLE_USER`, `ensure_self_or_admin`, `require_web_admin`, `require_web_platform_user` |
| `routers/integrations_git_account.py` | `CurrentUser`, `require_web_platform_user`, `resolve_effective_user_id` |
| `routers/tool_router.py` | `CurrentUser`, `require_scan_permission`, `require_web_user`, `ensure_self_or_admin` |
| `routers/basic_scan_router.py` | `CurrentUser`, `get_scan_current_user` |
| `routers/medium_scan_router.py` | `CurrentUser`, `require_scan_permission` |
| `routers/scan_router.py` | `CurrentUser`, `require_scan_permission`, `require_user_scan_permission` |
| `routers/sonarqube.py` | `PLATFORM_ROLE_ADMIN`, `CurrentUser`, `has_any_role`, `require_web_platform_user` |
