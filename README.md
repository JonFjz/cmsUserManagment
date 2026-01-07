# CMS User Managment

Lightweight ASP.NET Core API that provides authentication and user management features for a CMS. Implemented features include JWT authentication, refresh tokens, role-based authorization, two-factor authentication (TOTP / Google Authenticator), Redis-backed caching, and MySQL persistence.

Key features

- Login / Register (email + password)
- Two-factor authentication (TOTP): generate setup code, confirm, login with 2FA, disable 2FA
- JWT access tokens with refresh token flow
- Role-based endpoints (admin) for user management: list, get, search, update, delete, bulk delete
- Redis used for caching/session-like scenarios
- Swagger UI available for manual API exploration

Projects

- `cmsUserManagment.API` - ASP.NET Core Web API (entry point)
- `cmsUserManagment.Application` - DTOs, services interfaces, settings, validation
- `cmsUserManagment.Domain` - domain entities
- `cmsUserManagment.Infrastructure` - EF Core `AppDbContext`, repositories, security helpers

Prerequisites

- .NET SDK 8.0 (see `global.json`)
- MySQL 8+ (or use provided Docker Compose)
- Redis (or use provided Docker Compose)
- (optional) `dotnet-ef` if you want to run EF migrations locally

Configuration

Configuration lives in `appsettings.json` or via environment variables. Important keys:

- `ConnectionStrings:DefaultConnection` — MySQL connection string
- `Redis:Connection` — Redis host:port
- `JwtSettings:Secret` — symmetric secret used to sign JWTs
- `JwtSettings:Issuer` and `JwtSettings:Audience` — token issuer/audience
- `JwtSettings:ExpiryMinutes` — access token expiry minutes

The included `compose.yaml` demonstrates how to pass these settings as environment variables (e.g. `ConnectionStrings__DefaultConnection`, `Redis__Connection`, `JwtSettings__Secret`, ...).

Running

Locally (development):

1. Restore & build

```bash
dotnet restore
dotnet build
```

2. Run the API

```bash
cd cmsUserManagment.API
dotnet run
```

The API exposes Swagger UI at `/swagger` (e.g. `http://localhost:5000/swagger` depending on Kestrel binding).

With Docker Compose (recommended for full stack: MySQL + Redis):

```bash
docker compose up --build
```

By default `compose.yaml` maps the API to port `5054` (so Swagger would be at `http://localhost:5054/swagger`).

Authentication & Authorization

- The API uses JWT Bearer authentication. Include the access token in the `Authorization: Bearer <token>` header for protected endpoints.
- `UserManagementController` endpoints require the `admin` role.

API Endpoints (summary)

Auth endpoints (base: `/api/User`)

- `POST /api/User/register` — register a new user (public). Body: `RegisterUser` DTO.
- `GET /api/User/login?email={email}&password={password}` — login and receive JWT + refresh token
- `POST /api/User/logout` — logout (body: refresh token GUID)
- `GET /api/User/refresh-token?refreshToken={guid}` — exchange refresh token for new access token
- `POST /api/User/generate-two-factor-auth-code` — generate TOTP setup code (returns `SetupCode`) (authenticated)
- `POST /api/User/two-factor-auth-confirm` — confirm TOTP code (body: code)
- `DELETE /api/User/disable-two-factor-auth` — disable 2FA for current user
- `POST /api/User/login-with-two-factor-auth?loginId={id}&code={code}` — login using 2FA
- `PUT /api/User/update-account` — update account (body: `UpdateAccountRequest`)
- `GET /api/User/account-info` — get current account info
- `GET /api/User/VerifyUser` — returns current user id (authenticated)

User management endpoints (admin only, base: `/api/UserManagement`)

- `GET /api/UserManagement` — list all users
- `GET /api/UserManagement/{id}` — get user by id
- `GET /api/UserManagement/search?username=&email=&isAdmin=&orderBy=&descending=` — search users
- `PUT /api/UserManagement/{id}` — update user (body: `UpdateUserDto`)
- `DELETE /api/UserManagement/{id}` — delete user
- `POST /api/UserManagement/delete-bulk` — delete multiple users (body: array of GUIDs)

Notes & development tips

- The project uses EF Core migrations (see `cmsUserManagment.Infrastructure/Migrations`). If running locally against a fresh DB run migrations or use Docker Compose that provisions MySQL.
- 2FA implementation uses `Google.Authenticator` (TOTP). The `GenerateTwoFactorAuthSetupCode` endpoint returns a `SetupCode` that can be used by authenticator apps.
- Swagger is configured with a Bearer security definition so you can paste a JWT into Swagger UI to call protected endpoints.
- Secrets (JWT secret, DB password) are present in `appsettings.json` for convenience in this repo — do not use these in production. Use environment variables or a secret manager instead.

Contact / Contributing

If you want changes or run into issues, open a PR or issue in the repository. For quick local work, run with Docker Compose to boot MySQL + Redis and the API together.

License

This repository does not include an explicit license file. Add one if you plan to publish or share the code.
