# SecureGate-Nexus

A cybersecurity-focused Spring Boot application for studying JWT authentication, common token vulnerabilities, and production-grade mitigation patterns. SecureGate-Nexus demonstrates how proactive filter chains, strict payload design, and distributed token revocation harden APIs against real-world JWT attacks—including the infamous **Algorithm: `none`** exploit.

Built for portfolio review, security labs, and backend engineering best practices using **Java 21** and **Spring Boot 3**.

---

## Table of Contents

- [Project Overview](#project-overview)
- [Key Features](#key-features)
- [Tech Stack](#tech-stack)
- [Architecture](#architecture)
- [Security Scenarios & Vulnerability Testing](#security-scenarios--vulnerability-testing)
- [Installation & Setup](#installation--setup)
- [Web UI (Security Lab)](#web-ui-security-lab)
- [API Endpoints](#api-endpoints)
- [Configuration Reference](#configuration-reference)
- [Project Structure](#project-structure)
- [Contributing](#contributing)
- [License](#license)

---

## Project Overview

**SecureGate-Nexus** is a single-module monolithic Spring Boot API that acts as a hands-on security gateway. It issues RSA-signed JWTs, enforces a three-stage authentication filter chain, and ships with an integrated browser-based **Token Lab** for manual vulnerability testing.

The project is designed to answer two questions every backend engineer should be able to address:

1. **How do JWT implementations fail?** (algorithm confusion, unsigned tokens, bloated payloads, missing revocation)
2. **How do you defend against those failures?** (proactive header validation, RS256-only policy, Redis blacklist, minimal claims)

User credentials are stored in an in-memory repository (suitable for demos and labs). Tokens are signed with **RSA-2048** via **JJWT**, and revocation state is persisted in **Redis**.

---

## Key Features

| Feature | Description |
|---------|-------------|
| **Java 21** | Modern LTS runtime with strict compiler `release 21` enforcement |
| **Spring Boot 3.5** | Web, Security, Validation, and Redis auto-configuration |
| **Role-Based Access Control (RBAC)** | Roles embedded in JWT `scope` claim; admin routes require `ROLE_ADMIN` |
| **Algorithm: `none` Attack Simulation** | Web UI injects `alg: none` headers; backend blocks before signature verification |
| **Redis Token Blacklisting** | Instant logout/revocation via `blacklist:<jti>` keys with matching TTL |
| **Proactive Filter Chain** | Algorithm → Blacklist → Signature verification (ordered pipeline) |
| **Strict JWT Payload** | Only public claims: `sub`, `scope`, `jti`, `iat`, `exp` — no PII |
| **Integrated Security Lab UI** | Multi-view SPA (`index.html` / `app.js`) for register, login, token generation, and attack testing |
| **CORS Hardening** | Explicit allow-list for local front-end origins |
| **Auto RSA Key Management** | 2048-bit key pair generated on first startup if `keys/` PEM files are absent |

---

## Tech Stack

| Layer | Technology |
|-------|------------|
| Language | Java 21 |
| Framework | Spring Boot 3.5.x |
| Security | Spring Security 6 (stateless, CSRF disabled for API) |
| Token Library | [io.jsonwebtoken (JJWT)](https://github.com/jwtk/jjwt) 0.11.5 (`jjwt-api`, `jjwt-impl`, `jjwt-jackson`) |
| Caching / Revocation | Spring Data Redis + Lettuce connection pool |
| Signing Algorithm | RS256 (RSA-2048 asymmetric keys) |
| Password Hashing | BCrypt (`BCryptPasswordEncoder`) |
| Validation | Jakarta Bean Validation |
| Build Tool | Maven 3.9 (wrapper included) |
| Front-End Lab | Static HTML + Tailwind CSS CDN + vanilla JavaScript |

> **Note:** This project intentionally uses an **in-memory `ConcurrentHashMap`** for user and order storage during demos. It does **not** use Spring Data JPA. Swap in a database adapter for production deployments.

---

## Architecture

### Security Filter Chain (Execution Order)

Every request to `/api/v1/**` (except public auth routes) passes through three custom filters **before** controller logic executes:

```
Incoming Request
       │
       ▼
┌──────────────────────────────┐
│ 1. AlgorithmValidationFilter │  Decode JWT header; reject alg=none, HS*, or non-RS256
└──────────────────────────────┘
       │
       ▼
┌──────────────────────────────┐
│ 2. TokenBlacklistFilter      │  Extract jti; check Redis blacklist:<jti>
└──────────────────────────────┘
       │
       ▼
┌──────────────────────────────┐
│ 3. JwtAuthenticationFilter │  RS256 signature + expiry; populate SecurityContext
└──────────────────────────────┘
       │
       ▼
   Controller
```

### JWT Payload Contract

Tokens are signed with the server's RSA private key and contain **only** these claims:

| Claim | Purpose |
|-------|---------|
| `sub` | User UUID (not username or email) |
| `scope` | Space-delimited roles (e.g. `ROLE_USER`, `ROLE_ADMIN`) |
| `jti` | Unique token ID for Redis revocation |
| `iat` | Issued-at timestamp |
| `exp` | Expiration timestamp |

---

## Security Scenarios & Vulnerability Testing

### Algorithm: `none` Vulnerability

**The vulnerability:** Some JWT libraries historically accepted tokens where the header declared `"alg": "none"`, meaning no cryptographic signature was required. An attacker could forge a payload (e.g. escalate privileges) and bypass verification entirely.

**How SecureGate-Nexus simulates it:**

1. Sign in via the Web UI and click **Generate Token** to obtain a legitimate RS256 JWT (displayed in **Secure Output** only).
2. Manually paste the token into the **Attack & Verification Lab** textarea.
3. Click **Inject alg=none Payload** — the client rewrites the JWT header to `{"alg":"none"}`, reassembles the token, and places it back in the textarea.
4. Click **Verify & Route Token** — the request is sent to `GET /api/v1/secure/data`.

**How the application handles it:**

`AlgorithmValidationFilter` decodes the JWT header **before** any signature verification:

- Rejects `alg` values of `none`, `None`, or `NONE`
- Rejects symmetric algorithms (`HS256`, `HS384`, `HS512`) to prevent algorithm-confusion attacks against RS256 deployments
- Rejects any algorithm other than `RS256`

Blocked requests receive **HTTP 401** with:

```json
{"error":"Security Violation: Invalid or manipulated algorithm detected"}
```

This proactive approach saves CPU cycles and closes the logical bypass window entirely.

### Redis-Based Logout & Token Revocation

**The problem:** Stateless JWTs remain valid until expiration unless you maintain a revocation layer.

**How SecureGate-Nexus solves it:**

1. **Logout** — `POST /api/v1/auth/logout` parses the bearer token, extracts `jti` and `exp`, and calculates remaining TTL:

   ```
   remainingSeconds = (exp × 1000 − now) / 1000   // floored at 0
   ```

2. **Blacklist write** — `TokenBlacklistService` stores:

   ```
   Key:   blacklist:<jti>
   Value: revoked
   TTL:   remainingSeconds
   ```

   Redis automatically evicts the entry when the token would have expired naturally—no cleanup cron required.

3. **Blacklist check** — On every authenticated request, `TokenBlacklistFilter` extracts `jti` from the token payload (pre-verification decode) and calls `redisTemplate.hasKey("blacklist:" + jti)`.

4. **Blocked response** — Revoked tokens receive **HTTP 401**:

   ```json
   {"error":"Security Alert: This token has been revoked."}
   ```

The blacklist check runs **after** algorithm validation but **before** RSA signature verification, ensuring revoked tokens never reach business logic.

---

## Installation & Setup

### Prerequisites

- **JDK 21** (Oracle, Eclipse Temurin, or compatible)
- **Maven 3.9+** (or use the included `./mvnw` wrapper)
- **Redis 6+** (local install or Docker)
- **Git**

### 1. Clone the Repository

```bash
git clone https://github.com/<your-org>/SecureGate-Nexus.git
cd SecureGate-Nexus
```

### 2. Start Redis (Docker)

```bash
docker run -d --name securegate-redis -p 6379:6379 redis:7-alpine
```

Verify Redis is reachable:

```bash
docker exec -it securegate-redis redis-cli ping
# Expected: PONG
```

### 3. Review Configuration

Edit `src/main/resources/application.yml` if your environment differs from defaults:

```yaml
server:
  port: 8080

spring:
  data:
    redis:
      host: localhost
      port: 6379

jwt:
  keys-dir: keys
  private-key-path: keys/private.pem
  public-key-path: keys/public.pem
  access-token-expiry: 900   # seconds (15 minutes)
```

RSA keys are auto-generated on first startup if `keys/private.pem` and `keys/public.pem` do not exist. You may also pre-generate them:

```powershell
# Windows
powershell -ExecutionPolicy Bypass -File generate-keys.ps1
```

### 4. Build the Application

```bash
# Linux / macOS
./mvnw clean package -DskipTests

# Windows
mvnw.cmd clean package -DskipTests
```

### 5. Run the Application

```bash
# Option A — Maven wrapper
./mvnw spring-boot:run

# Option B — Windows helper script (generates keys + runs)
run.cmd

# Option C — JAR
java -jar target/securegate-nexus-1.0.0.jar
```

The API listens on **http://localhost:8080**. The security lab UI is served at **http://localhost:8080/**.

---

## Web UI (Security Lab)

The static front-end (`src/main/resources/static/`) provides a multi-view workflow:

| View | Purpose |
|------|---------|
| **Login** | Authenticate and enter the dashboard |
| **Register** | Create account (username, email, password — no length enforcement) |
| **Dashboard** | Generate tokens, manually paste into lab, inject `alg=none`, verify routing |

**Manual testing workflow:**

1. Sign in → dashboard opens with **empty** Secure Output and textarea.
2. Click **Generate Token** → JWT appears in Secure Output **only** (not auto-filled).
3. Copy and paste the token into the Attack & Verification Lab textarea.
4. Click **Verify & Route Token** → expect `Status 200 OK` for an unmodified valid token.
5. Click **Inject alg=none Payload**, then **Verify** again → expect `Status 401 Unauthorized`.

---

## API Endpoints

Base URL: `http://localhost:8080`

All protected endpoints require:

```
Authorization: Bearer <JWT>
```

### Authentication Endpoints

| Method | Endpoint | Description | Access |
|--------|----------|-------------|--------|
| `POST` | `/api/v1/auth/register` | Register a new user account | Public |
| `POST` | `/api/v1/auth/login` | Authenticate and receive a JWT | Public |
| `POST` | `/api/v1/auth/logout` | Revoke the current token (Redis blacklist) | Authenticated |

**Register request body:**

```json
{
  "username": "alice",
  "email": "alice@example.com",
  "password": "123",
  "role": "ROLE_USER"
}
```

**Login request body:**

```json
{
  "username": "alice",
  "password": "123"
}
```

**Login response:**

```json
{
  "accessToken": "<JWT>",
  "tokenType": "Bearer",
  "expiresIn": 900
}
```

### Secured & Test Endpoints

| Method | Endpoint | Description | Access |
|--------|----------|-------------|--------|
| `GET` | `/api/v1/secure/data` | Primary secured test endpoint; validates full filter chain | Authenticated |
| `GET` | `/api/v1/users/me` | Returns current user ID and roles from SecurityContext | Authenticated |
| `GET` | `/api/v1/users/admin` | Admin-only diagnostic endpoint | `ROLE_ADMIN` |
| `GET` | `/api/v1/orders` | List orders for the authenticated user | Authenticated |
| `GET` | `/api/v1/orders/{id}` | Fetch a single order (owner only) | Authenticated |
| `POST` | `/api/v1/orders` | Create a new order | Authenticated |
| `DELETE` | `/api/v1/orders/{id}` | Delete an order (owner only) | Authenticated |

### Static Resources

| Method | Endpoint | Description | Access |
|--------|----------|-------------|--------|
| `GET` | `/` | Security lab UI (`index.html`) | Public |
| `GET` | `/index.html` | Security lab UI | Public |
| `GET` | `/app.js` | Front-end application logic | Public |

### Quick cURL Examples

```bash
# Register
curl -s -X POST http://localhost:8080/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"demo","email":"demo@test.com","password":"123","role":"ROLE_USER"}'

# Login
TOKEN=$(curl -s -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"demo","password":"123"}' | jq -r '.accessToken')

# Access secured endpoint
curl -s http://localhost:8080/api/v1/secure/data \
  -H "Authorization: Bearer $TOKEN"

# Logout (revoke token)
curl -s -X POST http://localhost:8080/api/v1/auth/logout \
  -H "Authorization: Bearer $TOKEN"
```

---

## Configuration Reference

| Property | Default | Description |
|----------|---------|-------------|
| `server.port` | `8080` | HTTP listen port |
| `spring.data.redis.host` | `localhost` | Redis hostname |
| `spring.data.redis.port` | `6379` | Redis port |
| `jwt.access-token-expiry` | `900` | Token lifetime in seconds |
| `jwt.private-key-path` | `keys/private.pem` | RSA private key (signing) |
| `jwt.public-key-path` | `keys/public.pem` | RSA public key (verification) |

---

## Project Structure

```
SecureGate-Nexus/
├── src/main/java/com/securegate/
│   ├── SecureGateApplication.java          # Spring Boot entry point
│   ├── config/
│   │   ├── RSAKeyConfig.java               # RSA-2048 key load / auto-generation
│   │   └── security/
│   │       └── SecurityConfig.java         # Filter chain, CORS, RBAC rules
│   ├── controller/
│   │   ├── AuthController.java             # Register, login, logout
│   │   ├── SecureDataController.java       # Secured test endpoint
│   │   ├── UserController.java             # Profile + admin route
│   │   └── OrderController.java            # Sample protected CRUD
│   ├── filter/
│   │   ├── AlgorithmValidationFilter.java  # [1] Proactive alg header check
│   │   ├── TokenBlacklistFilter.java       # [2] Redis jti revocation check
│   │   └── JwtAuthenticationFilter.java    # [3] RS256 verify + SecurityContext
│   ├── model/                              # DTOs and domain models
│   ├── service/
│   │   ├── AuthService.java                # Registration, login, logout
│   │   ├── JwtService.java                 # Token creation and parsing
│   │   └── TokenBlacklistService.java      # Redis blacklist operations
│   └── util/
│       └── JwtDecodeUtil.java              # Pre-verification header/payload decode
├── src/main/resources/
│   ├── application.yml                     # Runtime configuration
│   └── static/
│       ├── index.html                      # Security lab UI
│       └── app.js                          # Multi-view state + attack helpers
├── keys/                                   # RSA PEM files (git-ignored)
├── pom.xml                                 # Maven dependencies (Java 21)
├── mvnw / mvnw.cmd                         # Maven wrapper (JDK 21)
├── run.cmd                                 # Windows setup + run helper
└── generate-keys.ps1                       # Manual RSA key generation script
```

---

## Contributing

Contributions are welcome. Please follow these guidelines:

1. **Fork** the repository and create a feature branch from `main`.
2. **Keep changes focused** — one concern per pull request.
3. **Match existing conventions** — Java 21, Spring Boot 3 patterns, Lombok usage, and the established filter-chain architecture.
4. **Do not commit secrets** — RSA private keys, `.env` files, and credentials must stay out of version control.
5. **Test manually** — verify login, token generation, `alg=none` blocking, and Redis logout before opening a PR.
6. **Write clear commit messages** — describe the *why*, not just the *what*.

Open an issue first for large architectural changes (e.g. database integration, OAuth2 migration, multi-module split).

---

## License

This project is licensed under the **MIT License**.

```
MIT License

Copyright (c) 2026 SecureGate-Nexus Contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

<p align="center">
  <strong>SecureGate-Nexus</strong> — Learn JWT vulnerabilities. Build the defenses.
</p>
