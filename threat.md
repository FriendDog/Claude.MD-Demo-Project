# Threat Model: OWASP Juice Shop

## System Overview

OWASP Juice Shop is an intentionally vulnerable Node.js/Express web application with an Angular SPA frontend and SQLite database. It serves as a security training platform exposing a broad attack surface across REST APIs, WebSockets, file serving, and B2B order processing.

**Components:**
- Angular 17 SPA (browser client)
- Express.js backend (Node.js, TypeScript)
- SQLite database via Sequelize ORM
- JWT-based authentication (RS256, 6h expiry)
- Socket.io WebSocket server
- Prometheus metrics endpoint
- FTP file server (`/ftp`)
- B2B order endpoint (JavaScript eval via `vm`)
- Swagger UI at `/api-docs`

**Actors:**
- Anonymous user (unauthenticated browser)
- Authenticated customer
- Deluxe member (elevated shopping privileges)
- Admin user
- B2B partner (machine client)
- Attacker (external threat)

**Trust Boundaries:**
- Internet ↔ Express server (primary boundary)
- Express server ↔ SQLite database
- Express server ↔ File system (FTP, logs, uploads, encryptionkeys)
- Authenticated session ↔ Admin-only resources

---

## Architecture Diagram

```
  ┌─────────────────────────────────────────────────────┐
  │                   Internet (untrusted)               │
  │                                                     │
  │  [Browser / User]          [B2B Partner / Bot]      │
  │       │  HTTPS                    │  HTTPS          │
  └───────┼───────────────────────────┼─────────────────┘
          │                           │
          ▼                           ▼
  ╔═══════════════════════════════════════════════╗
  ║           Express.js Backend (Node)           ║  ← Trust Boundary
  ║                                               ║
  ║  ┌─────────────┐  ┌──────────────────────┐   ║
  ║  │ Angular SPA │  │  REST API Routes     │   ║
  ║  │ (static)    │  │  /api/Users          │   ║
  ║  └─────────────┘  │  /api/Products       │   ║
  ║                   │  /rest/user/login    │   ║
  ║  ┌─────────────┐  │  /rest/products/     │   ║
  ║  │ Socket.io   │  │    search            │   ║
  ║  │ WebSocket   │  │  /b2b/v2/orders      │   ║
  ║  └─────────────┘  └──────────┬───────────┘   ║
  ║                              │               ║
  ║  ┌─────────────┐  ┌──────────▼───────────┐   ║
  ║  │ /ftp        │  │   Sequelize ORM      │   ║
  ║  │ /api-docs   │  └──────────┬───────────┘   ║
  ║  │ /encryptionkeys           │               ║
  ║  │ /support/logs             ▼               ║
  ║  │ /metrics   │  ┌───────────────────────┐   ║
  ║  └─────────────┘  │      SQLite DB        │   ║
  ║                   │  Users, Products,     │   ║
  ║                   │  Baskets, Orders      │   ║
  ║                   └───────────────────────┘   ║
  ╚═══════════════════════════════════════════════╝
          │
          ▼
  [File System]
  ftp/, logs/, uploads/,
  encryptionkeys/, frontend/dist/
```

---

## Threat Mapping

```
  [Browser / Attacker]
       │
       │  S─────── Spoofed JWT / OAuth token
       │  T─────── Tampered basket / order payload
       │  R─────── No audit log of auth events
       │  I─────── /api-docs exposed (no auth)
       │  D─────── No rate limit on login (brute force)
       │  E─────── IDOR on /api/BasketItems
       ▼
  ┌────────────────────────────────────────────────┐
  │  Express.js Backend                            │
  │                                                │
  │  /rest/user/login   ← T(SQLi), I(MD5 hashes)  │
  │  /rest/products/    ← T(SQLi UNION), I(schema) │
  │    search                                      │
  │  /b2bOrder          ← E(RCE via vm sandbox)   │
  │  /ftp               ← I(directory listing)    │
  │  /encryptionkeys    ← I(private key exposed)  │
  │  /support/logs      ← I(access log leak)      │
  │  /metrics           ← I(app internals)        │
  │  WebSocket          ← S(no origin check)      │
  │  JWT (RS256)        ← S(alg:none bypass)      │
  │    hardcoded privkey ← S, T                   │
  └────────────────────────────────────────────────┘
```

---

## Threat Table

| ID | STRIDE | Component | Threat | Impact | Likelihood | Mitigation |
|----|--------|-----------|--------|--------|------------|------------|
| S1 | Spoofing | JWT (`insecurity.ts:56`) | Hardcoded RSA private key in source allows attacker to forge arbitrary tokens | Critical | High | Store private key in secrets manager; rotate key |
| S2 | Spoofing | JWT (`insecurity.ts:54`) | `alg:none` algorithm confusion — `expressJwt` configured without `algorithms` allowlist | Critical | High | Explicitly set `algorithms: ['RS256']` in `expressJwt` options |
| S3 | Spoofing | OAuth flow | Password-based OAuth login accepts guessable base64-encoded password | High | Medium | Enforce OAuth PKCE; remove password fallback |
| S4 | Spoofing | WebSocket (`socket.io`) | No `origin` validation on WebSocket upgrade; any domain can connect | Medium | Medium | Restrict `cors` origins on Socket.io server |
| T1 | Tampering | Login (`login.ts:34`) | Raw SQL string interpolation: `SELECT * FROM Users WHERE email = '${email}'` — SQL injection allows admin login bypass | Critical | High | Use parameterized queries / Sequelize `findOne({ where: { email } })` |
| T2 | Tampering | Search (`search.ts:23`) | Raw SQL in product search: `LIKE '%${criteria}%'` — UNION injection leaks all user emails and MD5 passwords | Critical | High | Parameterized query with `Op.like` |
| T3 | Tampering | B2B Order (`b2bOrder.ts:23`) | `vm.runInContext('safeEval(orderLinesData)', ...)` — user-controlled input passed to JS eval sandbox (breakout achievable) | Critical | High | Remove eval; parse order data as structured JSON with schema validation |
| T4 | Tampering | File Upload (`fileUpload.ts`) | XML upload processed without XXE protection; YAML upload without safe-load | High | Medium | Disable external entity resolution; use `js-yaml` `safeLoad` |
| T5 | Tampering | Profile image URL (`profileImageUrlUpload.ts`) | SSRF — server fetches attacker-supplied URL for profile image | High | Medium | Validate URL against allowlist of image CDNs; disable redirects |
| T6 | Tampering | Product reviews | Stored XSS — `helmet.xssFilter()` explicitly disabled (`server.ts:188`); review content rendered unsanitized | High | High | Re-enable XSS filter; sanitize review content server-side |
| R1 | Repudiation | Auth events | No server-side audit log of login successes/failures; in-memory token map lost on restart | Medium | High | Persist auth events to append-only log; include IP, timestamp, user ID |
| R2 | Repudiation | Order placement | Orders reference basket ID, not a signed user+item snapshot; contents can be altered pre-confirmation | Medium | Medium | Hash and sign order contents at placement time |
| R3 | Repudiation | Admin actions | No admin action audit trail — challenge solves, user deletions not logged with actor identity | Medium | Medium | Add structured audit log middleware for privileged routes |
| I1 | Info Disclosure | `/api-docs` (`server.ts:286`) | Swagger UI served publicly without authentication — exposes all API endpoints, parameters, and schemas | High | High | Restrict `/api-docs` to authenticated admin sessions |
| I2 | Info Disclosure | `/ftp` (`server.ts:269`) | Directory listing enabled — backup files, acquisition docs, Easter eggs browsable by anyone | High | High | Remove `serveIndex`; serve only explicitly whitelisted files |
| I3 | Info Disclosure | `/encryptionkeys` (`server.ts:277`) | Encryption key directory browseable; private JWT key derivable | Critical | High | Remove public route; never serve key material via HTTP |
| I4 | Info Disclosure | `/support/logs` (`server.ts:281`) | Access logs served publicly — reveals internal paths, user emails, session tokens in URLs | High | High | Restrict log endpoint to admin role; scrub PII from logs |
| I5 | Info Disclosure | `/metrics` | Prometheus metrics endpoint public — leaks request rates, error counts, app internals | Medium | High | Require auth or bind metrics to loopback only |
| I6 | Info Disclosure | `insecurity.ts:43` | Passwords hashed with MD5 (no salt) — trivially crackable with rainbow tables | Critical | High | Replace with bcrypt/argon2 with per-user salt |
| I7 | Info Disclosure | Data export (`dataExport.ts`) | Full user data export available to authenticated user with no rate limiting — facilitates account scraping | Medium | Medium | Rate-limit exports; require re-authentication |
| D1 | Denial of Service | Login (`server.ts`) | No rate limiting on `/rest/user/login` — brute-force and credential stuffing viable | High | High | Apply `express-rate-limit` to auth endpoints (already imported, not applied to login) |
| D2 | Denial of Service | B2B Order (`b2bOrder.ts:23`) | `vm.runInContext` with 2s timeout — attacker can exhaust CPU with near-timeout loops | Medium | High | Remove eval; structured parsing has no compute amplification |
| D3 | Denial of Service | File Upload | No file size check before streaming to disk for all upload types — disk exhaustion | Medium | Medium | Enforce `limits.fileSize` in multer config before processing |
| D4 | Denial of Service | WebSocket | No per-connection message rate limit on Socket.io — event flood can saturate event loop | Medium | Medium | Add Socket.io middleware to throttle messages per socket |
| E1 | Elevation of Privilege | Basket IDOR | `/api/BasketItems` REST endpoint (finale-rest) — no ownership check; user A can read/modify user B's basket by ID | High | High | Add ownership middleware to BasketItem and Basket REST handlers |
| E2 | Elevation of Privilege | Admin role | User `role` field stored in JWT payload — if private key is compromised (I3), attacker can self-issue admin token | Critical | High | Mitigated by fixing S1/S3; additionally verify role against DB on each request |
| E3 | Elevation of Privilege | Deluxe upgrade (`deluxe.ts`) | Payment for deluxe membership processed client-side with no server-side price verification | High | Medium | Verify payment amount server-side before granting role |
| E4 | Elevation of Privilege | Password reset | Security question answers guessable from public OSINT (user names visible in reviews) | High | High | Replace security questions with email-based reset + signed time-limited token |

---

## Key Risks

1. **Hardcoded JWT private key + MD5 passwords** (S1, I6): An attacker who reads the source can forge admin tokens and crack all user passwords offline — complete account takeover of every user.

2. **SQL Injection in login and search** (T1, T2): Login bypass to admin account and full database schema + user credential exfiltration via a single unauthenticated search request.

3. **RCE via B2B eval endpoint** (T3): Authenticated (or unauthenticated with valid JWT) call to `/b2b/v2/orders` can break the `vm` sandbox and execute arbitrary OS commands.

4. **Sensitive file/key exposure** (I2, I3, I4): `/ftp`, `/encryptionkeys`, and `/support/logs` are publicly browseable — private keys, backups, and log data are one GET request away.

5. **No XSS protection + stored XSS** (T6): `helmet.xssFilter()` is deliberately disabled; product reviews persist unsanitized HTML/script content shown to all users.

---

## Recommended Controls

| Priority | Control | Addresses |
|----------|---------|-----------|
| P0 | Replace all raw SQL with parameterized Sequelize queries | T1, T2 |
| P0 | Remove hardcoded JWT private key; load from environment/secrets manager | S1, E2 |
| P0 | Replace MD5 password hashing with bcrypt (cost ≥ 12) | I6 |
| P0 | Remove `vm.runInContext` eval in B2B endpoint; parse JSON schema instead | T3, D2 |
| P1 | Restrict `/api-docs`, `/ftp`, `/encryptionkeys`, `/support/logs` to admin-authenticated sessions | I1–I4 |
| P1 | Add ownership checks to Basket/BasketItem/Order REST handlers | E1 |
| P1 | Apply `express-rate-limit` to `/rest/user/login` and `/rest/user/reset-password` | D1 |
| P1 | Set explicit `algorithms: ['RS256']` in `expressJwt` to prevent `alg:none` | S2 |
| P2 | Re-enable `helmet.xssFilter()` and add `Content-Security-Policy` header | T6 |
| P2 | Validate profile image URLs against CDN allowlist to block SSRF | T5 |
| P2 | Add server-side audit log for auth events, admin actions, and data exports | R1–R3 |
| P2 | Bind `/metrics` to loopback or require admin auth | I5 |
| P3 | Add Socket.io per-connection rate limiting | D4 |
| P3 | Replace security-question password reset with email + signed token | E4 |
| P3 | Verify payment amount server-side before granting Deluxe membership | E3 |
