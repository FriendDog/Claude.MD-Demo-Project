---
name: stride-threat-model
description: Creates a STRIDE threat model of the current project with ASCII diagrams and outputs a threat.md file. Use when analyzing system security, designing architectures, or identifying threats in applications.
---

# Skill: STRIDE Threat Model

Generate a comprehensive STRIDE threat model for OWASP Juice Shop. Produce a `threat.md` file at the project root with findings organized by STRIDE category.

## General Workflow

1. **Understand the Architecture**: Read `CLAUDE.md`, `package.json`, route files, and middleware to map components.
2. **Identify Assets & Trust Boundaries**: List data stores, APIs, external integrations, and user roles.
3. **Draw a Data Flow Diagram (DFD)**: Produce an ASCII DFD showing actors, processes, data stores, and trust boundaries.
4. **Apply STRIDE**: For each DFD element, enumerate threats in each category.
5. **Rate & Prioritize**: Assign a risk rating (High / Medium / Low) to each threat using DREAD-lite (Damage + Reproducibility + Exploitability).
6. **Map to Mitigations**: Link each threat to an OWASP countermeasure or existing Juice Shop challenge that demonstrates it.
7. **Write `threat.md`**: Output the full model using the structure below.

---

## STRIDE Categories

| Letter | Threat | Security Property Violated |
|--------|--------|---------------------------|
| S | Spoofing | Authentication |
| T | Tampering | Integrity |
| R | Repudiation | Non-repudiation |
| I | Information Disclosure | Confidentiality |
| D | Denial of Service | Availability |
| E | Elevation of Privilege | Authorization |

---

## Output Format (`threat.md`)

```markdown
# STRIDE Threat Model — OWASP Juice Shop

## 1. Architecture Overview
<brief description of the app: Node/Express backend, Angular frontend, SQLite DB, REST + WebSocket APIs>

## 2. Data Flow Diagram

<ASCII DFD — see template below>

## 3. Assets & Trust Boundaries

| Asset | Classification | Trust Zone |
|-------|---------------|------------|
| ...   | ...           | ...        |

## 4. Threat Inventory

### S — Spoofing
| ID | Component | Threat Description | Risk | Mitigation | Related Challenge |
|----|-----------|-------------------|------|------------|-------------------|
| S1 | ...       | ...               | High | ...        | ...               |

### T — Tampering
...

### R — Repudiation
...

### I — Information Disclosure
...

### D — Denial of Service
...

### E — Elevation of Privilege
...

## 5. Risk Summary

| Rating | Count |
|--------|-------|
| High   | N     |
| Medium | N     |
| Low    | N     |

## 6. Top Priorities
1. ...
2. ...
3. ...
```

---

## ASCII DFD Template

```
  [Browser / User]
        |
        | HTTPS
        v
  +-----|--------+      +-----------+
  |  Angular SPA |      | Admin UI  |
  +-----|--------+      +-----|-----+
        |                     |
        |  REST / WebSocket   |
        v                     v
  +-----+---------------------+-----+   <- Trust Boundary: Internet ↔ App
  |         Express.js Backend      |
  |  Routes | Middleware | Services |
  +----+----+--------+----+---------+
       |             |    |
       |             |    +---> [File System] (logs, uploads)
       v             v
  [SQLite DB]   [External APIs]
                (Payment, OAuth)
```

Adjust the diagram to reflect actual components found in the codebase (e.g., WebSockets for `socket.io`, B2B XML endpoint, metrics endpoint).

---

## Key Files to Read

- `routes/` — all Express route handlers (attack surface)
- `lib/` — shared utilities (sanitization, JWT, crypto helpers)
- `models/` — Sequelize models (data assets)
- `frontend/src/app/Services/` — Angular services calling the API
- `config/default.yml` — runtime configuration
- `data/static/challenges.yml` — existing vulnerabilities (cross-reference)

---

## Juice Shop–Specific Threat Hints

Focus analysis on these high-value areas:

- **JWT**: weak secret, algorithm confusion (`alg: none`)
- **SQLi**: Sequelize raw queries in login and search routes
- **XSS**: reflected/stored in product reviews, basket, user profile
- **IDOR**: order and basket endpoints lack ownership checks
- **SSRF / Path Traversal**: file serving routes
- **Broken Auth**: forgotten password flow, brute-force on login
- **Sensitive Data**: API exposes internal fields, `/api-docs` unauthenticated
- **XXE**: B2B order endpoint parses XML
- **Prototype Pollution**: deep merge utilities
- **DoS**: large payload uploads, ReDoS in search

---

## Risk Rating Guide

| Rating | Criteria |
|--------|----------|
| High   | Exploitable with basic tools, significant data loss or account takeover |
| Medium | Requires some skill or chaining; limited blast radius |
| Low    | Theoretical, requires unusual conditions or low impact |
