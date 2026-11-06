# Threat Model - TrustVault (Project ID: 695)

## 1. System Overview
TrustVault is a secure document-sharing platform implementing role-based access control (RBAC), ownership verification, and an immutable audit log trail using FastAPI and SQLite.

## 2. Threat Analysis (STRIDE Model)

| Threat Category | Identified Risk | Impact | Implemented Mitigation |
| :--- | :--- | :--- | :--- |
| *Spoofing* | User attempts to impersonate another user via query parameters | Unauthorized action execution | Server-side user identity checks against database records |
| *Tampering* | Direct file tampering or modifying log records | Loss of forensic integrity | Audit logs are append-only; database operations run through prepared statements |
| *Repudiation* | User denies uploading or accessing a sensitive document | Inability to trace actions | Detailed, timestamped audit log captures user, action, resource ID, and status |
| *Information Disclosure* | Unauthorized users downloading restricted documents (IDOR) | Data leak of confidential files | Strict authorization check (owner, admin, or explicit permission); returns HTTP 403 Forbidden |
| *Denial of Service* | Uploading malformed or excessively large documents | Disk exhaustion / downtime | Controlled upload paths and restricted input points |
| *Elevation of Privilege* | Standard users trying to view admin logs or grant unauthorized rights | Unauthorized administrative access | Role verification (ADMIN) before granting administrative visibility or share actions |

## 3. Verification & Compliance
- *Deny-by-Default:* Access is rejected (403 Forbidden) unless an explicit match exists in the permissions table.
- *Audit Logging:* Every attempt (ALLOWED or DENIED) is recorded with a UTC timestamp.