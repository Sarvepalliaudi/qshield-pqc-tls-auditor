# qshield-audit — Security Audit Report

> **Tool Name:** `qshield-audit` (Q-Shield PQC-TLS & OWASP Security Auditor)  
> **Proprietary Notice:** "Specified, architected, and exclusively engineered by Sarvepalli Audi Siva Bhanuvardhan. This specification and dual hardware-software architecture is original work created solely for this application."  
> **Disclaimer:** Scan initiated by the listed Session Operator. The operator is solely responsible for ensuring explicit written authorization prior to testing any target.

## 1. Audit Metadata & Executive Summary

| Field | Value |
| :--- | :--- |
| **Session Operator** | Sarvepalli Audi Siva Bhanuvardhan |
| **Operator Organization / University** | Dhanalakshmi Srinivasan University, Tiruchirappalli |
| **Authorization Scope** | Authorized (2026-11-25T05:30:26.448157600+00:00) |
| **Requested Target URL** | `https://example.com` |
| **Resolved Final URL** | `https://example.com/` |
| **HTTP Response** | `200` (HTTP/1.1) |
| **Negotiated TLS Version** | `16'h0304 (TLS 1.3)` |
| **Negotiated Cipher Suite** | `TLS13_AES_256_GCM_SHA384` |
| **Negotiated Key-Exchange Group** | `16'h11EC (X25519MLKEM768)` |
| **Timestamp (UTC)** | `2026-11-25T05:30:26.938876800+00:00` |
| **Execution Latency** | `387 ms` |
| **Final Security Score** | **25 / 100** (Grade **F**) |

## 2. Security Findings & Remediation Matrix

| Check | Category | Status | Severity | Observed | Nginx Fix | Apache Fix |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| Strict-Transport-Security | OWASP Header | `[FAIL]` | High | Missing | `add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;` | `Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"` |
| Content-Security-Policy | OWASP Header | `[FAIL]` | High | Missing | `add_header Content-Security-Policy "default-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self';" always;` | `Header always set Content-Security-Policy "default-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self';"` |
| X-Frame-Options | OWASP Header | `[FAIL]` | Medium | Missing | `add_header X-Frame-Options "DENY" always;` | `Header always set X-Frame-Options "DENY"` |
| X-Content-Type-Options | OWASP Header | `[FAIL]` | Medium | Missing | `add_header X-Content-Type-Options "nosniff" always;` | `Header always set X-Content-Type-Options "nosniff"` |
| Referrer-Policy | OWASP Header | `[FAIL]` | Low | Missing | `add_header Referrer-Policy "strict-origin-when-cross-origin" always;` | `Header always set Referrer-Policy "strict-origin-when-cross-origin"` |
| Permissions-Policy | OWASP Header | `[FAIL]` | Low | Missing | `add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;` | `Header always set Permissions-Policy "geolocation=(), microphone=(), camera=()"` |
| Cookie Security (Set-Cookie) | Passive Vulnerability | `[OK]` | Info | No Set-Cookie headers emitted | `proxy_cookie_path / "/; HttpOnly; Secure; SameSite=Strict";` | `Header edit Set-Cookie ^(.*)$ "$1; HttpOnly; Secure; SameSite=Strict"` |
| Banner Disclosure (Server / X-Powered-By) | Passive Vulnerability | `[WARN]` | Low | Server: cloudflare | `server_tokens off;<br>more_clear_headers 'Server' 'X-Powered-By';` | `ServerTokens Prod<br>ServerSignature Off<br>Header unset X-Powered-By` |
| CORS Policy (Access-Control-Allow-Origin) | Passive Vulnerability | `[OK]` | Info | Absent (Same-Origin default) | `add_header Access-Control-Allow-Origin "https://trusted.example.com" always;` | `Header always set Access-Control-Allow-Origin "https://trusted.example.com"` |
| NIST IR 8547 / FIPS 203 ML-KEM-768 Posture | PQC-TLS Readiness | `[OK]` | Info | TLS 1.3 \| TLS13_AES_256_GCM_SHA384 \| X25519MLKEM768 (0x11EC) — Hybrid FIPS 203 PQC active | `ssl_protocols TLSv1.3;<br>ssl_ecdh_curve X25519MLKEM768:X25519:prime256v1;<br>ssl_prefer_server_ciphers off;` | `SSLProtocol -all +TLSv1.3<br>SSLOpenSSLConfCmd Curves X25519MLKEM768:X25519:prime256v1` |

## 3. Actionable Remediation Snippets (Nginx & Apache)

### [FAIL] `Strict-Transport-Security` (High)

- **Observed:** Missing
- **Recommendation:** Enforce HTTPS via HSTS to block SSL stripping.

**Nginx (`server {}` block):**
```nginx
add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
```

**Apache (`VirtualHost` / `.htaccess`):**
```apache
Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"
```

### [FAIL] `Content-Security-Policy` (High)

- **Observed:** Missing
- **Recommendation:** Define a strict Content-Security-Policy to mitigate XSS and injection.

**Nginx (`server {}` block):**
```nginx
add_header Content-Security-Policy "default-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self';" always;
```

**Apache (`VirtualHost` / `.htaccess`):**
```apache
Header always set Content-Security-Policy "default-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self';"
```

### [FAIL] `X-Frame-Options` (Medium)

- **Observed:** Missing
- **Recommendation:** Add X-Frame-Options: DENY (or SAMEORIGIN) to prevent clickjacking.

**Nginx (`server {}` block):**
```nginx
add_header X-Frame-Options "DENY" always;
```

**Apache (`VirtualHost` / `.htaccess`):**
```apache
Header always set X-Frame-Options "DENY"
```

### [FAIL] `X-Content-Type-Options` (Medium)

- **Observed:** Missing
- **Recommendation:** Set X-Content-Type-Options: nosniff to prevent MIME confusion.

**Nginx (`server {}` block):**
```nginx
add_header X-Content-Type-Options "nosniff" always;
```

**Apache (`VirtualHost` / `.htaccess`):**
```apache
Header always set X-Content-Type-Options "nosniff"
```

### [FAIL] `Referrer-Policy` (Low)

- **Observed:** Missing
- **Recommendation:** Add Referrer-Policy to prevent URL token leakage.

**Nginx (`server {}` block):**
```nginx
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
```

**Apache (`VirtualHost` / `.htaccess`):**
```apache
Header always set Referrer-Policy "strict-origin-when-cross-origin"
```

### [FAIL] `Permissions-Policy` (Low)

- **Observed:** Missing
- **Recommendation:** Restrict powerful browser APIs via Permissions-Policy.

**Nginx (`server {}` block):**
```nginx
add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;
```

**Apache (`VirtualHost` / `.htaccess`):**
```apache
Header always set Permissions-Policy "geolocation=(), microphone=(), camera=()"
```

### [WARN] `Banner Disclosure (Server / X-Powered-By)` (Low)

- **Observed:** Server: cloudflare
- **Recommendation:** Suppress Server and X-Powered-By banners to reduce fingerprinting.

**Nginx (`server {}` block):**
```nginx
server_tokens off;
more_clear_headers 'Server' 'X-Powered-By';
```

**Apache (`VirtualHost` / `.htaccess`):**
```apache
ServerTokens Prod
ServerSignature Off
Header unset X-Powered-By
```

## 4. Hardware Silicon Cipher Policy Verification (`hardware/tls_cipher_gate.v`)

Deterministic hardware policy mapping from live TLS handshake telemetry per NIST IR 8547 (October 2026) and FIPS 203:

| Signal / Telemetry | Value | Meaning |
| :--- | :--- | :--- |
| `tls_version[15:0]` | `16'h0304 (TLS 1.3)` | Live negotiated TLS protocol version |
| `cipher_id[15:0]` | `16'h11EC (X25519MLKEM768)` | Live negotiated key-exchange group identifier |
| `cipher_suite` | `TLS13_AES_256_GCM_SHA384` | Live negotiated AEAD cipher suite |
| `pqc_safe` | `1` | Asserted `1` only for TLS 1.3 (`16'h0304`) + ML-KEM-768 (`16'h11EC` / `16'h11EB`) |
| `classical_vuln` | `0` | Asserted `1` when vulnerable to Shor's algorithm or downgrade |
| `allow_packet` | `1` | Hardware gate forwarding decision (`1` = Allow, `0` = Drop) |

**Policy Verdict:** ALLOW: Hardware gate verified 16'h0304 (TLS 1.3) + 16'h11EC (X25519MLKEM768) with TLS13_AES_256_GCM_SHA384 under NIST IR 8547 / FIPS 203.

## 5. Issue Classification Guide (Internal Security Audit vs. Bug Bounty Scope)

| Tier | Example Findings | Report to Organization? | Bug Bounty Eligible? |
| :--- | :--- | :--- | :--- |
| **Tier 1: Immediate Transport / Auth Defect** | Cleartext HTTP, broken/untrusted TLS PKI (`UnknownIssuer`), wildcard CORS on authenticated APIs, session tokens missing `HttpOnly`/`Secure` | Yes — High/Critical IT & DevOps remediation | Only with verified exploit PoC & impact (telemetry cookies like `_octo` are out-of-scope) |
| **Tier 2: Defense-in-Depth Hardening** | Missing `Permissions-Policy`, `Referrer-Policy`, `X-Frame-Options`, `Server`/`X-Powered-By` banners, CSP `style-src 'unsafe-inline'` | Yes — Standard blue-team / compliance hardening ticket | No — Automated scanner & missing-header findings without PoC are out-of-scope |
| **Tier 3: Strategic PQC Migration** | Classical `X25519`/`ECDHE`/`RSA` without FIPS 203 `ML-KEM-768` (`0x11EC`/`0x11EB`) | Yes — NIST IR 8547 (Oct 2026) HNDL roadmap | No — Architectural crypto upgrade advisory |

---

## Software Author & Engineering Attribution

- **Tool Architected & Engineered by:** Sarvepalli Audi Siva Bhanuvardhan
- **University:** B.Tech CSE Cybersecurity, Dhanalakshmi Srinivasan University, Tiruchirappalli, Tamil Nadu, India
- **Internship:** Dev/Craft by Fennark (`DEV-CRAFT-BQ2VPH`) | Task 3: Security Audit
- **LinkedIn:** https://www.linkedin.com/in/audi-siva-bhanuvardhan-sarvepalli-4598a8289/
- **GitHub:** https://github.com/Sarvepalliaudi
