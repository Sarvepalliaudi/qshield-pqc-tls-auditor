<!--
==============================================================================
Tool Name: qshield-audit (Q-Shield PQC-TLS & OWASP Security Auditor)
Proprietary Notice: "Specified, architected, and exclusively engineered by
Sarvepalli Audi Siva Bhanuvardhan. This specification and dual
hardware-software architecture is original work created solely for this
application."
Author: Sarvepalli Audi Siva Bhanuvardhan
University: B.Tech Computer Science and Engineering (Cybersecurity), Final Year
            (7th Semester), Dhanalakshmi Srinivasan University,
            Tiruchirappalli, Tamil Nadu, India
Internship: Cybersecurity Virtual Internship — Dev/Craft by Fennark
            (https://devcraft.fennark.xyz) | Intern ID: DEV-CRAFT-BQ2VPH |
            Task 3: Security Audit
LinkedIn: https://www.linkedin.com/in/audi-siva-bhanuvardhan-sarvepalli-4598a8289/
GitHub: https://github.com/Sarvepalliaudi
==============================================================================
-->

# qshield-audit User Manual

**Tool Name:** `qshield-audit` (Q-Shield PQC-TLS & OWASP Security Auditor)  
**Proprietary Notice:** "Specified, architected, and exclusively engineered by Sarvepalli Audi Siva Bhanuvardhan. This specification and dual hardware-software architecture is original work created solely for this application."  
**Author:** Sarvepalli Audi Siva Bhanuvardhan  
**University:** B.Tech Computer Science and Engineering (Cybersecurity), Final Year (7th Semester), Dhanalakshmi Srinivasan University, Tiruchirappalli, Tamil Nadu, India  
**Internship:** Cybersecurity Virtual Internship — Dev/Craft by Fennark ([https://devcraft.fennark.xyz](https://devcraft.fennark.xyz)) | Intern ID: `DEV-CRAFT-BQ2VPH` | Task 3: Security Audit  
**LinkedIn:** [https://www.linkedin.com/in/audi-siva-bhanuvardhan-sarvepalli-4598a8289/](https://www.linkedin.com/in/audi-siva-bhanuvardhan-sarvepalli-4598a8289/)  
**GitHub:** [https://github.com/Sarvepalliaudi](https://github.com/Sarvepalliaudi)

---

## 1. Architecture & Why Unix/VLC Minimalism Beats Bloated Scanners

Most modern security scanners ship with heavy browser runtimes, ANSI-colored terminal UIs, multi-megabyte plugin frameworks, and noisy telemetry. That bloat slows startup, breaks log redirection (`> out.txt`), and obscures deterministic security reasoning.

`qshield-audit` follows the **Linux/Unix & VLC (`vlc --intf dummy`) philosophy**:
- **Zero ANSI colors / Zero TUI bloat:** Plain-text status tags (`[OK]`, `[WARN]`, `[FAIL]`, `[STAGE 1/4]`) work identically in CI/CD pipelines, SSH sessions, Windows PowerShell, and `grep`/`awk` filters.
- **Single-pass passive inspection:** One clean `reqwest` (`rustls-tls`) HTTP GET request captures transport posture, latency, and response headers without intrusive fuzzing or noisy traffic.
- **Dual hardware-software verification:** The Rust auditor (`src/auditor.rs`) mirrors the deterministic combinational/sequential policy in `hardware/tls_cipher_gate.v`, proving how software TLS posture maps directly to silicon-level packet gating.

### Component Map

```text
+-------------------------------------------------------------------+
|                        qshield-audit (Rust)                       |
|  src/main.rs  -> CLI args (clap) & 4-stage pipeline orchestration |
|  src/auth.rs  -> First-run operator gate (operator_profile.json)  |
|  src/guide.rs -> Plain-text interactive --guide & ASCII progress  |
|  src/auditor.rs -> Passive HTTP GET, OWASP headers, PQC-TLS check |
|  src/report.rs  -> Structured AUDIT_REPORT.md + Nginx/Apache fix  |
+---------------------------------+---------------------------------+
                                  |
                                  v (Stage 4 Policy Mapping)
+-------------------------------------------------------------------+
|                   Verilog Hardware Gate (RTL)                     |
|  hardware/tls_cipher_gate.v    -> 16-bit TLS & Cipher Gate (<60L) |
|  hardware/tb_tls_cipher_gate.v -> Self-checking iverilog testbench|
+-------------------------------------------------------------------+
```

---

## 2. Quick Installation (Rust & Icarus Verilog on Windows / Linux)

### A. Rust Toolchain

**Linux / macOS:**
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
```

**Windows (PowerShell / winget):**
```powershell
winget install Rustlang.Rustup
```

Clone the repository and build the optimized release binary:
```bash
git clone https://github.com/Sarvepalliaudi/qshield-pqc-tls-auditor.git
cd qshield-pqc-tls-auditor
cargo build --release
```
The compiled executable is created at `target/release/qshield-audit` (or `target\release\qshield-audit.exe` on Windows).

### B. Icarus Verilog (`iverilog`)

**Ubuntu / Debian:**
```bash
sudo apt-get update && sudo apt-get install -y iverilog
```

**Windows:**
- Download the Icarus Verilog Windows installer from [bleyer.org/icarus](https://bleyer.org/icarus/) (or install via Chocolatey: `choco install iverilog`) and ensure `iverilog` and `vvp` are in your system `PATH`.

---

## 3. First-Time Operator Login & `--guide` Mode Walkthrough

On first launch (when `operator_profile.json` does not exist in the working directory), `qshield-audit` enforces an explicit authorization gate via `std::io::stdin()`:

1. **Operator Full Name:** Enter your full name.
2. **Organization / University:** Enter your university, team, or organization.
3. **Authorization Consent:** Type `AUTHORIZED` (exact uppercase) to confirm authorized passive assessment scope.

`qshield-audit` saves `operator_profile.json` locally and automatically enables `--guide` mode on that first run. In `--guide` mode, each of the 4 stages prints an ASCII progress bar (`[##--------] 25%` through `[##########] 100%`), explains the security mechanics in plain English, and pauses with `Press ENTER to execute stage...`:

- `[STAGE 1/4] Target Reachability & Passive HTTP Handshake`
- `[STAGE 2/4] OWASP Security Header & Cookie/CORS Policy Check`
- `[STAGE 3/4] Post-Quantum TLS (NIST IR 8547 / FIPS 203 ML-KEM-768) Readiness Check`
- `[STAGE 4/4] Hardware Silicon Cipher Policy Verification (Verilog Logic Mapping)`

On subsequent runs, `operator_profile.json` is loaded automatically and a single line is printed:
```text
[AUTH] Operator: Sarvepalli Audi Siva Bhanuvardhan | Scope: Authorized
```

To clear saved credentials and re-authenticate, pass `--reset-login`.

---

## 4. CLI Flags & Pipe-Friendly Output Examples

### Available Flags

| Flag | Default | Description |
| :--- | :--- | :--- |
| `--url <URL>` | `https://example.com` | Target URL to inspect passively |
| `--guide` | `false` (auto on first run) | Interactive stage-by-stage explanation and pause |
| `--output <FILE>` | `AUDIT_REPORT.md` | Output path for the generated Markdown report |
| `--reset-login` | `false` | Delete `operator_profile.json` and re-run login gate |
| `--serve` | `false` | Launch zero-JS plain-HTML portal (`GET /`, `POST /audit`) on `0.0.0.0:$PORT` (default `8080`) |

### Usage Examples

```bash
# Run default passive audit against https://example.com
./target/release/qshield-audit

# Audit a custom target with interactive --guide walkthrough
./target/release/qshield-audit --url https://example.com --guide

# Save report to a custom filename
./target/release/qshield-audit --url https://example.com --output custom_audit.md

# Pipe-friendly Unix filtering (zero ANSI escape codes)
./target/release/qshield-audit --url https://example.com | grep -E "^\[(FAIL|WARN|OK)\]"

# Save clean console transcript to a plain-text log
./target/release/qshield-audit --url https://example.com > audit_console.log

# Reset operator profile and re-authorize
./target/release/qshield-audit --reset-login
```

---

## 5. Reading `AUDIT_REPORT.md` & Applying Nginx / Apache Fixes

Every run exports a structured Markdown report containing:
1. **Audit Metadata & Executive Summary:** Operator identity, target URL, HTTP status/version, UTC timestamp, execution latency (`ms`), deterministic score (`0–100`), and letter grade (`A`–`F`).
2. **Security Findings & Remediation Matrix:** Evaluates:
   - **6 OWASP Security Headers:** `Strict-Transport-Security`, `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`.
   - **Passive Web Vulnerabilities:** `Set-Cookie` missing `HttpOnly`/`Secure`/`SameSite`, exposed `Server` or `X-Powered-By` banners, and wildcard CORS (`Access-Control-Allow-Origin: *`).
   - **PQC Readiness Assessment:** Evaluates HTTPS/TLS posture against **NIST IR 8547 (October 2026)** and **FIPS 203 (`X25519MLKEM768` / `SecP256r1MLKEM768`)**, flagging classical RSA/ECDSA/X25519 key-exchange vulnerability to Shor's algorithm and Harvest-Now-Decrypt-Later (HNDL) threats.
3. **Actionable Nginx & Apache Fix Blocks:** Copy the exact directives from Section 3 of `AUDIT_REPORT.md` into your Nginx `server {}` block (`nginx -t && systemctl reload nginx`) or Apache `VirtualHost` (`apachectl configtest && systemctl reload apache2`).
4. **Hardware Silicon Cipher Policy Verification:** Displays the exact signal mapping (`tls_version`, `cipher_id`, `pqc_safe`, `classical_vuln`, `allow_packet`) corresponding to `hardware/tls_cipher_gate.v`.

---

## 6. Simulating `tls_cipher_gate.v` with `iverilog`

Compile and run the self-checking hardware testbench:

```bash
iverilog -o hardware/sim_cipher_gate.vvp hardware/tls_cipher_gate.v hardware/tb_tls_cipher_gate.v
vvp hardware/sim_cipher_gate.vvp
```

The gate asserts `pqc_safe = 1`, `classical_vuln = 0`, and `allow_packet = 1` **only** when:
- `tls_version == 16'h0304` (TLS 1.3), **AND**
- `cipher_id == 16'h11EC` (`X25519MLKEM768`) or `16'h11EB` (`SecP256r1MLKEM768`).

All classical, downgraded (`16'h0303`), or cleartext (`16'h0000`) handshakes fail closed (`classical_vuln = 1`, `allow_packet = 0`).

---

## 7. Live Cloud Deployment (Render.com Free Tier)

[![Live Status](https://img.shields.io/badge/Render-Live%20Web%20Service%20(Replace%20with%20Live%20URL)-brightgreen)](https://qshield-audit.onrender.com)

`qshield-audit` can be hosted as a zero-JavaScript web service on **Render.com Free Tier** using the included `Dockerfile` and `render.yaml`:

1. **Test Locally:**
   ```bash
   cargo build --release
   ./target/release/qshield-audit --serve
   ```
   Open `http://127.0.0.1:8080` in a browser (the server reads `PORT` from the environment and defaults to `8080`).
2. **Push to GitHub:** Push `Cargo.toml`, `Cargo.lock`, `src/`, `hardware/`, `docs/`, `LICENSE`, `Dockerfile`, and `render.yaml` to [https://github.com/Sarvepalliaudi/qshield-pqc-tls-auditor](https://github.com/Sarvepalliaudi/qshield-pqc-tls-auditor).
3. **Deploy on Render.com:**
   - Open the [Render Dashboard](https://dashboard.render.com) -> **New +** -> **Web Service** (or **Blueprint** using `render.yaml`).
   - Select `Sarvepalliaudi/qshield-pqc-tls-auditor`.
   - Set **Runtime** to `Docker`, **Instance Type** to `Free`, **Root Directory** to `.` (repository root), and **Health Check Path** to `/`.
4. **Verify & Update Badge:** Once Render completes the multi-stage Docker build, verify `GET /` returns the audit form and update the placeholder badge URL (`https://qshield-audit.onrender.com`) with your live Render endpoint.

---

## 8. Issue Classification: Organization Audit vs. Bug Bounty Scope

`qshield-audit` is a **passive posture & cryptographic readiness auditor** designed for authorized blue-team assessments, university/enterprise DevSecOps hardening, and NIST IR 8547 migration planning. Understanding how findings classify avoids invalid bug bounty submissions:

| Tier | Findings | Report to Organization? | Bug Bounty Eligible? |
| :--- | :--- | :--- | :--- |
| **Tier 1: Immediate Transport / Auth Defect** | Cleartext HTTP (`http://`), broken/incomplete TLS certificate chains (`UnknownIssuer`), wildcard CORS (`*`) on sensitive endpoints, authenticated session cookies missing `HttpOnly`/`Secure` | **Yes** — High/Critical IT & DevOps remediation | **Only with a working exploit PoC** demonstrating real impact (public telemetry cookies like `_octo` are out-of-scope) |
| **Tier 2: Defense-in-Depth Hardening** | Missing `Permissions-Policy`, `Referrer-Policy`, `X-Frame-Options`, `Server`/`X-Powered-By` banners, CSP `style-src 'unsafe-inline'` without an XSS PoC | **Yes** — Standard security hardening ticket | **No** — Automated scanner outputs and missing best-practice headers are explicitly out-of-scope in public bounty programs |
| **Tier 3: Strategic PQC Migration** | Classical `X25519`/`ECDHE`/`RSA` key exchange without FIPS 203 `ML-KEM-768` (`0x11EC`/`0x11EB`) | **Yes** — NIST IR 8547 (Oct 2026) HNDL migration roadmap | **No** — Architectural cryptographic upgrade advisory |

---

## 9. Web Scope Guard, Anti-Abuse Controls & Legal License

When running as a hosted service (`--serve`), `qshield-audit` enforces strict defensive guardrails so a public demo cannot be abused as an open scanning proxy:

1. **Operator Attribution Separation & Liability Notice:**
   - Neither the web form nor CLI pre-fills the software author's name. Every session requires the active operator to enter their own Operator Name, Organization/University, and explicit authorization consent.
   - Both the web UI and `AUDIT_REPORT.md` display the disclaimer: *"Scan initiated by the listed Session Operator. The operator is solely responsible for ensuring explicit written authorization prior to testing any target."*
2. **Scope Guard Allowlist (`403 Forbidden`):**
   - By default, `--serve` permits only `example.com`, `example.org`, `example.net`, `localhost`, and `127.0.0.1`.
   - Administrators can allow additional authorized hosts by setting the `ALLOWED_TARGETS` environment variable (comma-separated, e.g., `ALLOWED_TARGETS=staging.myorg.internal,demo.myorg.org`).
   - Any non-allowlisted domain returns **HTTP 403 Forbidden** with instructions to use the local CLI binary for authorized infrastructure.
3. **SSRF & Private CIDR Filter:**
   - Blocks cloud metadata (`169.254.169.254`, `169.254.0.0/16`) and RFC 1918 private networks (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) both at URL validation and post-DNS resolution.
   - Disables HTTP redirects in web mode and enforces a strict **5-second request timeout** with zero crawling or active payloads.
4. **In-Memory Rate Limiting (`429 Too Many Requests`):**
   - Enforces a sliding window of **5 scans per 60 seconds per client IP**.
5. **License (`LICENSE`):**
   - Distributed under the **MIT License** (`Copyright (c) 2026 Sarvepalli Audi Siva Bhanuvardhan`) with an **Authorized Defensive Use Only** clause.



