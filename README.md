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

# qshield-audit — Q-Shield PQC-TLS & OWASP Security Auditor

> **Proprietary Notice:** "Specified, architected, and exclusively engineered by Sarvepalli Audi Siva Bhanuvardhan. This specification and dual hardware-software architecture is original work created solely for this application."

A high-performance, zero-bloat hardware-to-software security auditing engine built in **Rust** and **Verilog**, engineered on the **Linux/Unix & VLC philosophy**: deterministic logic, zero ANSI terminal colors, zero heavy UI dependencies, fast single-pass execution, and pipe-friendly plain-text output.

---

## Author & Internship Credentials

- **Tool Name:** `qshield-audit` (Q-Shield PQC-TLS & OWASP Security Auditor)
- **Author:** **Sarvepalli Audi Siva Bhanuvardhan**
- **University:** B.Tech Computer Science and Engineering (Cybersecurity), Final Year (7th Semester), **Dhanalakshmi Srinivasan University**, Tiruchirappalli, Tamil Nadu, India
- **Internship:** Cybersecurity Virtual Internship — **Dev/Craft by Fennark** ([https://devcraft.fennark.xyz](https://devcraft.fennark.xyz)) | **Intern ID:** `DEV-CRAFT-BQ2VPH` | **Task 3: Security Audit**
- **LinkedIn:** [https://www.linkedin.com/in/audi-siva-bhanuvardhan-sarvepalli-4598a8289/](https://www.linkedin.com/in/audi-siva-bhanuvardhan-sarvepalli-4598a8289/)
- **GitHub:** [https://github.com/Sarvepalliaudi](https://github.com/Sarvepalliaudi)
- **Repository:** [https://github.com/Sarvepalliaudi/qshield-pqc-tls-auditor](https://github.com/Sarvepalliaudi/qshield-pqc-tls-auditor)

---

## Dual Hardware-to-Software Architecture

```text
  [Operator]
      |
      v  (1) First-Run Authorization Gate -> operator_profile.json
  +---+---------------------------------------------------------------+
  | qshield-audit (Rust / tokio / reqwest + rustls-tls / clap)        |
  |                                                                   |
  |  [STAGE 1/4] Target Reachability & Passive HTTP Handshake         |
  |  [STAGE 2/4] 6 OWASP Headers + Set-Cookie / Banner / CORS Check   |
  |  [STAGE 3/4] Post-Quantum TLS (NIST IR 8547 / FIPS 203 ML-KEM-768)|
  |  [STAGE 4/4] Silicon Cipher Policy Mapping                        |
  +---+-------------------------------+-------------------------------+
      |                               |
      v                               v
  AUDIT_REPORT.md             hardware/tls_cipher_gate.v
  (Score, Grade A-F,          (Inputs: clk, rst_n, tls_version, cipher_id)
   Nginx & Apache Fixes)      (Outputs: pqc_safe, classical_vuln, allow_packet)
```

---

## Core Capabilities

1. **Zero-Bloat Linux/VLC CLI (`src/main.rs`, `src/guide.rs`):**
   - Zero color crates (`colored`, `console`, `indicatif`, `tui` avoided).
   - Clean plain-text markers (`[OK]`, `[WARN]`, `[FAIL]`, `[STAGE 1/4]`) ready for `| grep` and `> out.txt`.
   - Interactive `--guide` mode (auto-enabled on first run) with ASCII progress bars (`[####------] 40%`) and stage-by-stage explanations.
2. **First-Run Operator Login Gate (`src/auth.rs`):**
   - Prompts via `std::io::stdin()` for Operator Full Name, Organization / University, and explicit `AUTHORIZED` consent before persisting `operator_profile.json`.
   - Supports `--reset-login` to clear and re-authenticate.
3. **Passive OWASP & Web Vulnerability Audit (`src/auditor.rs`, `src/report.rs`):**
   - Evaluates `Strict-Transport-Security`, `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, and `Permissions-Policy` with a deterministic `0–100` score and `A`–`F` grade.
   - Detects missing `HttpOnly`/`Secure`/`SameSite` on `Set-Cookie`, `Server`/`X-Powered-By` banner leakage, and wildcard `Access-Control-Allow-Origin: *`.
   - Exports `AUDIT_REPORT.md` with exact **Nginx** and **Apache** remediation blocks.
4. **Live Post-Quantum Cryptography (PQC-TLS) & Verilog Silicon Gate (`src/auditor.rs`, `hardware/tls_cipher_gate.v`):**
   - Uses `rustls` with the **`aws-lc-rs`** crypto provider (`prefer-post-quantum`) to inspect the live TLS handshake stream and record negotiated protocol version (`0x0304` / `0x0303`), cipher suite (`TLS13_AES_128_GCM_SHA256`, `TLS13_AES_256_GCM_SHA384`, `TLS13_CHACHA20_POLY1305_SHA256`), and key-exchange group ID (`16'h11EC` `X25519MLKEM768`, `16'h001D` `X25519`, `16'h0017` `secp256r1`).
   - Dynamically computes `pqc_safe`, `classical_vuln`, and `allow_packet` against NIST IR 8547 (October 2026) and FIPS 203, alongside a synthesizable `< 60`-line Verilog gate (`tls_cipher_gate`) and `iverilog` testbench (`hardware/tb_tls_cipher_gate.v`).
5. **Hosted Web Scope Guard, Anti-Abuse & Operator Attribution Protection (`src/web.rs`, `LICENSE`):**
   - **No pre-filled author identity:** Web form and CLI strictly require the active operator to enter their own name, organization, and explicit authorization consent. Generated reports display a prominent liability disclaimer and separate Session Operator metadata from the Software Author footer.
   - **Scope Guard Allowlist:** `--serve` restricts scans to RFC 2606 authorized test domains (`example.com`, `example.org`, `example.net`, `localhost`, `127.0.0.1`) plus comma-separated hosts in `ALLOWED_TARGETS`. Unauthorized domains return `403 Forbidden`.
   - **SSRF & Rate-Limit Controls:** Blocks cloud metadata (`169.254.169.254`, `169.254.0.0/16`) and RFC 1918 private CIDRs (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), enforces a strict `5`-second timeout with zero redirects/crawling, and limits each client IP to `5` scans per `60` seconds (`429 Too Many Requests`).
   - **License:** MIT License with an **Authorized Defensive Use Only** clause in [LICENSE](LICENSE).

---

## Build & Run Commands

### Clone, Build & Test Rust Engine
```bash
git clone https://github.com/Sarvepalliaudi/qshield-pqc-tls-auditor.git
cd qshield-pqc-tls-auditor
cargo test
cargo build --release
```

### Run Security Audit
```bash
# Default audit (https://example.com -> AUDIT_REPORT.md)
./target/release/qshield-audit

# Interactive step-by-step guide on custom target
./target/release/qshield-audit --url https://example.com --guide --output AUDIT_REPORT.md

# Reset operator authorization profile
./target/release/qshield-audit --reset-login

# Launch lightweight zero-JS HTML web portal on 0.0.0.0:$PORT (default 8080)
./target/release/qshield-audit --serve
```

### Simulate Verilog Hardware Cipher Gate
```bash
iverilog -o hardware/sim_cipher_gate.vvp hardware/tls_cipher_gate.v hardware/tb_tls_cipher_gate.v
vvp hardware/sim_cipher_gate.vvp
```

---

## Live Cloud Deployment (Render.com Free Tier)

[![Live Status](https://img.shields.io/badge/Render-Live%20Web%20Service%20(Replace%20with%20Live%20URL)-brightgreen)](https://qshield-audit.onrender.com)

`qshield-audit` includes a multi-stage `Dockerfile` and `render.yaml` Blueprint to host the zero-JavaScript `--serve` portal (`GET /` and `POST /audit`) on **Render.com Free Tier**:

1. Push this repository to [https://github.com/Sarvepalliaudi/qshield-pqc-tls-auditor](https://github.com/Sarvepalliaudi/qshield-pqc-tls-auditor).
2. Log in to [Render.com](https://render.com) and click **New + -> Web Service** (or **Blueprint** using `render.yaml`).
3. Connect `Sarvepalliaudi/qshield-pqc-tls-auditor` and confirm:
   - **Runtime:** `Docker`
   - **Plan:** `Free`
   - **Root Directory:** `.` (repository root)
   - **Health Check Path:** `/`
4. Click **Create Web Service**. Render builds the `--release` binary via `Dockerfile`, binds to `0.0.0.0:$PORT` (default `8080`), and serves the live portal.
5. Replace `https://qshield-audit.onrender.com` in the badge above with your deployed `*.onrender.com` URL.

---

## Repository Structure

```text
qshield-pqc-tls-auditor/
├── .gitignore
├── Cargo.toml
├── Cargo.lock
├── Dockerfile
├── LICENSE
├── render.yaml
├── README.md
├── AUDIT_REPORT.md
├── docs/
│   └── USER_MANUAL.md
├── hardware/
│   ├── tls_cipher_gate.v
│   └── tb_tls_cipher_gate.v
└── src/
    ├── main.rs
    ├── auth.rs
    ├── guide.rs
    ├── auditor.rs
    ├── report.rs
    └── web.rs
```

See [docs/USER_MANUAL.md](docs/USER_MANUAL.md) for complete installation, walkthroughs, and remediation documentation.

---

**Keywords:** Post-Quantum Cryptography, PQC-TLS, NIST IR 8547, FIPS 203, ML-KEM-768, X25519MLKEM768, SecP256r1MLKEM768, Shor's Algorithm, Harvest Now Decrypt Later, OWASP Security Headers, HTTP Security Audit, Rust Cybersecurity CLI, Verilog Hardware Security Gate, RTL Cipher Policy, Dhanalakshmi Srinivasan University, Tiruchirappalli, Sarvepalli Audi Siva Bhanuvardhan, Dev/Craft by Fennark, DEV-CRAFT-BQ2VPH
