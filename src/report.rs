// =============================================================================
// Tool Name: qshield-audit (Q-Shield PQC-TLS & OWASP Security Auditor)
// Proprietary Notice: "Specified, architected, and exclusively engineered by
// Sarvepalli Audi Siva Bhanuvardhan. This specification and dual
// hardware-software architecture is original work created solely for this
// application."
// Author: Sarvepalli Audi Siva Bhanuvardhan
// University: B.Tech Computer Science and Engineering (Cybersecurity), Final Year
//             (7th Semester), Dhanalakshmi Srinivasan University,
//             Tiruchirappalli, Tamil Nadu, India
// Internship: Cybersecurity Virtual Internship — Dev/Craft by Fennark
//             (https://devcraft.fennark.xyz) | Intern ID: DEV-CRAFT-BQ2VPH |
//             Task 3: Security Audit
// LinkedIn: https://www.linkedin.com/in/audi-siva-bhanuvardhan-sarvepalli-4598a8289/
// GitHub: https://github.com/Sarvepalliaudi
// =============================================================================

use crate::auditor::{AuditResult, CheckStatus};
use crate::auth::OperatorProfile;
use std::fs;

fn escape_md_cell(input: &str) -> String {
    input.replace('|', "\\|").replace('\n', "<br>")
}

fn format_table_observed(observed: &str) -> String {
    const MAX_LEN: usize = 90;
    let char_count = observed.chars().count();
    if char_count <= MAX_LEN {
        escape_md_cell(observed)
    } else {
        let truncated: String = observed.chars().take(MAX_LEN).collect();
        escape_md_cell(&format!("{}... (see Section 3)", truncated))
    }
}

pub fn render_markdown_report(operator: &OperatorProfile, audit: &AuditResult) -> String {
    let mut md = String::new();

    md.push_str("# qshield-audit — Security Audit Report\n\n");
    md.push_str("> **Tool Name:** `qshield-audit` (Q-Shield PQC-TLS & OWASP Security Auditor)  \n");
    md.push_str("> **Proprietary Notice:** \"Specified, architected, and exclusively engineered by Sarvepalli Audi Siva Bhanuvardhan. This specification and dual hardware-software architecture is original work created solely for this application.\"  \n");
    md.push_str("> **Disclaimer:** Scan initiated by the listed Session Operator. The operator is solely responsible for ensuring explicit written authorization prior to testing any target.\n\n");

    md.push_str("## 1. Audit Metadata & Executive Summary\n\n");
    md.push_str("| Field | Value |\n");
    md.push_str("| :--- | :--- |\n");
    md.push_str(&format!(
        "| **Session Operator** | {} |\n",
        escape_md_cell(&operator.full_name)
    ));
    md.push_str(&format!(
        "| **Operator Organization / University** | {} |\n",
        escape_md_cell(&operator.organization)
    ));
    md.push_str(&format!(
        "| **Authorization Scope** | {} ({}) |\n",
        escape_md_cell(&operator.authorization_scope),
        escape_md_cell(&operator.authorized_at_utc)
    ));
    md.push_str(&format!(
        "| **Requested Target URL** | `{}` |\n",
        escape_md_cell(&audit.target_url)
    ));
    md.push_str(&format!(
        "| **Resolved Final URL** | `{}` |\n",
        escape_md_cell(&audit.final_url)
    ));
    md.push_str(&format!(
        "| **HTTP Response** | `{}` ({}) |\n",
        audit.http_status,
        escape_md_cell(&audit.http_version)
    ));
    md.push_str(&format!(
        "| **Negotiated TLS Version** | `{}` |\n",
        escape_md_cell(&audit.hardware_gate.tls_version_label)
    ));
    md.push_str(&format!(
        "| **Negotiated Cipher Suite** | `{}` |\n",
        escape_md_cell(&audit.hardware_gate.cipher_suite_name)
    ));
    md.push_str(&format!(
        "| **Negotiated Key-Exchange Group** | `{}` |\n",
        escape_md_cell(&audit.hardware_gate.cipher_id_label)
    ));
    md.push_str(&format!("| **Timestamp (UTC)** | `{}` |\n", audit.timestamp_utc));
    md.push_str(&format!("| **Execution Latency** | `{} ms` |\n", audit.latency_ms));
    md.push_str(&format!(
        "| **Final Security Score** | **{} / 100** (Grade **{}**) |\n\n",
        audit.score, audit.grade
    ));

    md.push_str("## 2. Security Findings & Remediation Matrix\n\n");
    md.push_str("| Check | Category | Status | Severity | Observed | Nginx Fix | Apache Fix |\n");
    md.push_str("| :--- | :--- | :--- | :--- | :--- | :--- | :--- |\n");

    for finding in &audit.findings {
        md.push_str(&format!(
            "| {} | {} | `{}` | {} | {} | `{}` | `{}` |\n",
            escape_md_cell(&finding.name),
            escape_md_cell(&finding.category),
            finding.status.tag(),
            finding.severity.as_str(),
            format_table_observed(&finding.observed),
            escape_md_cell(&finding.nginx_fix),
            escape_md_cell(&finding.apache_fix),
        ));
    }
    md.push('\n');

    md.push_str("## 3. Actionable Remediation Snippets (Nginx & Apache)\n\n");
    let action_items: Vec<_> = audit
        .findings
        .iter()
        .filter(|f| f.status != CheckStatus::Ok)
        .collect();

    if action_items.is_empty() {
        md.push_str("All audited OWASP headers, passive checks, and PQC-TLS checks passed with `[OK]`.\n\n");
    } else {
        for finding in action_items {
            md.push_str(&format!(
                "### {} `{}` ({})\n\n",
                finding.status.tag(),
                finding.name,
                finding.severity.as_str()
            ));
            md.push_str(&format!("- **Observed:** {}\n", finding.observed));
            md.push_str(&format!("- **Recommendation:** {}\n\n", finding.recommendation));
            md.push_str("**Nginx (`server {}` block):**\n```nginx\n");
            md.push_str(&finding.nginx_fix);
            md.push_str("\n```\n\n");
            md.push_str("**Apache (`VirtualHost` / `.htaccess`):**\n```apache\n");
            md.push_str(&finding.apache_fix);
            md.push_str("\n```\n\n");
        }
    }

    md.push_str("## 4. Hardware Silicon Cipher Policy Verification (`hardware/tls_cipher_gate.v`)\n\n");
    md.push_str("Deterministic hardware policy mapping from live TLS handshake telemetry per NIST IR 8547 (October 2026) and FIPS 203:\n\n");
    md.push_str("| Signal / Telemetry | Value | Meaning |\n");
    md.push_str("| :--- | :--- | :--- |\n");
    md.push_str(&format!(
        "| `tls_version[15:0]` | `{}` | Live negotiated TLS protocol version |\n",
        escape_md_cell(&audit.hardware_gate.tls_version_label)
    ));
    md.push_str(&format!(
        "| `cipher_id[15:0]` | `{}` | Live negotiated key-exchange group identifier |\n",
        escape_md_cell(&audit.hardware_gate.cipher_id_label)
    ));
    md.push_str(&format!(
        "| `cipher_suite` | `{}` | Live negotiated AEAD cipher suite |\n",
        escape_md_cell(&audit.hardware_gate.cipher_suite_name)
    ));
    md.push_str(&format!(
        "| `pqc_safe` | `{}` | Asserted `1` only for TLS 1.3 (`16'h0304`) + ML-KEM-768 (`16'h11EC` / `16'h11EB`) |\n",
        audit.hardware_gate.pqc_safe
    ));
    md.push_str(&format!(
        "| `classical_vuln` | `{}` | Asserted `1` when vulnerable to Shor's algorithm or downgrade |\n",
        audit.hardware_gate.classical_vuln
    ));
    md.push_str(&format!(
        "| `allow_packet` | `{}` | Hardware gate forwarding decision (`1` = Allow, `0` = Drop) |\n\n",
        audit.hardware_gate.allow_packet
    ));
    md.push_str(&format!("**Policy Verdict:** {}\n\n", audit.hardware_gate.policy_note));

    md.push_str("## 5. Issue Classification Guide (Internal Security Audit vs. Bug Bounty Scope)\n\n");
    md.push_str("| Tier | Example Findings | Report to Organization? | Bug Bounty Eligible? |\n");
    md.push_str("| :--- | :--- | :--- | :--- |\n");
    md.push_str("| **Tier 1: Immediate Transport / Auth Defect** | Cleartext HTTP, broken/untrusted TLS PKI (`UnknownIssuer`), wildcard CORS on authenticated APIs, session tokens missing `HttpOnly`/`Secure` | Yes — High/Critical IT & DevOps remediation | Only with verified exploit PoC & impact (telemetry cookies like `_octo` are out-of-scope) |\n");
    md.push_str("| **Tier 2: Defense-in-Depth Hardening** | Missing `Permissions-Policy`, `Referrer-Policy`, `X-Frame-Options`, `Server`/`X-Powered-By` banners, CSP `style-src 'unsafe-inline'` | Yes — Standard blue-team / compliance hardening ticket | No — Automated scanner & missing-header findings without PoC are out-of-scope |\n");
    md.push_str("| **Tier 3: Strategic PQC Migration** | Classical `X25519`/`ECDHE`/`RSA` without FIPS 203 `ML-KEM-768` (`0x11EC`/`0x11EB`) | Yes — NIST IR 8547 (Oct 2026) HNDL roadmap | No — Architectural crypto upgrade advisory |\n\n");

    md.push_str("---\n\n");
    md.push_str("## Software Author & Engineering Attribution\n\n");
    md.push_str("- **Tool Architected & Engineered by:** Sarvepalli Audi Siva Bhanuvardhan\n");
    md.push_str("- **University:** B.Tech CSE Cybersecurity, Dhanalakshmi Srinivasan University, Tiruchirappalli, Tamil Nadu, India\n");
    md.push_str("- **Internship:** Dev/Craft by Fennark (`DEV-CRAFT-BQ2VPH`) | Task 3: Security Audit\n");
    md.push_str("- **LinkedIn:** https://www.linkedin.com/in/audi-siva-bhanuvardhan-sarvepalli-4598a8289/\n");
    md.push_str("- **GitHub:** https://github.com/Sarvepalliaudi\n");

    md
}

pub fn write_report(path: &str, content: &str) -> Result<(), String> {
    fs::write(path, content).map_err(|e| format!("Failed to write report '{}': {}", path, e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auditor::{eval_verilog_cipher_gate, Finding, Severity, TlsHandshakeTelemetry};

    #[test]
    fn test_report_contains_required_credentials_and_tables() {
        let operator = OperatorProfile {
            full_name: "Alice Evaluator".to_string(),
            organization: "Security Lab".to_string(),
            authorization_scope: "Authorized".to_string(),
            authorized_at_utc: "2026-11-25T04:00:00Z".to_string(),
        };

        let tls = TlsHandshakeTelemetry {
            tls_version_u16: 0x0304,
            tls_version_name: "TLS 1.3".to_string(),
            cipher_suite_name: "TLS13_AES_128_GCM_SHA256".to_string(),
            kx_group_id: 0x11EC,
            kx_group_name: "X25519MLKEM768".to_string(),
        };

        let audit = AuditResult {
            target_url: "https://example.com".to_string(),
            final_url: "https://example.com/".to_string(),
            http_status: 200,
            http_version: "HTTP/2.0".to_string(),
            latency_ms: 42,
            timestamp_utc: "2026-11-25T04:00:01Z".to_string(),
            score: 85,
            grade: 'B',
            findings: vec![Finding {
                category: "OWASP Header".to_string(),
                name: "Strict-Transport-Security".to_string(),
                status: CheckStatus::Fail,
                severity: Severity::High,
                observed: "Missing".to_string(),
                recommendation: "Add HSTS".to_string(),
                nginx_fix: "add_header Strict-Transport-Security \"max-age=63072000\" always;"
                    .to_string(),
                apache_fix: "Header always set Strict-Transport-Security \"max-age=63072000\""
                    .to_string(),
            }],
            tls_telemetry: tls,
            hardware_gate: eval_verilog_cipher_gate(
                0x0304,
                0x11EC,
                "TLS13_AES_128_GCM_SHA256",
                "X25519MLKEM768",
            ),
        };

        let md = render_markdown_report(&operator, &audit);
        assert!(md.contains("**Disclaimer:** Scan initiated by the listed Session Operator."));
        assert!(md.contains("Tool Architected & Engineered by:"));
        assert!(md.contains("DEV-CRAFT-BQ2VPH"));
        assert!(md.contains("Dhanalakshmi Srinivasan University, Tiruchirappalli"));
        assert!(md.contains("TLS13_AES_128_GCM_SHA256"));
        assert!(md.contains("16'h11EC (X25519MLKEM768)"));
        assert!(md.contains("Nginx Fix"));
        assert!(md.contains("Apache Fix"));
    }

    #[test]
    fn test_table_truncates_observed_over_90_chars_and_keeps_section_3_full() {
        let long_csp = "default-src 'self'; script-src https://a.example.com https://b.example.com https://c.example.com | end";
        let truncated = format_table_observed(long_csp);
        assert!(truncated.ends_with("... (see Section 3)"));
        assert!(!truncated.contains("https://c.example.com"));

        let operator = OperatorProfile {
            full_name: "Alice Evaluator".to_string(),
            organization: "Security Lab".to_string(),
            authorization_scope: "Authorized".to_string(),
            authorized_at_utc: "2026-11-25T04:00:00Z".to_string(),
        };
        let tls = TlsHandshakeTelemetry {
            tls_version_u16: 0x0304,
            tls_version_name: "TLS 1.3".to_string(),
            cipher_suite_name: "TLS13_AES_128_GCM_SHA256".to_string(),
            kx_group_id: 0x001D,
            kx_group_name: "X25519".to_string(),
        };
        let audit = AuditResult {
            target_url: "https://example.com".to_string(),
            final_url: "https://example.com/".to_string(),
            http_status: 200,
            http_version: "HTTP/2.0".to_string(),
            latency_ms: 42,
            timestamp_utc: "2026-11-25T04:00:01Z".to_string(),
            score: 85,
            grade: 'B',
            findings: vec![Finding {
                category: "OWASP Header".to_string(),
                name: "Content-Security-Policy".to_string(),
                status: CheckStatus::Warn,
                severity: Severity::Medium,
                observed: long_csp.to_string(),
                recommendation: "Tighten CSP".to_string(),
                nginx_fix: "add_header Content-Security-Policy \"default-src 'self';\" always;"
                    .to_string(),
                apache_fix: "Header always set Content-Security-Policy \"default-src 'self';\""
                    .to_string(),
            }],
            tls_telemetry: tls,
            hardware_gate: eval_verilog_cipher_gate(
                0x0304,
                0x001D,
                "TLS13_AES_128_GCM_SHA256",
                "X25519",
            ),
        };

        let md = render_markdown_report(&operator, &audit);
        let section2 = md.split("## 3.").next().unwrap();
        let section3 = md.split("## 3.").nth(1).unwrap();
        assert!(section2.contains("... (see Section 3)"));
        assert!(section3.contains(long_csp));
    }
}
