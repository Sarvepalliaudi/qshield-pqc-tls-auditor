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

use crate::auditor::{self, AuditResult, CheckStatus};
use crate::auth::OperatorProfile;
use crate::report;
use axum::extract::{ConnectInfo, Form, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse};
use axum::routing::{get, post};
use axum::Router;
use serde::Deserialize;
use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use url::Url;

const BUILTIN_ALLOWED_HOSTS: &[&str] = &[
    "example.com",
    "example.org",
    "example.net",
    "localhost",
    "127.0.0.1",
];

const SCOPE_GUARD_MSG: &str = "Blocked by Scope Guard: Public web demo restricts scans to RFC 2606 authorized test domains (example.com) or administrator-allowlisted targets. Use the local CLI binary to audit your own authorized infrastructure.";
const RATE_LIMIT_MAX_REQUESTS: usize = 5;
const RATE_LIMIT_WINDOW: Duration = Duration::from_secs(60);
const WEB_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone, Default)]
pub struct WebState {
    pub rate_limiter: Arc<Mutex<HashMap<String, VecDeque<Instant>>>>,
}

#[derive(Debug, Deserialize)]
pub struct AuditForm {
    pub operator_name: String,
    pub organization: String,
    pub target_url: String,
    pub authorized: Option<String>,
}

pub fn escape_html(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(ch),
        }
    }
    out
}

fn format_observed_cell(observed: &str) -> String {
    const LIMIT: usize = 120;
    if observed.chars().count() <= LIMIT {
        return escape_html(observed);
    }
    let preview: String = observed.chars().take(LIMIT).collect();
    let total_chars = observed.chars().count();
    format!(
        "<details><summary>{}... ({} chars — click to expand)</summary><pre class=\"wrap-pre\">{}</pre></details>",
        escape_html(&preview),
        total_chars,
        escape_html(observed)
    )
}

fn status_badge(status: CheckStatus) -> &'static str {
    match status {
        CheckStatus::Ok => "<span class=\"badge badge-ok\">[OK]</span>",
        CheckStatus::Warn => "<span class=\"badge badge-warn\">[WARN]</span>",
        CheckStatus::Fail => "<span class=\"badge badge-fail\">[FAIL]</span>",
    }
}

pub fn parse_allowed_hosts(extra_env: Option<&str>) -> Vec<String> {
    let mut hosts: Vec<String> = BUILTIN_ALLOWED_HOSTS
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    if let Some(raw) = extra_env {
        for item in raw.split(',') {
            let h = item.trim().to_ascii_lowercase();
            if !h.is_empty() && !hosts.contains(&h) {
                hosts.push(h);
            }
        }
    }
    hosts
}

pub fn validate_web_target_syntax_and_scope(
    raw_url: &str,
    extra_allowed_env: Option<&str>,
) -> Result<(String, String, u16, bool), (StatusCode, String)> {
    let normalized = auditor::normalize_url(raw_url);
    let parsed = Url::parse(&normalized).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            format!("Invalid target URL '{}': {}", raw_url, e),
        )
    })?;

    let scheme = parsed.scheme().to_ascii_lowercase();
    if scheme != "http" && scheme != "https" {
        return Err((
            StatusCode::BAD_REQUEST,
            "Only http:// and https:// URLs are supported.".to_string(),
        ));
    }

    let host = parsed
        .host_str()
        .ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                "Target URL must include a valid hostname.".to_string(),
            )
        })?
        .trim_matches(['[', ']'])
        .to_ascii_lowercase();

    let port = parsed.port_or_known_default().unwrap_or(443);
    let is_explicit_local = host == "localhost" || host == "127.0.0.1";

    if let Ok(ip) = host.parse::<IpAddr>() {
        if auditor::is_blocked_ssrf_ip(ip, is_explicit_local) {
            return Err((
                StatusCode::FORBIDDEN,
                format!(
                    "Blocked by SSRF Guard: Private, link-local, and cloud metadata IP ranges (such as {}) are prohibited in web mode.",
                    ip
                ),
            ));
        }
    }

    let allowed = parse_allowed_hosts(extra_allowed_env);
    if !allowed.iter().any(|h| h == &host) {
        return Err((StatusCode::FORBIDDEN, SCOPE_GUARD_MSG.to_string()));
    }

    Ok((normalized, host, port, is_explicit_local))
}

async fn verify_resolved_ips_safe(
    host: &str,
    port: u16,
    allow_loopback: bool,
) -> Result<(), (StatusCode, String)> {
    if host.parse::<IpAddr>().is_ok() {
        return Ok(());
    }

    let addrs = tokio::net::lookup_host((host, port)).await.map_err(|e| {
        (
            StatusCode::BAD_GATEWAY,
            format!("DNS resolution failed for {}: {}", host, e),
        )
    })?;

    for sock in addrs {
        if auditor::is_blocked_ssrf_ip(sock.ip(), allow_loopback) {
            return Err((
                StatusCode::FORBIDDEN,
                format!(
                    "Blocked by SSRF Guard: Host '{}' resolved to restricted internal/metadata IP {}.",
                    host,
                    sock.ip()
                ),
            ));
        }
    }
    Ok(())
}

pub fn check_rate_limit(
    limiter: &Mutex<HashMap<String, VecDeque<Instant>>>,
    client_ip: &str,
    now: Instant,
) -> bool {
    let mut map = match limiter.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    let queue = map.entry(client_ip.to_string()).or_default();
    while let Some(&front) = queue.front() {
        if now.duration_since(front) >= RATE_LIMIT_WINDOW {
            queue.pop_front();
        } else {
            break;
        }
    }
    if queue.len() >= RATE_LIMIT_MAX_REQUESTS {
        return false;
    }
    queue.push_back(now);
    true
}

fn extract_client_ip(headers: &HeaderMap, peer: Option<SocketAddr>) -> String {
    if let Some(xff) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
        if let Some(first) = xff.split(',').next().map(str::trim).filter(|s| !s.is_empty()) {
            return first.to_string();
        }
    }
    peer.map(|addr| addr.ip().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

fn page_head(title: &str) -> String {
    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{}</title>
<style>
*{{box-sizing:border-box;}}
body{{background:#0b0b0b;color:#e5e5e5;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:14px;line-height:1.55;margin:0;padding:24px;}}
.wrap{{max-width:1040px;margin:0 auto;}}
.box{{background:#121212;border:1px solid #2f2f2f;padding:18px;margin-bottom:18px;}}
.box-error{{border-color:#fff;background:#1a1a1a;}}
.disclaimer{{border:1px dashed #8c8c8c;background:#161616;padding:10px 12px;margin-top:10px;font-size:12px;color:#e0e0e0;}}
h1,h2,h3{{margin:0 0 10px 0;font-weight:700;color:#fff;}}
h1{{font-size:18px;border-bottom:1px solid #2f2f2f;padding-bottom:8px;letter-spacing:0.3px;}}
h2{{font-size:15px;margin-top:4px;}}
h3{{font-size:14px;margin-top:14px;}}
label{{display:block;margin:12px 0 4px 0;font-weight:700;}}
input[type=text],input[type=url]{{width:100%;background:#080808;color:#fff;border:1px solid #444;padding:9px 10px;font-family:inherit;font-size:14px;}}
input[type=text]:focus,input[type=url]:focus{{outline:none;border-color:#fff;}}
button{{margin-top:14px;background:#e5e5e5;color:#0b0b0b;border:1px solid #fff;padding:9px 18px;font-family:inherit;font-weight:700;cursor:pointer;}}
button:hover{{background:#fff;}}
.kpi-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:10px;margin-bottom:16px;}}
.kpi{{background:#0b0b0b;border:1px solid #333;padding:12px;}}
.kpi-label{{font-size:11px;color:#9a9a9a;text-transform:uppercase;letter-spacing:0.6px;}}
.kpi-val{{font-size:18px;font-weight:700;color:#fff;margin-top:4px;}}
table{{width:100%;border-collapse:collapse;margin-top:8px;font-size:13px;}}
th,td{{border:1px solid #2e2e2e;padding:8px 10px;text-align:left;vertical-align:top;word-break:break-word;}}
th{{background:#1a1a1a;color:#fff;white-space:nowrap;}}
pre{{background:#080808;border:1px solid #2b2b2b;padding:10px;overflow-x:auto;font-size:12px;margin:6px 0 12px 0;color:#e5e5e5;}}
.wrap-pre{{white-space:pre-wrap;word-break:break-all;}}
.badge{{display:inline-block;padding:1px 6px;font-weight:700;font-size:12px;white-space:nowrap;}}
.badge-ok{{border:1px solid #8c8c8c;color:#e5e5e5;}}
.badge-warn{{border:1px dashed #cfcfcf;color:#fff;}}
.badge-fail{{background:#e5e5e5;color:#0b0b0b;border:1px solid #fff;}}
details summary{{cursor:pointer;color:#d4d4d4;}}
details summary:hover{{color:#fff;}}
a{{color:#dcdcdc;}}
.muted{{color:#a3a3a3;font-size:12px;}}
.btn-link{{display:inline-block;border:1px solid #555;padding:6px 12px;text-decoration:none;margin-top:8px;}}
.btn-link:hover{{border-color:#fff;color:#fff;}}
.footer{{border-top:1px solid #2f2f2f;padding-top:12px;margin-top:24px;font-size:12px;color:#b0b0b0;}}
</style>
</head>
<body>
<div class="wrap">
<div class="box">
<h1>qshield-audit // Q-Shield PQC-TLS &amp; OWASP Security Auditor</h1>
<div class="muted">"Specified, architected, and exclusively engineered by Sarvepalli Audi Siva Bhanuvardhan. This specification and dual hardware-software architecture is original work created solely for this application."</div>
<div class="disclaimer"><strong>Disclaimer:</strong> Scan initiated by the listed Session Operator. The operator is solely responsible for ensuring explicit written authorization prior to testing any target.</div>
</div>
"#,
        escape_html(title)
    )
}

fn page_footer() -> &'static str {
    r#"<div class="footer">
Tool Architected &amp; Engineered by Sarvepalli Audi Siva Bhanuvardhan | B.Tech CSE Cybersecurity, Dhanalakshmi Srinivasan University, Tiruchirappalli | Dev/Craft by Fennark (DEV-CRAFT-BQ2VPH) | LinkedIn: <a href="https://www.linkedin.com/in/audi-siva-bhanuvardhan-sarvepalli-4598a8289/">https://www.linkedin.com/in/audi-siva-bhanuvardhan-sarvepalli-4598a8289/</a> | GitHub: <a href="https://github.com/Sarvepalliaudi">https://github.com/Sarvepalliaudi</a>
</div>
</div>
</body>
</html>
"#
}

pub fn render_index_html(error_msg: Option<&str>) -> String {
    let mut html = page_head("qshield-audit | PQC-TLS & OWASP Auditor");
    if let Some(err) = error_msg {
        html.push_str(&format!(
            "<div class=\"box box-error\"><strong>[FAIL]</strong> {}</div>\n",
            escape_html(err)
        ));
    }

    html.push_str(
        r#"<div class="box">
<h2>[AUTH &amp; TARGET] Passive Security Audit Console</h2>
<p class="muted">Zero-bloat single-pass passive HTTP/TLS inspection using live <code>rustls</code> (<code>aws-lc-rs</code>) handshake telemetry, 6 OWASP headers, Set-Cookie/Banner/CORS posture, NIST IR 8547 / FIPS 203 (<code>X25519MLKEM768</code>) readiness, and Verilog silicon cipher gate policy. Public web mode enforces Scope Guard (RFC 2606 allowlist + <code>ALLOWED_TARGETS</code>), SSRF CIDR blocking, 5s timeout, and 5 scans/min rate limiting.</p>
<form method="post" action="/audit">
  <label for="operator_name">Operator Name</label>
  <input id="operator_name" name="operator_name" type="text" placeholder="Enter your full name" required>

  <label for="organization">Organization / University</label>
  <input id="organization" name="organization" type="text" placeholder="Enter your organization or university" required>

  <label for="target_url">Target URL (Authorized Scope Guard Target)</label>
  <input id="target_url" name="target_url" type="url" value="https://example.com" required>

  <label style="font-weight:400;margin-top:12px;">
    <input type="checkbox" name="authorized" value="yes" required>
    <strong>[AUTHORIZED]</strong> I confirm explicit written authorization to perform a passive security header &amp; TLS posture audit on the target URL.
  </label>

  <button type="submit">[RUN PASSIVE AUDIT]</button>
</form>
</div>
<div class="box">
<h2>[PIPELINE] 4-Stage Deterministic Audit Architecture</h2>
<table>
  <tr><th>Stage</th><th>Verification Scope</th></tr>
  <tr><td>[STAGE 1/4]</td><td>Target Reachability, Scope Guard / SSRF Filter &amp; Live <code>aws-lc-rs</code> TLS Handshake Telemetry (5s timeout)</td></tr>
  <tr><td>[STAGE 2/4]</td><td>6 OWASP Headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy) + Set-Cookie / Banner / CORS</td></tr>
  <tr><td>[STAGE 3/4]</td><td>Live Post-Quantum TLS Inspection against NIST IR 8547 (Oct 2026) &amp; FIPS 203 (<code>X25519MLKEM768</code> / <code>16'h11EC</code>)</td></tr>
  <tr><td>[STAGE 4/4]</td><td>Dynamic Verilog Silicon Cipher Gate Verification (<code>hardware/tls_cipher_gate.v</code>)</td></tr>
</table>
</div>
"#,
    );

    html.push_str(page_footer());
    html
}

pub fn render_result_html(operator_name: &str, organization: &str, audit: &AuditResult) -> String {
    let mut html = page_head("qshield-audit | Audit Report");
    let gate_verdict = if audit.hardware_gate.allow_packet == 1 {
        "ALLOW (pqc_safe=1)"
    } else {
        "BLOCK (pqc_safe=0)"
    };

    html.push_str("<div class=\"box\">\n<h2>[SUMMARY] Audit Execution Scorecard</h2>\n");
    html.push_str("<div class=\"kpi-grid\">\n");
    html.push_str(&format!(
        "<div class=\"kpi\"><div class=\"kpi-label\">Security Score</div><div class=\"kpi-val\">{} / 100</div></div>\n",
        audit.score
    ));
    html.push_str(&format!(
        "<div class=\"kpi\"><div class=\"kpi-label\">Final Grade</div><div class=\"kpi-val\">Grade {}</div></div>\n",
        audit.grade
    ));
    html.push_str(&format!(
        "<div class=\"kpi\"><div class=\"kpi-label\">Latency</div><div class=\"kpi-val\">{} ms</div></div>\n",
        audit.latency_ms
    ));
    html.push_str(&format!(
        "<div class=\"kpi\"><div class=\"kpi-label\">Silicon Gate</div><div class=\"kpi-val\">{}</div></div>\n",
        gate_verdict
    ));
    html.push_str("</div>\n<table>\n");
    html.push_str(&format!(
        "<tr><th>Session Operator</th><td>{} (Scope: Authorized)</td></tr>\n",
        escape_html(operator_name)
    ));
    html.push_str(&format!(
        "<tr><th>Operator Organization / University</th><td>{}</td></tr>\n",
        escape_html(organization)
    ));
    html.push_str(&format!(
        "<tr><th>Target URL</th><td>{}</td></tr>\n",
        escape_html(&audit.target_url)
    ));
    html.push_str(&format!(
        "<tr><th>Final URL</th><td>{}</td></tr>\n",
        escape_html(&audit.final_url)
    ));
    html.push_str(&format!(
        "<tr><th>HTTP Response</th><td>{} ({})</td></tr>\n",
        audit.http_status,
        escape_html(&audit.http_version)
    ));
    html.push_str(&format!(
        "<tr><th>Negotiated TLS / Cipher / Key Exchange</th><td><code>{}</code> | <code>{}</code> | <code>{}</code></td></tr>\n",
        escape_html(&audit.hardware_gate.tls_version_label),
        escape_html(&audit.hardware_gate.cipher_suite_name),
        escape_html(&audit.hardware_gate.cipher_id_label)
    ));
    html.push_str(&format!(
        "<tr><th>Timestamp (UTC)</th><td>{}</td></tr>\n",
        escape_html(&audit.timestamp_utc)
    ));
    html.push_str("</table>\n</div>\n");

    html.push_str("<div class=\"box\">\n<h2>[STAGE 2 &amp; 3] OWASP Headers, Passive Vulns &amp; Live PQC-TLS (NIST IR 8547 / ML-KEM-768)</h2>\n");
    html.push_str("<table>\n<tr><th>Check</th><th>Category</th><th>Status</th><th>Severity</th><th>Observed</th></tr>\n");
    for f in &audit.findings {
        html.push_str(&format!(
            "<tr><td><strong>{}</strong></td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>\n",
            escape_html(&f.name),
            escape_html(&f.category),
            status_badge(f.status),
            f.severity.as_str(),
            format_observed_cell(&f.observed)
        ));
    }
    html.push_str("</table>\n</div>\n");

    html.push_str("<div class=\"box\">\n<h2>[STAGE 4] Hardware Silicon Cipher Gate (hardware/tls_cipher_gate.v)</h2>\n<table>\n");
    html.push_str(&format!(
        "<tr><th>tls_version[15:0]</th><td><code>{}</code></td></tr>\n",
        escape_html(&audit.hardware_gate.tls_version_label)
    ));
    html.push_str(&format!(
        "<tr><th>cipher_id[15:0]</th><td><code>{}</code></td></tr>\n",
        escape_html(&audit.hardware_gate.cipher_id_label)
    ));
    html.push_str(&format!(
        "<tr><th>cipher_suite</th><td><code>{}</code></td></tr>\n",
        escape_html(&audit.hardware_gate.cipher_suite_name)
    ));
    html.push_str(&format!(
        "<tr><th>Gate Outputs</th><td><code>pqc_safe={}</code>, <code>classical_vuln={}</code>, <code>allow_packet={}</code></td></tr>\n",
        audit.hardware_gate.pqc_safe,
        audit.hardware_gate.classical_vuln,
        audit.hardware_gate.allow_packet
    ));
    html.push_str(&format!(
        "<tr><th>Policy Verdict</th><td>{}</td></tr>\n",
        escape_html(&audit.hardware_gate.policy_note)
    ));
    html.push_str("</table>\n</div>\n");

    html.push_str("<div class=\"box\">\n<h2>[REMEDIATION] Copy-Paste Nginx &amp; Apache Fixes</h2>\n");
    let action_items: Vec<_> = audit
        .findings
        .iter()
        .filter(|f| f.status != CheckStatus::Ok)
        .collect();

    if action_items.is_empty() {
        html.push_str("<p>[OK] All evaluated checks passed.</p>\n");
    } else {
        for f in action_items {
            html.push_str(&format!(
                "<h3>{} {} ({})</h3>\n<p class=\"muted\">{}</p>\n",
                status_badge(f.status),
                escape_html(&f.name),
                f.severity.as_str(),
                escape_html(&f.recommendation)
            ));
            html.push_str(&format!(
                "<strong>Nginx:</strong><pre>{}</pre>\n",
                escape_html(&f.nginx_fix)
            ));
            html.push_str(&format!(
                "<strong>Apache:</strong><pre>{}</pre>\n",
                escape_html(&f.apache_fix)
            ));
        }
    }

    html.push_str(
        r#"</div>
<div class="box">
<h2>[SCOPE] Issue Classification Guide (Organization Audit vs. Bug Bounty)</h2>
<table>
  <tr><th>Tier</th><th>Example Findings</th><th>Organization Ticket</th><th>Bug Bounty Scope</th></tr>
  <tr><td><strong>Tier 1: Immediate Transport / Auth Defect</strong></td><td>Cleartext HTTP, broken TLS PKI (<code>UnknownIssuer</code>), wildcard CORS on authenticated APIs, session tokens missing <code>HttpOnly</code>/<code>Secure</code></td><td>Yes (High/Critical DevOps fix)</td><td>Only with verified exploit PoC &amp; impact (non-auth cookies like <code>_octo</code> are out-of-scope)</td></tr>
  <tr><td><strong>Tier 2: Defense-in-Depth Hardening</strong></td><td>Missing <code>Permissions-Policy</code> / <code>Referrer-Policy</code>, <code>Server</code> banner disclosure, CSP <code>style-src 'unsafe-inline'</code> without XSS PoC</td><td>Yes (Blue-team hardening)</td><td>No (Missing headers &amp; scanner output are out-of-scope)</td></tr>
  <tr><td><strong>Tier 3: Strategic PQC Migration</strong></td><td>Classical <code>X25519</code>/<code>ECDHE</code>/<code>RSA</code> without FIPS 203 <code>ML-KEM-768</code> (<code>0x11EC</code>/<code>0x11EB</code>)</td><td>Yes (NIST IR 8547 roadmap)</td><td>No (Architectural crypto upgrade advisory)</td></tr>
</table>
</div>
<div class="box">
"#,
    );

    let web_operator = OperatorProfile {
        full_name: operator_name.to_string(),
        organization: organization.to_string(),
        authorization_scope: "Authorized".to_string(),
        authorized_at_utc: audit.timestamp_utc.clone(),
    };
    let md_report = report::render_markdown_report(&web_operator, audit);
    html.push_str(&format!(
        "<details><summary>[EXPORT] View Raw Markdown Audit Report (AUDIT_REPORT.md)</summary><pre class=\"wrap-pre\">{}</pre></details>\n",
        escape_html(&md_report)
    ));
    html.push_str("<p><a class=\"btn-link\" href=\"/\">&lt;- Run Another Audit</a></p>\n</div>\n");

    html.push_str(page_footer());
    html
}

async fn get_index() -> Html<String> {
    Html(render_index_html(None))
}

async fn post_audit(
    State(state): State<WebState>,
    headers: HeaderMap,
    connect_info: Option<ConnectInfo<SocketAddr>>,
    Form(form): Form<AuditForm>,
) -> impl IntoResponse {
    let client_ip = extract_client_ip(&headers, connect_info.map(|c| c.0));
    if !check_rate_limit(&state.rate_limiter, &client_ip, Instant::now()) {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Html(render_index_html(Some(
                "Rate limit exceeded: maximum 5 scans per 60 seconds per client IP.",
            ))),
        );
    }

    let operator_name = form.operator_name.trim();
    if operator_name.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Html(render_index_html(Some("Operator Name is required."))),
        );
    }

    let organization = form.organization.trim();
    if organization.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Html(render_index_html(Some(
                "Organization / University is required.",
            ))),
        );
    }

    if form.authorized.as_deref() != Some("yes") {
        return (
            StatusCode::BAD_REQUEST,
            Html(render_index_html(Some(
                "Authorization Consent checkbox must be checked to proceed.",
            ))),
        );
    }

    let extra_allowed = std::env::var("ALLOWED_TARGETS").ok();
    let (normalized_url, host, port, allow_loopback) =
        match validate_web_target_syntax_and_scope(&form.target_url, extra_allowed.as_deref()) {
            Ok(v) => v,
            Err((status, msg)) => return (status, Html(render_index_html(Some(&msg)))),
        };

    if let Err((status, msg)) = verify_resolved_ips_safe(&host, port, allow_loopback).await {
        return (status, Html(render_index_html(Some(&msg))));
    }

    let snapshot =
        match auditor::fetch_target_with_timeout(&normalized_url, WEB_REQUEST_TIMEOUT, true).await {
            Ok(s) => s,
            Err(err) => {
                return (
                    StatusCode::BAD_GATEWAY,
                    Html(render_index_html(Some(&err))),
                );
            }
        };

    let (header_findings, header_deductions) =
        auditor::evaluate_headers_and_vulns(&snapshot.headers);
    let (pqc_finding, hardware_gate, pqc_deductions) = auditor::evaluate_pqc_and_hardware(
        &snapshot.final_url,
        &snapshot.http_version,
        &snapshot.tls_telemetry,
    );
    let audit = auditor::build_audit_result(
        &snapshot,
        header_findings,
        header_deductions,
        pqc_finding,
        hardware_gate,
        pqc_deductions,
    );

    println!(
        "[WEB] IP: {} | Operator: {} ({}) | Target: {} | TLS: {} / {} / {} | Score: {}/100 ({}) | Latency: {} ms",
        client_ip,
        operator_name,
        organization,
        audit.final_url,
        audit.tls_telemetry.tls_version_name,
        audit.tls_telemetry.cipher_suite_name,
        audit.tls_telemetry.kx_group_name,
        audit.score,
        audit.grade,
        audit.latency_ms
    );

    (
        StatusCode::OK,
        Html(render_result_html(operator_name, organization, &audit)),
    )
}

pub fn build_router() -> Router {
    let state = WebState::default();
    Router::new()
        .route("/", get(get_index))
        .route("/audit", post(post_audit))
        .with_state(state)
}

pub async fn serve(port: u16) -> Result<(), String> {
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|e| format!("Failed to bind {}: {}", addr, e))?;

    println!("[SERVE] Listening on http://0.0.0.0:{}", port);
    axum::serve(
        listener,
        build_router().into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .map_err(|e| format!("Web server error: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auditor::{eval_verilog_cipher_gate, Finding, Severity, TlsHandshakeTelemetry};
    use chrono::Utc;

    #[test]
    fn test_escape_html_prevents_xss() {
        assert_eq!(
            escape_html("<script>alert('x')</script>"),
            "&lt;script&gt;alert(&#39;x&#39;)&lt;/script&gt;"
        );
    }

    #[test]
    fn test_long_observed_value_collapses_into_details() {
        let long_csp = "default-src 'self'; ".repeat(15);
        let rendered = format_observed_cell(&long_csp);
        assert!(rendered.contains("<details>"));
        assert!(rendered.contains("click to expand"));
    }

    #[test]
    fn test_index_html_has_no_prefilled_author_and_shows_disclaimer() {
        let html = render_index_html(None);
        assert!(html.contains("action=\"/audit\""));
        assert!(html.contains("name=\"operator_name\""));
        assert!(html.contains("name=\"organization\""));
        assert!(html.contains("name=\"target_url\""));
        assert!(html.contains("name=\"authorized\""));
        assert!(!html.contains("value=\"Sarvepalli"));
        assert!(html.contains("Disclaimer:"));
        assert!(html.contains("Tool Architected &amp; Engineered by Sarvepalli Audi Siva Bhanuvardhan"));
        assert!(html.contains("DEV-CRAFT-BQ2VPH"));
    }

    #[test]
    fn test_scope_guard_allowlist_and_ssrf_blocking() {
        assert!(validate_web_target_syntax_and_scope("https://example.com", None).is_ok());
        assert!(validate_web_target_syntax_and_scope("https://example.org", None).is_ok());
        assert!(validate_web_target_syntax_and_scope("https://example.net", None).is_ok());
        assert!(validate_web_target_syntax_and_scope("http://localhost:8080", None).is_ok());
        assert!(validate_web_target_syntax_and_scope("http://127.0.0.1:8080", None).is_ok());
        assert!(
            validate_web_target_syntax_and_scope("https://custom.internal.test", Some("custom.internal.test"))
                .is_ok()
        );

        let blocked = validate_web_target_syntax_and_scope("https://github.com", None)
            .expect_err("third-party domain must be rejected");
        assert_eq!(blocked.0, StatusCode::FORBIDDEN);
        assert!(blocked.1.contains("Blocked by Scope Guard:"));

        for ssrf_target in &[
            "http://169.254.169.254/latest/meta-data/",
            "http://10.0.0.1/",
            "http://172.16.0.1/",
            "http://192.168.1.1/",
        ] {
            let err = validate_web_target_syntax_and_scope(ssrf_target, Some("169.254.169.254,10.0.0.1"))
                .expect_err("SSRF CIDR must be blocked even if allowlisted");
            assert_eq!(err.0, StatusCode::FORBIDDEN);
        }
    }

    #[test]
    fn test_rate_limiter_enforces_5_per_60s() {
        let limiter = Mutex::new(HashMap::new());
        let start = Instant::now();
        for _ in 0..5 {
            assert!(check_rate_limit(&limiter, "203.0.113.10", start));
        }
        assert!(!check_rate_limit(
            &limiter,
            "203.0.113.10",
            start + Duration::from_secs(10)
        ));
        assert!(check_rate_limit(
            &limiter,
            "203.0.113.10",
            start + Duration::from_secs(61)
        ));
    }

    #[test]
    fn test_result_html_renders_fixes_and_live_pqc_status() {
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
            latency_ms: 35,
            timestamp_utc: Utc::now().to_rfc3339(),
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

        let html = render_result_html("Alice Evaluator", "Test Security Lab", &audit);
        assert!(html.contains("85 / 100"));
        assert!(html.contains("Grade B"));
        assert!(html.contains("TLS13_AES_128_GCM_SHA256"));
        assert!(html.contains("ALLOW (pqc_safe=1)"));
        assert!(html.contains("AUDIT_REPORT.md"));
        assert!(html.contains("DEV-CRAFT-BQ2VPH"));
    }
}
