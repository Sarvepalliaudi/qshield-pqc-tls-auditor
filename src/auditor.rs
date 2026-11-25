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

use chrono::Utc;
use reqwest::header::HeaderMap;
use reqwest::{Client, Version};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ProtocolVersion, RootCertStore};
use std::error::Error;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Once};
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use url::Url;

static CRYPTO_INIT: Once = Once::new();

pub fn init_crypto_provider() {
    CRYPTO_INIT.call_once(|| {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    });
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckStatus {
    Ok,
    Warn,
    Fail,
}

impl CheckStatus {
    pub fn tag(self) -> &'static str {
        match self {
            CheckStatus::Ok => "[OK]",
            CheckStatus::Warn => "[WARN]",
            CheckStatus::Fail => "[FAIL]",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "Info",
            Severity::Low => "Low",
            Severity::Medium => "Medium",
            Severity::High => "High",
            Severity::Critical => "Critical",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Finding {
    pub category: String,
    pub name: String,
    pub status: CheckStatus,
    pub severity: Severity,
    pub observed: String,
    pub recommendation: String,
    pub nginx_fix: String,
    pub apache_fix: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsHandshakeTelemetry {
    pub tls_version_u16: u16,
    pub tls_version_name: String,
    pub cipher_suite_name: String,
    pub kx_group_id: u16,
    pub kx_group_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HardwareGateMapping {
    pub tls_version: u16,
    pub cipher_id: u16,
    pub cipher_suite_name: String,
    pub tls_version_label: String,
    pub cipher_id_label: String,
    pub pqc_safe: u8,
    pub classical_vuln: u8,
    pub allow_packet: u8,
    pub policy_note: String,
}

#[derive(Debug, Clone)]
pub struct HandshakeSnapshot {
    pub requested_url: String,
    pub final_url: String,
    pub status_code: u16,
    pub http_version: String,
    pub latency_ms: u128,
    pub headers: HeaderMap,
    pub tls_telemetry: TlsHandshakeTelemetry,
}

#[derive(Debug, Clone)]
pub struct AuditResult {
    pub target_url: String,
    pub final_url: String,
    pub http_status: u16,
    pub http_version: String,
    pub latency_ms: u128,
    pub timestamp_utc: String,
    pub score: u8,
    pub grade: char,
    pub findings: Vec<Finding>,
    pub tls_telemetry: TlsHandshakeTelemetry,
    pub hardware_gate: HardwareGateMapping,
}

pub fn normalize_url(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        trimmed.to_string()
    } else {
        format!("https://{}", trimmed)
    }
}

/// Returns true if `ip` belongs to cloud metadata (169.254.0.0/16), RFC 1918 private
/// networks (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16), CGNAT, unspecified, or IPv6
/// link-local / unique-local ranges.
pub fn is_blocked_ssrf_ip(ip: IpAddr, allow_loopback: bool) -> bool {
    match ip {
        IpAddr::V4(v4) => is_blocked_ssrf_v4(v4, allow_loopback),
        IpAddr::V6(v6) => is_blocked_ssrf_v6(v6, allow_loopback),
    }
}

fn is_blocked_ssrf_v4(ip: Ipv4Addr, allow_loopback: bool) -> bool {
    let octets = ip.octets();
    if ip.is_loopback() {
        return !allow_loopback;
    }
    if ip.is_unspecified() || ip.is_broadcast() || ip.is_multicast() {
        return true;
    }
    // 169.254.0.0/16 (includes 169.254.169.254 cloud metadata)
    if octets[0] == 169 && octets[1] == 254 {
        return true;
    }
    // 10.0.0.0/8
    if octets[0] == 10 {
        return true;
    }
    // 172.16.0.0/12
    if octets[0] == 172 && (16..=31).contains(&octets[1]) {
        return true;
    }
    // 192.168.0.0/16
    if octets[0] == 192 && octets[1] == 168 {
        return true;
    }
    // 100.64.0.0/10 (CGNAT)
    if octets[0] == 100 && (64..=127).contains(&octets[1]) {
        return true;
    }
    false
}

fn is_blocked_ssrf_v6(ip: Ipv6Addr, allow_loopback: bool) -> bool {
    if let Some(mapped_v4) = ip.to_ipv4_mapped() {
        return is_blocked_ssrf_v4(mapped_v4, allow_loopback);
    }
    if ip.is_loopback() {
        return !allow_loopback;
    }
    if ip.is_unspecified() || ip.is_multicast() {
        return true;
    }
    let segments = ip.segments();
    // fe80::/10 link-local
    if (segments[0] & 0xffc0) == 0xfe80 {
        return true;
    }
    // fc00::/7 unique local addresses
    if (segments[0] & 0xfe00) == 0xfc00 {
        return true;
    }
    false
}

fn format_http_version(version: Version) -> &'static str {
    match version {
        Version::HTTP_09 => "HTTP/0.9",
        Version::HTTP_10 => "HTTP/1.0",
        Version::HTTP_11 => "HTTP/1.1",
        Version::HTTP_2 => "HTTP/2.0",
        Version::HTTP_3 => "HTTP/3.0",
        _ => "HTTP/Unknown",
    }
}

fn format_error_chain(err: &dyn Error) -> String {
    let mut parts = vec![err.to_string()];
    let mut current = err.source();
    while let Some(cause) = current {
        parts.push(cause.to_string());
        current = cause.source();
    }
    parts.join(" | caused by: ")
}

fn format_tls_version_label(version_u16: u16) -> String {
    match version_u16 {
        0x0304 => "16'h0304 (TLS 1.3)".to_string(),
        0x0303 => "16'h0303 (TLS 1.2)".to_string(),
        0x0302 => "16'h0302 (TLS 1.1)".to_string(),
        0x0301 => "16'h0301 (TLS 1.0)".to_string(),
        0x0000 => "16'h0000 (Cleartext / No TLS)".to_string(),
        other => format!("16'h{:04X}", other),
    }
}

fn format_kx_group_label(group_id: u16, group_name: &str) -> String {
    match group_id {
        0x11EC => "16'h11EC (X25519MLKEM768)".to_string(),
        0x11EB => "16'h11EB (SecP256r1MLKEM768)".to_string(),
        0x001D => "16'h001D (X25519 Classical ECDHE)".to_string(),
        0x0017 => "16'h0017 (secp256r1 Classical ECDHE)".to_string(),
        0x0018 => "16'h0018 (secp384r1 Classical ECDHE)".to_string(),
        0x0000 => "16'h0000 (None / Classical Static or Cleartext)".to_string(),
        other if !group_name.is_empty() => format!("16'h{:04X} ({})", other, group_name),
        other => format!("16'h{:04X}", other),
    }
}

pub async fn probe_tls_handshake(
    target_url: &str,
    timeout_dur: Duration,
) -> Result<TlsHandshakeTelemetry, String> {
    init_crypto_provider();

    let parsed = Url::parse(target_url)
        .map_err(|e| format!("Invalid URL '{}' for TLS inspection: {}", target_url, e))?;

    if !parsed.scheme().eq_ignore_ascii_case("https") {
        return Ok(TlsHandshakeTelemetry {
            tls_version_u16: 0x0000,
            tls_version_name: "Cleartext HTTP".to_string(),
            cipher_suite_name: "None (Cleartext)".to_string(),
            kx_group_id: 0x0000,
            kx_group_name: "None".to_string(),
        });
    }

    let host = parsed
        .host_str()
        .ok_or_else(|| format!("Target URL '{}' is missing a host", target_url))?
        .trim_matches(['[', ']'])
        .to_string();
    let port = parsed.port_or_known_default().unwrap_or(443);

    let mut root_store = RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("Failed to configure TLS protocol versions: {}", e))?
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let connector = TlsConnector::from(Arc::new(config));
    let server_name = ServerName::try_from(host.clone())
        .map_err(|_| format!("Invalid TLS server name '{}'", host))?;

    let addr = format!("{}:{}", host, port);
    let tcp = timeout(timeout_dur, TcpStream::connect(&addr))
        .await
        .map_err(|_| format!("TLS probe TCP connect timed out after {}s for {}", timeout_dur.as_secs(), addr))?
        .map_err(|e| format!("TLS probe TCP connect failed for {}: {}", addr, e))?;

    let tls_stream = timeout(timeout_dur, connector.connect(server_name, tcp))
        .await
        .map_err(|_| format!("TLS handshake timed out after {}s for {}", timeout_dur.as_secs(), addr))?
        .map_err(|e| format!("TLS handshake failed for {}: {}", addr, format_error_chain(&e)))?;

    let (_, conn) = tls_stream.get_ref();

    let (tls_version_u16, tls_version_name) = match conn.protocol_version() {
        Some(ProtocolVersion::TLSv1_3) => (0x0304, "TLS 1.3".to_string()),
        Some(ProtocolVersion::TLSv1_2) => (0x0303, "TLS 1.2".to_string()),
        Some(other) => {
            let code = u16::from(other);
            (code, format!("TLS (0x{:04X})", code))
        }
        None => (0x0000, "Unknown".to_string()),
    };

    let cipher_suite_name = conn
        .negotiated_cipher_suite()
        .map(|cs| format!("{:?}", cs.suite()))
        .unwrap_or_else(|| "Unknown".to_string());

    let (kx_group_id, kx_group_name) = match conn.negotiated_key_exchange_group() {
        Some(kx) => {
            let group = kx.name();
            (u16::from(group), format!("{:?}", group))
        }
        None => (0x0000, "None / Static RSA".to_string()),
    };

    Ok(TlsHandshakeTelemetry {
        tls_version_u16,
        tls_version_name,
        cipher_suite_name,
        kx_group_id,
        kx_group_name,
    })
}

pub async fn fetch_target(raw_url: &str) -> Result<HandshakeSnapshot, String> {
    fetch_target_with_timeout(raw_url, Duration::from_secs(15), false).await
}

pub async fn fetch_target_with_timeout(
    raw_url: &str,
    timeout_dur: Duration,
    disable_redirects: bool,
) -> Result<HandshakeSnapshot, String> {
    init_crypto_provider();
    let normalized = normalize_url(raw_url);

    let redirect_policy = if disable_redirects {
        reqwest::redirect::Policy::none()
    } else {
        reqwest::redirect::Policy::limited(5)
    };

    let client = Client::builder()
        .connect_timeout(timeout_dur)
        .timeout(timeout_dur)
        .redirect(redirect_policy)
        .user_agent("qshield-audit/1.0 (PQC-TLS & OWASP Passive Auditor)")
        .build()
        .map_err(|e| {
            format!(
                "Failed to initialize HTTP/TLS client: {}",
                format_error_chain(&e)
            )
        })?;

    let start = Instant::now();
    let response = client.get(&normalized).send().await.map_err(|e| {
        format!(
            "Target handshake failed for {}: {}",
            normalized,
            format_error_chain(&e)
        )
    })?;
    let latency_ms = start.elapsed().as_millis();

    let final_url = response.url().to_string();
    let status_code = response.status().as_u16();
    let http_version = format_http_version(response.version()).to_string();
    let headers = response.headers().clone();

    let tls_telemetry = probe_tls_handshake(&final_url, timeout_dur).await?;

    Ok(HandshakeSnapshot {
        requested_url: normalized,
        final_url,
        status_code,
        http_version,
        latency_ms,
        headers,
        tls_telemetry,
    })
}

fn header_str(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

pub fn evaluate_headers_and_vulns(headers: &HeaderMap) -> (Vec<Finding>, i32) {
    let mut findings = Vec::new();
    let mut deductions: i32 = 0;

    // 1. Strict-Transport-Security (HSTS)
    match header_str(headers, "strict-transport-security") {
        Some(val) => {
            let lower = val.to_ascii_lowercase();
            if lower.contains("max-age=0") || !lower.contains("max-age=") {
                deductions += 5;
                findings.push(Finding {
                    category: "OWASP Header".to_string(),
                    name: "Strict-Transport-Security".to_string(),
                    status: CheckStatus::Warn,
                    severity: Severity::Medium,
                    observed: val,
                    recommendation: "Set max-age >= 31536000 with includeSubDomains.".to_string(),
                    nginx_fix: "add_header Strict-Transport-Security \"max-age=63072000; includeSubDomains; preload\" always;".to_string(),
                    apache_fix: "Header always set Strict-Transport-Security \"max-age=63072000; includeSubDomains; preload\"".to_string(),
                });
            } else {
                findings.push(Finding {
                    category: "OWASP Header".to_string(),
                    name: "Strict-Transport-Security".to_string(),
                    status: CheckStatus::Ok,
                    severity: Severity::Info,
                    observed: val,
                    recommendation: "HSTS policy is active.".to_string(),
                    nginx_fix: "add_header Strict-Transport-Security \"max-age=63072000; includeSubDomains; preload\" always;".to_string(),
                    apache_fix: "Header always set Strict-Transport-Security \"max-age=63072000; includeSubDomains; preload\"".to_string(),
                });
            }
        }
        None => {
            deductions += 15;
            findings.push(Finding {
                category: "OWASP Header".to_string(),
                name: "Strict-Transport-Security".to_string(),
                status: CheckStatus::Fail,
                severity: Severity::High,
                observed: "Missing".to_string(),
                recommendation: "Enforce HTTPS via HSTS to block SSL stripping.".to_string(),
                nginx_fix: "add_header Strict-Transport-Security \"max-age=63072000; includeSubDomains; preload\" always;".to_string(),
                apache_fix: "Header always set Strict-Transport-Security \"max-age=63072000; includeSubDomains; preload\"".to_string(),
            });
        }
    }

    // 2. Content-Security-Policy (CSP)
    match header_str(headers, "content-security-policy") {
        Some(val) => {
            let lower = val.to_ascii_lowercase();
            if lower.contains("'unsafe-inline'") || lower.contains("'unsafe-eval'") {
                deductions += 5;
                findings.push(Finding {
                    category: "OWASP Header".to_string(),
                    name: "Content-Security-Policy".to_string(),
                    status: CheckStatus::Warn,
                    severity: Severity::Medium,
                    observed: val,
                    recommendation: "Remove 'unsafe-inline' and 'unsafe-eval' from CSP directives.".to_string(),
                    nginx_fix: "add_header Content-Security-Policy \"default-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self';\" always;".to_string(),
                    apache_fix: "Header always set Content-Security-Policy \"default-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self';\"".to_string(),
                });
            } else {
                findings.push(Finding {
                    category: "OWASP Header".to_string(),
                    name: "Content-Security-Policy".to_string(),
                    status: CheckStatus::Ok,
                    severity: Severity::Info,
                    observed: val,
                    recommendation: "CSP header is configured.".to_string(),
                    nginx_fix: "add_header Content-Security-Policy \"default-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self';\" always;".to_string(),
                    apache_fix: "Header always set Content-Security-Policy \"default-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self';\"".to_string(),
                });
            }
        }
        None => {
            deductions += 15;
            findings.push(Finding {
                category: "OWASP Header".to_string(),
                name: "Content-Security-Policy".to_string(),
                status: CheckStatus::Fail,
                severity: Severity::High,
                observed: "Missing".to_string(),
                recommendation: "Define a strict Content-Security-Policy to mitigate XSS and injection.".to_string(),
                nginx_fix: "add_header Content-Security-Policy \"default-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self';\" always;".to_string(),
                apache_fix: "Header always set Content-Security-Policy \"default-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self';\"".to_string(),
            });
        }
    }

    // 3. X-Frame-Options
    match header_str(headers, "x-frame-options") {
        Some(val) => {
            let upper = val.to_ascii_uppercase();
            if upper == "DENY" || upper == "SAMEORIGIN" {
                findings.push(Finding {
                    category: "OWASP Header".to_string(),
                    name: "X-Frame-Options".to_string(),
                    status: CheckStatus::Ok,
                    severity: Severity::Info,
                    observed: val,
                    recommendation: "Clickjacking framing policy is active.".to_string(),
                    nginx_fix: "add_header X-Frame-Options \"DENY\" always;".to_string(),
                    apache_fix: "Header always set X-Frame-Options \"DENY\"".to_string(),
                });
            } else {
                deductions += 5;
                findings.push(Finding {
                    category: "OWASP Header".to_string(),
                    name: "X-Frame-Options".to_string(),
                    status: CheckStatus::Warn,
                    severity: Severity::Low,
                    observed: val,
                    recommendation: "Use DENY or SAMEORIGIN for X-Frame-Options.".to_string(),
                    nginx_fix: "add_header X-Frame-Options \"DENY\" always;".to_string(),
                    apache_fix: "Header always set X-Frame-Options \"DENY\"".to_string(),
                });
            }
        }
        None => {
            deductions += 10;
            findings.push(Finding {
                category: "OWASP Header".to_string(),
                name: "X-Frame-Options".to_string(),
                status: CheckStatus::Fail,
                severity: Severity::Medium,
                observed: "Missing".to_string(),
                recommendation: "Add X-Frame-Options: DENY (or SAMEORIGIN) to prevent clickjacking.".to_string(),
                nginx_fix: "add_header X-Frame-Options \"DENY\" always;".to_string(),
                apache_fix: "Header always set X-Frame-Options \"DENY\"".to_string(),
            });
        }
    }

    // 4. X-Content-Type-Options
    match header_str(headers, "x-content-type-options") {
        Some(val) if val.eq_ignore_ascii_case("nosniff") => {
            findings.push(Finding {
                category: "OWASP Header".to_string(),
                name: "X-Content-Type-Options".to_string(),
                status: CheckStatus::Ok,
                severity: Severity::Info,
                observed: val,
                recommendation: "MIME-type sniffing protection is active.".to_string(),
                nginx_fix: "add_header X-Content-Type-Options \"nosniff\" always;".to_string(),
                apache_fix: "Header always set X-Content-Type-Options \"nosniff\"".to_string(),
            });
        }
        Some(val) => {
            deductions += 5;
            findings.push(Finding {
                category: "OWASP Header".to_string(),
                name: "X-Content-Type-Options".to_string(),
                status: CheckStatus::Warn,
                severity: Severity::Medium,
                observed: val,
                recommendation: "Set X-Content-Type-Options strictly to 'nosniff'.".to_string(),
                nginx_fix: "add_header X-Content-Type-Options \"nosniff\" always;".to_string(),
                apache_fix: "Header always set X-Content-Type-Options \"nosniff\"".to_string(),
            });
        }
        None => {
            deductions += 10;
            findings.push(Finding {
                category: "OWASP Header".to_string(),
                name: "X-Content-Type-Options".to_string(),
                status: CheckStatus::Fail,
                severity: Severity::Medium,
                observed: "Missing".to_string(),
                recommendation: "Set X-Content-Type-Options: nosniff to prevent MIME confusion.".to_string(),
                nginx_fix: "add_header X-Content-Type-Options \"nosniff\" always;".to_string(),
                apache_fix: "Header always set X-Content-Type-Options \"nosniff\"".to_string(),
            });
        }
    }

    // 5. Referrer-Policy
    match header_str(headers, "referrer-policy") {
        Some(val) => {
            findings.push(Finding {
                category: "OWASP Header".to_string(),
                name: "Referrer-Policy".to_string(),
                status: CheckStatus::Ok,
                severity: Severity::Info,
                observed: val,
                recommendation: "Referrer leakage policy is configured.".to_string(),
                nginx_fix: "add_header Referrer-Policy \"strict-origin-when-cross-origin\" always;".to_string(),
                apache_fix: "Header always set Referrer-Policy \"strict-origin-when-cross-origin\"".to_string(),
            });
        }
        None => {
            deductions += 10;
            findings.push(Finding {
                category: "OWASP Header".to_string(),
                name: "Referrer-Policy".to_string(),
                status: CheckStatus::Fail,
                severity: Severity::Low,
                observed: "Missing".to_string(),
                recommendation: "Add Referrer-Policy to prevent URL token leakage.".to_string(),
                nginx_fix: "add_header Referrer-Policy \"strict-origin-when-cross-origin\" always;".to_string(),
                apache_fix: "Header always set Referrer-Policy \"strict-origin-when-cross-origin\"".to_string(),
            });
        }
    }

    // 6. Permissions-Policy
    match header_str(headers, "permissions-policy") {
        Some(val) => {
            findings.push(Finding {
                category: "OWASP Header".to_string(),
                name: "Permissions-Policy".to_string(),
                status: CheckStatus::Ok,
                severity: Severity::Info,
                observed: val,
                recommendation: "Browser feature restrictions are declared.".to_string(),
                nginx_fix: "add_header Permissions-Policy \"geolocation=(), microphone=(), camera=()\" always;".to_string(),
                apache_fix: "Header always set Permissions-Policy \"geolocation=(), microphone=(), camera=()\"".to_string(),
            });
        }
        None => {
            deductions += 10;
            findings.push(Finding {
                category: "OWASP Header".to_string(),
                name: "Permissions-Policy".to_string(),
                status: CheckStatus::Fail,
                severity: Severity::Low,
                observed: "Missing".to_string(),
                recommendation: "Restrict powerful browser APIs via Permissions-Policy.".to_string(),
                nginx_fix: "add_header Permissions-Policy \"geolocation=(), microphone=(), camera=()\" always;".to_string(),
                apache_fix: "Header always set Permissions-Policy \"geolocation=(), microphone=(), camera=()\"".to_string(),
            });
        }
    }

    // 7. Passive Web Vulnerability: Set-Cookie Flags (HttpOnly, Secure, SameSite)
    let cookies: Vec<String> = headers
        .get_all(reqwest::header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .map(|s| s.trim().to_string())
        .collect();

    if cookies.is_empty() {
        findings.push(Finding {
            category: "Passive Vulnerability".to_string(),
            name: "Cookie Security (Set-Cookie)".to_string(),
            status: CheckStatus::Ok,
            severity: Severity::Info,
            observed: "No Set-Cookie headers emitted".to_string(),
            recommendation: "No session cookie exposure in passive landing response.".to_string(),
            nginx_fix: "proxy_cookie_path / \"/; HttpOnly; Secure; SameSite=Strict\";".to_string(),
            apache_fix: "Header edit Set-Cookie ^(.*)$ \"$1; HttpOnly; Secure; SameSite=Strict\"".to_string(),
        });
    } else {
        let mut issues = Vec::new();
        let mut missing_critical_flag = false;
        for raw_cookie in &cookies {
            let cookie_name = raw_cookie.split('=').next().unwrap_or("cookie").trim();
            let lower = raw_cookie.to_ascii_lowercase();
            let mut missing = Vec::new();
            if !lower.contains("httponly") {
                missing.push("HttpOnly");
                missing_critical_flag = true;
            }
            if !lower.contains("secure") {
                missing.push("Secure");
                missing_critical_flag = true;
            }
            if !lower.contains("samesite") {
                missing.push("SameSite");
            }
            if !missing.is_empty() {
                issues.push(format!("{} missing [{}]", cookie_name, missing.join(", ")));
            }
        }

        if issues.is_empty() {
            findings.push(Finding {
                category: "Passive Vulnerability".to_string(),
                name: "Cookie Security (Set-Cookie)".to_string(),
                status: CheckStatus::Ok,
                severity: Severity::Info,
                observed: format!("{} cookie(s) properly hardened", cookies.len()),
                recommendation: "All observed cookies include HttpOnly, Secure, and SameSite.".to_string(),
                nginx_fix: "proxy_cookie_path / \"/; HttpOnly; Secure; SameSite=Strict\";".to_string(),
                apache_fix: "Header edit Set-Cookie ^(.*)$ \"$1; HttpOnly; Secure; SameSite=Strict\"".to_string(),
            });
        } else {
            deductions += if missing_critical_flag { 10 } else { 5 };
            findings.push(Finding {
                category: "Passive Vulnerability".to_string(),
                name: "Cookie Security (Set-Cookie)".to_string(),
                status: if missing_critical_flag {
                    CheckStatus::Fail
                } else {
                    CheckStatus::Warn
                },
                severity: Severity::Medium,
                observed: issues.join("; "),
                recommendation: "Enforce HttpOnly, Secure, and SameSite=Strict/Lax on all cookies.".to_string(),
                nginx_fix: "proxy_cookie_path / \"/; HttpOnly; Secure; SameSite=Strict\";".to_string(),
                apache_fix: "Header edit Set-Cookie ^(.*)$ \"$1; HttpOnly; Secure; SameSite=Strict\"".to_string(),
            });
        }
    }

    // 8. Passive Web Vulnerability: Server / X-Powered-By Fingerprinting
    let mut disclosed = Vec::new();
    if let Some(s) = header_str(headers, "server") {
        disclosed.push(format!("Server: {}", s));
    }
    if let Some(p) = header_str(headers, "x-powered-by") {
        disclosed.push(format!("X-Powered-By: {}", p));
    }

    if disclosed.is_empty() {
        findings.push(Finding {
            category: "Passive Vulnerability".to_string(),
            name: "Banner Disclosure (Server / X-Powered-By)".to_string(),
            status: CheckStatus::Ok,
            severity: Severity::Info,
            observed: "Not exposed".to_string(),
            recommendation: "Server stack headers are suppressed.".to_string(),
            nginx_fix: "server_tokens off;\nmore_clear_headers 'Server' 'X-Powered-By';".to_string(),
            apache_fix: "ServerTokens Prod\nServerSignature Off\nHeader unset X-Powered-By".to_string(),
        });
    } else {
        deductions += 5;
        findings.push(Finding {
            category: "Passive Vulnerability".to_string(),
            name: "Banner Disclosure (Server / X-Powered-By)".to_string(),
            status: CheckStatus::Warn,
            severity: Severity::Low,
            observed: disclosed.join(" | "),
            recommendation: "Suppress Server and X-Powered-By banners to reduce fingerprinting.".to_string(),
            nginx_fix: "server_tokens off;\nmore_clear_headers 'Server' 'X-Powered-By';".to_string(),
            apache_fix: "ServerTokens Prod\nServerSignature Off\nHeader unset X-Powered-By".to_string(),
        });
    }

    // 9. Passive Web Vulnerability: Wildcard CORS
    match header_str(headers, "access-control-allow-origin") {
        Some(val) if val == "*" => {
            deductions += 10;
            findings.push(Finding {
                category: "Passive Vulnerability".to_string(),
                name: "CORS Policy (Access-Control-Allow-Origin)".to_string(),
                status: CheckStatus::Fail,
                severity: Severity::High,
                observed: "Access-Control-Allow-Origin: *".to_string(),
                recommendation: "Replace wildcard '*' with explicit trusted origin allowlists.".to_string(),
                nginx_fix: "add_header Access-Control-Allow-Origin \"https://trusted.example.com\" always;".to_string(),
                apache_fix: "Header always set Access-Control-Allow-Origin \"https://trusted.example.com\"".to_string(),
            });
        }
        Some(val) => {
            findings.push(Finding {
                category: "Passive Vulnerability".to_string(),
                name: "CORS Policy (Access-Control-Allow-Origin)".to_string(),
                status: CheckStatus::Ok,
                severity: Severity::Info,
                observed: format!("Scoped origin ({})", val),
                recommendation: "CORS origin is explicitly scoped.".to_string(),
                nginx_fix: "add_header Access-Control-Allow-Origin \"https://trusted.example.com\" always;".to_string(),
                apache_fix: "Header always set Access-Control-Allow-Origin \"https://trusted.example.com\"".to_string(),
            });
        }
        None => {
            findings.push(Finding {
                category: "Passive Vulnerability".to_string(),
                name: "CORS Policy (Access-Control-Allow-Origin)".to_string(),
                status: CheckStatus::Ok,
                severity: Severity::Info,
                observed: "Absent (Same-Origin default)".to_string(),
                recommendation: "Same-Origin policy applies by default.".to_string(),
                nginx_fix: "add_header Access-Control-Allow-Origin \"https://trusted.example.com\" always;".to_string(),
                apache_fix: "Header always set Access-Control-Allow-Origin \"https://trusted.example.com\"".to_string(),
            });
        }
    }

    (findings, deductions)
}

/// Software mirror of `hardware/tls_cipher_gate.v` combinational/sequential policy:
/// Asserts `pqc_safe = 1` and `allow_packet = 1` ONLY when
/// `tls_version == 16'h0304` (TLS 1.3) AND
/// `cipher_id` is `16'h11EC` (X25519MLKEM768) or `16'h11EB` (SecP256r1MLKEM768).
pub fn eval_verilog_cipher_gate(
    tls_version: u16,
    cipher_id: u16,
    cipher_suite_name: &str,
    kx_group_name: &str,
) -> HardwareGateMapping {
    let is_tls13 = tls_version == 0x0304;
    let is_pqc_hybrid = cipher_id == 0x11EC || cipher_id == 0x11EB;
    let pass = is_tls13 && is_pqc_hybrid;

    let tls_version_label = format_tls_version_label(tls_version);
    let cipher_id_label = format_kx_group_label(cipher_id, kx_group_name);

    let policy_note = if pass {
        format!(
            "ALLOW: Hardware gate verified {} + {} with {} under NIST IR 8547 / FIPS 203.",
            tls_version_label, cipher_id_label, cipher_suite_name
        )
    } else {
        format!(
            "BLOCK: Hardware gate observed {} + {} ({}) -> asserts classical_vuln=1, allow_packet=0 (requires TLS 1.3 16'h0304 + ML-KEM-768 16'h11EC/16'h11EB).",
            tls_version_label, cipher_id_label, cipher_suite_name
        )
    };

    HardwareGateMapping {
        tls_version,
        cipher_id,
        cipher_suite_name: cipher_suite_name.to_string(),
        tls_version_label,
        cipher_id_label,
        pqc_safe: if pass { 1 } else { 0 },
        classical_vuln: if pass { 0 } else { 1 },
        allow_packet: if pass { 1 } else { 0 },
        policy_note,
    }
}

pub fn evaluate_pqc_and_hardware(
    final_url: &str,
    http_version: &str,
    tls: &TlsHandshakeTelemetry,
) -> (Finding, HardwareGateMapping, i32) {
    let gate = eval_verilog_cipher_gate(
        tls.tls_version_u16,
        tls.kx_group_id,
        &tls.cipher_suite_name,
        &tls.kx_group_name,
    );

    let is_https = final_url.to_ascii_lowercase().starts_with("https://");
    if !is_https || tls.tls_version_u16 == 0x0000 {
        let finding = Finding {
            category: "PQC-TLS Readiness".to_string(),
            name: "NIST IR 8547 / FIPS 203 ML-KEM-768 Posture".to_string(),
            status: CheckStatus::Fail,
            severity: Severity::Critical,
            observed: format!("Cleartext HTTP ({}) - No TLS / No PQC", http_version),
            recommendation: "Migrate immediately to HTTPS with TLS 1.3 (0x0304) and hybrid FIPS 203 X25519MLKEM768 (0x11EC) to defeat interception and Shor's algorithm.".to_string(),
            nginx_fix: "ssl_protocols TLSv1.3;\nssl_ecdh_curve X25519MLKEM768:X25519:prime256v1;\nssl_prefer_server_ciphers off;".to_string(),
            apache_fix: "SSLProtocol -all +TLSv1.3\nSSLOpenSSLConfCmd Curves X25519MLKEM768:X25519:prime256v1".to_string(),
        };
        return (finding, gate, 30);
    }

    if gate.pqc_safe == 1 {
        let finding = Finding {
            category: "PQC-TLS Readiness".to_string(),
            name: "NIST IR 8547 / FIPS 203 ML-KEM-768 Posture".to_string(),
            status: CheckStatus::Ok,
            severity: Severity::Info,
            observed: format!(
                "{} | {} | {} (0x{:04X}) — Hybrid FIPS 203 PQC active",
                tls.tls_version_name, tls.cipher_suite_name, tls.kx_group_name, tls.kx_group_id
            ),
            recommendation: "Post-Quantum hybrid ML-KEM-768 key exchange is active and compliant with NIST IR 8547.".to_string(),
            nginx_fix: "ssl_protocols TLSv1.3;\nssl_ecdh_curve X25519MLKEM768:X25519:prime256v1;\nssl_prefer_server_ciphers off;".to_string(),
            apache_fix: "SSLProtocol -all +TLSv1.3\nSSLOpenSSLConfCmd Curves X25519MLKEM768:X25519:prime256v1".to_string(),
        };
        return (finding, gate, 0);
    }

    if tls.tls_version_u16 < 0x0304 {
        let finding = Finding {
            category: "PQC-TLS Readiness".to_string(),
            name: "NIST IR 8547 / FIPS 203 ML-KEM-768 Posture".to_string(),
            status: CheckStatus::Fail,
            severity: Severity::High,
            observed: format!(
                "{} (0x{:04X}) | {} | {} (0x{:04X}) — Legacy TLS without PQC",
                tls.tls_version_name,
                tls.tls_version_u16,
                tls.cipher_suite_name,
                tls.kx_group_name,
                tls.kx_group_id
            ),
            recommendation: "Upgrade to TLS 1.3 (0x0304) with hybrid FIPS 203 X25519MLKEM768 (0x11EC) per NIST IR 8547.".to_string(),
            nginx_fix: "ssl_protocols TLSv1.3;\nssl_ecdh_curve X25519MLKEM768:X25519:prime256v1;\nssl_prefer_server_ciphers off;".to_string(),
            apache_fix: "SSLProtocol -all +TLSv1.3\nSSLOpenSSLConfCmd Curves X25519MLKEM768:X25519:prime256v1".to_string(),
        };
        return (finding, gate, 20);
    }

    let finding = Finding {
        category: "PQC-TLS Readiness".to_string(),
        name: "NIST IR 8547 / FIPS 203 ML-KEM-768 Posture".to_string(),
        status: CheckStatus::Warn,
        severity: Severity::Medium,
        observed: format!(
            "{} | {} | {} (0x{:04X}) — Classical key exchange vulnerable to Shor's algorithm & HNDL",
            tls.tls_version_name, tls.cipher_suite_name, tls.kx_group_name, tls.kx_group_id
        ),
        recommendation: "Enable hybrid Post-Quantum key encapsulation (FIPS 203 X25519MLKEM768 / SecP256r1MLKEM768) on TLS 1.3 per NIST IR 8547 (October 2026) roadmap.".to_string(),
        nginx_fix: "ssl_protocols TLSv1.3;\nssl_ecdh_curve X25519MLKEM768:X25519:prime256v1;\nssl_prefer_server_ciphers off;".to_string(),
        apache_fix: "SSLProtocol -all +TLSv1.3\nSSLOpenSSLConfCmd Curves X25519MLKEM768:X25519:prime256v1".to_string(),
    };
    (finding, gate, 10)
}

pub fn compute_score_and_grade(deductions: i32) -> (u8, char) {
    let raw = 100 - deductions;
    let clamped = raw.clamp(0, 100) as u8;
    let grade = match clamped {
        90..=100 => 'A',
        80..=89 => 'B',
        70..=79 => 'C',
        55..=69 => 'D',
        _ => 'F',
    };
    (clamped, grade)
}

pub fn build_audit_result(
    snapshot: &HandshakeSnapshot,
    header_findings: Vec<Finding>,
    header_deductions: i32,
    pqc_finding: Finding,
    hardware_gate: HardwareGateMapping,
    pqc_deductions: i32,
) -> AuditResult {
    let mut findings = header_findings;
    findings.push(pqc_finding);

    let (score, grade) = compute_score_and_grade(header_deductions + pqc_deductions);

    AuditResult {
        target_url: snapshot.requested_url.clone(),
        final_url: snapshot.final_url.clone(),
        http_status: snapshot.status_code,
        http_version: snapshot.http_version.clone(),
        latency_ms: snapshot.latency_ms,
        timestamp_utc: Utc::now().to_rfc3339(),
        score,
        grade,
        findings,
        tls_telemetry: snapshot.tls_telemetry.clone(),
        hardware_gate,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::header::{HeaderValue, ACCESS_CONTROL_ALLOW_ORIGIN, SERVER, SET_COOKIE};

    #[test]
    fn test_hardened_headers_score() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "strict-transport-security",
            HeaderValue::from_static("max-age=63072000; includeSubDomains"),
        );
        headers.insert(
            "content-security-policy",
            HeaderValue::from_static("default-src 'self'"),
        );
        headers.insert("x-frame-options", HeaderValue::from_static("DENY"));
        headers.insert("x-content-type-options", HeaderValue::from_static("nosniff"));
        headers.insert(
            "referrer-policy",
            HeaderValue::from_static("strict-origin-when-cross-origin"),
        );
        headers.insert(
            "permissions-policy",
            HeaderValue::from_static("geolocation=()"),
        );

        let (findings, deductions) = evaluate_headers_and_vulns(&headers);
        assert_eq!(deductions, 0);
        assert!(findings.iter().all(|f| f.status == CheckStatus::Ok));
    }

    #[test]
    fn test_vulnerable_headers_detection() {
        let mut headers = HeaderMap::new();
        headers.insert(SERVER, HeaderValue::from_static("Apache/2.4.58"));
        headers.insert(ACCESS_CONTROL_ALLOW_ORIGIN, HeaderValue::from_static("*"));
        headers.insert(SET_COOKIE, HeaderValue::from_static("sid=abc123; Path=/"));

        let (findings, deductions) = evaluate_headers_and_vulns(&headers);
        assert!(deductions >= 80);
        assert!(findings
            .iter()
            .any(|f| f.name.contains("CORS") && f.status == CheckStatus::Fail));
        assert!(findings
            .iter()
            .any(|f| f.name.contains("Cookie") && f.status == CheckStatus::Fail));
        assert!(findings
            .iter()
            .any(|f| f.name.contains("Banner") && f.status == CheckStatus::Warn));
    }

    #[test]
    fn test_verilog_cipher_gate_equivalence() {
        let pass_x25519 =
            eval_verilog_cipher_gate(0x0304, 0x11EC, "TLS13_AES_128_GCM_SHA256", "X25519MLKEM768");
        assert_eq!(pass_x25519.pqc_safe, 1);
        assert_eq!(pass_x25519.classical_vuln, 0);
        assert_eq!(pass_x25519.allow_packet, 1);

        let pass_secp = eval_verilog_cipher_gate(
            0x0304,
            0x11EB,
            "TLS13_AES_256_GCM_SHA384",
            "secp256r1MLKEM768",
        );
        assert_eq!(pass_secp.pqc_safe, 1);
        assert_eq!(pass_secp.classical_vuln, 0);
        assert_eq!(pass_secp.allow_packet, 1);

        let block_classical =
            eval_verilog_cipher_gate(0x0304, 0x001D, "TLS13_AES_128_GCM_SHA256", "X25519");
        assert_eq!(block_classical.pqc_safe, 0);
        assert_eq!(block_classical.classical_vuln, 1);
        assert_eq!(block_classical.allow_packet, 0);

        let block_downgrade =
            eval_verilog_cipher_gate(0x0303, 0x11EC, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "X25519MLKEM768");
        assert_eq!(block_downgrade.pqc_safe, 0);
        assert_eq!(block_downgrade.classical_vuln, 1);
        assert_eq!(block_downgrade.allow_packet, 0);
    }

    #[test]
    fn test_ssrf_cidr_blocking() {
        assert!(is_blocked_ssrf_ip("169.254.169.254".parse().unwrap(), true));
        assert!(is_blocked_ssrf_ip("10.0.0.5".parse().unwrap(), true));
        assert!(is_blocked_ssrf_ip("172.16.0.1".parse().unwrap(), true));
        assert!(is_blocked_ssrf_ip("172.31.255.254".parse().unwrap(), true));
        assert!(!is_blocked_ssrf_ip("172.32.0.1".parse().unwrap(), true));
        assert!(is_blocked_ssrf_ip("192.168.1.10".parse().unwrap(), true));
        assert!(!is_blocked_ssrf_ip("127.0.0.1".parse().unwrap(), true));
        assert!(is_blocked_ssrf_ip("127.0.0.1".parse().unwrap(), false));
        assert!(!is_blocked_ssrf_ip("93.184.216.34".parse().unwrap(), false));
    }
}
