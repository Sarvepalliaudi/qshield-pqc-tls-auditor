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

mod auditor;
mod auth;
mod guide;
mod report;
mod web;

use clap::Parser;
use std::env;
use std::process;

#[derive(Parser, Debug)]
#[command(
    name = "qshield-audit",
    version = "1.0.0",
    about = "Zero-bloat Post-Quantum TLS (NIST IR 8547 / FIPS 203) & OWASP passive security auditor"
)]
struct Cli {
    /// Target URL to audit passively
    #[arg(long, default_value = "https://example.com")]
    url: String,

    /// Enable interactive step-by-step plain-text guide mode
    #[arg(long)]
    guide: bool,

    /// Output Markdown report file path
    #[arg(long, default_value = "AUDIT_REPORT.md")]
    output: String,

    /// Clear operator_profile.json and re-run operator authorization login
    #[arg(long)]
    reset_login: bool,

    /// Run lightweight plain-HTML web server on 0.0.0.0:$PORT (default 8080)
    #[arg(long)]
    serve: bool,
}

fn print_banner() {
    println!("========================================================================");
    println!("Tool Name   : qshield-audit (Q-Shield PQC-TLS & OWASP Security Auditor)");
    println!("Notice      : Specified, architected, and exclusively engineered by");
    println!("              Sarvepalli Audi Siva Bhanuvardhan. This specification and");
    println!("              dual hardware-software architecture is original work");
    println!("              created solely for this application.");
    println!("Author      : Sarvepalli Audi Siva Bhanuvardhan");
    println!("University  : B.Tech Computer Science and Engineering (Cybersecurity),");
    println!("              Final Year (7th Semester), Dhanalakshmi Srinivasan");
    println!("              University, Tiruchirappalli, Tamil Nadu, India");
    println!("Internship  : Cybersecurity Virtual Internship — Dev/Craft by Fennark");
    println!("              (https://devcraft.fennark.xyz) | Intern ID: DEV-CRAFT-BQ2VPH");
    println!("              Task 3: Security Audit");
    println!("LinkedIn    : https://www.linkedin.com/in/audi-siva-bhanuvardhan-sarvepalli-4598a8289/");
    println!("GitHub      : https://github.com/Sarvepalliaudi");
    println!("========================================================================");
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    print_banner();

    if cli.serve {
        let port: u16 = env::var("PORT")
            .ok()
            .and_then(|v| v.parse::<u16>().ok())
            .unwrap_or(8080);

        if let Err(err) = web::serve(port).await {
            eprintln!("[FAIL] {}", err);
            process::exit(1);
        }
        return;
    }

    let (operator, is_first_run) = match auth::load_or_prompt_operator(cli.reset_login) {
        Ok(res) => res,
        Err(err) => {
            eprintln!("[FAIL] {}", err);
            process::exit(1);
        }
    };

    let guide_enabled = cli.guide || is_first_run;
    if guide_enabled {
        println!("[INFO] Interactive --guide mode active.");
    }

    // Stage 1/4: Target Reachability & Passive HTTP Handshake
    if let Err(err) = guide::enter_stage(
        guide_enabled,
        1,
        4,
        25,
        "Target Reachability & Passive HTTP Handshake",
        "Sends a single passive HTTP GET using rustls-tls to measure round-trip latency and capture raw response headers without intrusive probing.",
    ) {
        eprintln!("[FAIL] {}", err);
        process::exit(1);
    }

    let snapshot = match auditor::fetch_target(&cli.url).await {
        Ok(snap) => {
            println!(
                "[OK] Target reachable: {} -> {} | Status: {} ({}) | Latency: {} ms",
                snap.requested_url, snap.final_url, snap.status_code, snap.http_version, snap.latency_ms
            );
            snap
        }
        Err(err) => {
            eprintln!("[FAIL] {}", err);
            process::exit(1);
        }
    };

    // Stage 2/4: OWASP Security Header & Cookie/CORS Policy Check
    if let Err(err) = guide::enter_stage(
        guide_enabled,
        2,
        4,
        50,
        "OWASP Security Header & Cookie/CORS Policy Check",
        "Inspects the 6 core OWASP defense headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy) plus Set-Cookie flags, Server/X-Powered-By banners, and wildcard CORS.",
    ) {
        eprintln!("[FAIL] {}", err);
        process::exit(1);
    }

    let (header_findings, header_deductions) = auditor::evaluate_headers_and_vulns(&snapshot.headers);
    for f in &header_findings {
        println!(
            "{} {} ({}) -> {}",
            f.status.tag(),
            f.name,
            f.severity.as_str(),
            f.observed
        );
    }

    // Stage 3/4: Post-Quantum TLS (NIST IR 8547 / FIPS 203 ML-KEM-768) Readiness Check
    if let Err(err) = guide::enter_stage(
        guide_enabled,
        3,
        4,
        75,
        "Post-Quantum TLS (NIST IR 8547 / FIPS 203 ML-KEM-768) Readiness Check",
        "Evaluates transport security against NIST IR 8547 (October 2026) and FIPS 203 (X25519MLKEM768 / SecP256r1MLKEM768) to flag classical RSA/ECDSA/X25519 exposure to Shor's algorithm.",
    ) {
        eprintln!("[FAIL] {}", err);
        process::exit(1);
    }

    let (pqc_finding, hardware_gate, pqc_deductions) = auditor::evaluate_pqc_and_hardware(
        &snapshot.final_url,
        &snapshot.http_version,
        &snapshot.tls_telemetry,
    );
    println!(
        "{} {} ({}) -> {}",
        pqc_finding.status.tag(),
        pqc_finding.name,
        pqc_finding.severity.as_str(),
        pqc_finding.observed
    );

    // Stage 4/4: Hardware Silicon Cipher Policy Verification (Verilog Logic Mapping)
    if let Err(err) = guide::enter_stage(
        guide_enabled,
        4,
        4,
        100,
        "Hardware Silicon Cipher Policy Verification (Verilog Logic Mapping)",
        "Maps live negotiated TLS version and key-exchange group ID onto hardware/tls_cipher_gate.v (requires tls_version=16'h0304 and cipher_id=16'h11EC or 16'h11EB to assert pqc_safe=1 and allow_packet=1).",
    ) {
        eprintln!("[FAIL] {}", err);
        process::exit(1);
    }

    let gate_tag = if hardware_gate.allow_packet == 1 {
        "[OK]"
    } else {
        "[FAIL]"
    };
    println!(
        "{} tls_cipher_gate(tls_version={}, cipher_id={}, suite={}) => pqc_safe={}, classical_vuln={}, allow_packet={}",
        gate_tag,
        hardware_gate.tls_version_label,
        hardware_gate.cipher_id_label,
        hardware_gate.cipher_suite_name,
        hardware_gate.pqc_safe,
        hardware_gate.classical_vuln,
        hardware_gate.allow_packet
    );

    let audit = auditor::build_audit_result(
        &snapshot,
        header_findings,
        header_deductions,
        pqc_finding,
        hardware_gate,
        pqc_deductions,
    );

    let markdown = report::render_markdown_report(&operator, &audit);
    if let Err(err) = report::write_report(&cli.output, &markdown) {
        eprintln!("[FAIL] {}", err);
        process::exit(1);
    }

    println!();
    println!(
        "[OK] Audit Complete | Score: {}/100 | Grade: {} | Latency: {} ms | Report: {}",
        audit.score, audit.grade, audit.latency_ms, cli.output
    );
}
