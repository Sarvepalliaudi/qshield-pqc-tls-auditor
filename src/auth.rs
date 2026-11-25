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
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{self, Write};
use std::path::Path;

pub const PROFILE_PATH: &str = "operator_profile.json";
pub const REQUIRED_CONSENT: &str = "AUTHORIZED";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OperatorProfile {
    pub full_name: String,
    pub organization: String,
    pub authorization_scope: String,
    pub authorized_at_utc: String,
}

fn read_prompt_line(prompt: &str) -> Result<String, String> {
    print!("{}", prompt);
    io::stdout()
        .flush()
        .map_err(|e| format!("Failed to flush stdout: {}", e))?;

    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .map_err(|e| format!("Failed to read from stdin: {}", e))?;

    Ok(input.trim().to_string())
}

pub fn validate_registration(
    full_name: &str,
    organization: &str,
    consent: &str,
) -> Result<OperatorProfile, String> {
    let name = full_name.trim();
    let org = organization.trim();
    let ack = consent.trim();

    if name.is_empty() {
        return Err("Operator Full Name cannot be empty.".to_string());
    }
    if org.is_empty() {
        return Err("Organization / University cannot be empty.".to_string());
    }
    if ack != REQUIRED_CONSENT {
        return Err(format!(
            "Authorization consent failed. Expected '{}', received '{}'.",
            REQUIRED_CONSENT, ack
        ));
    }

    Ok(OperatorProfile {
        full_name: name.to_string(),
        organization: org.to_string(),
        authorization_scope: "Authorized".to_string(),
        authorized_at_utc: Utc::now().to_rfc3339(),
    })
}

pub fn load_or_prompt_operator(reset_login: bool) -> Result<(OperatorProfile, bool), String> {
    let profile_path = Path::new(PROFILE_PATH);

    if reset_login && profile_path.exists() {
        fs::remove_file(profile_path)
            .map_err(|e| format!("Failed to remove {}: {}", PROFILE_PATH, e))?;
        println!("[AUTH] Reset requested. Removed existing {}.", PROFILE_PATH);
    }

    if profile_path.exists() {
        let raw = fs::read_to_string(profile_path)
            .map_err(|e| format!("Failed to read {}: {}", PROFILE_PATH, e))?;
        let profile: OperatorProfile = serde_json::from_str(&raw)
            .map_err(|e| format!("Corrupt {}: {} (run with --reset-login)", PROFILE_PATH, e))?;

        println!(
            "[AUTH] Operator: {} | Scope: {}",
            profile.full_name, profile.authorization_scope
        );
        return Ok((profile, false));
    }

    println!("------------------------------------------------------------------------");
    println!("[AUTH] First-Run Operator Login Gate");
    println!("[INFO] Disclaimer: Scan initiated by the listed Session Operator. The");
    println!("       operator is solely responsible for ensuring explicit written");
    println!("       authorization prior to testing any target.");
    println!("------------------------------------------------------------------------");

    let full_name = read_prompt_line("Operator Full Name: ")?;
    let organization = read_prompt_line("Organization / University: ")?;
    let consent = read_prompt_line("Authorization Consent (Type 'AUTHORIZED' to proceed): ")?;

    let profile = validate_registration(&full_name, &organization, &consent)?;
    let serialized = serde_json::to_string_pretty(&profile)
        .map_err(|e| format!("Failed to serialize operator profile: {}", e))?;

    fs::write(profile_path, serialized)
        .map_err(|e| format!("Failed to write {}: {}", PROFILE_PATH, e))?;

    println!("[OK] Saved operator credentials to {}.", PROFILE_PATH);
    println!(
        "[AUTH] Operator: {} | Scope: {}",
        profile.full_name, profile.authorization_scope
    );

    Ok((profile, true))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_registration_success() {
        let profile = validate_registration(
            "Jane Doe",
            "Security Assessment Team",
            "AUTHORIZED",
        )
        .expect("expected valid profile");

        assert_eq!(profile.full_name, "Jane Doe");
        assert_eq!(profile.organization, "Security Assessment Team");
        assert_eq!(profile.authorization_scope, "Authorized");
    }

    #[test]
    fn test_validate_registration_rejects_invalid_consent() {
        let err = validate_registration("Test Operator", "Test Org", "yes")
            .expect_err("expected invalid consent to fail");
        assert!(err.contains("AUTHORIZED"));
    }

    #[test]
    fn test_validate_registration_rejects_empty_fields() {
        assert!(validate_registration("   ", "Test Org", "AUTHORIZED").is_err());
        assert!(validate_registration("Alice", "", "AUTHORIZED").is_err());
    }
}
