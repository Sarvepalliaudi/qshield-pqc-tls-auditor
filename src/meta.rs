// ==============================================================================
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
// ==============================================================================

pub const TOOL_NAME: &str = "qshield-audit (Q-Shield PQC-TLS & OWASP Security Auditor)";
pub const TOOL_VERSION: &str = "1.0.0";
pub const PROPRIETARY_NOTICE: &str =
    "Specified, architected, and exclusively engineered by Sarvepalli Audi Siva Bhanuvardhan. \
This specification and dual hardware-software architecture is original work created solely for this application.";
pub const AUTHOR: &str = "Sarvepalli Audi Siva Bhanuvardhan";
pub const UNIVERSITY: &str =
    "B.Tech Computer Science and Engineering (Cybersecurity), Final Year (7th Semester), \
Dhanalakshmi Srinivasan University, Tiruchirappalli, Tamil Nadu, India";
pub const INTERNSHIP: &str =
    "Cybersecurity Virtual Internship - Dev/Craft by Fennark (https://devcraft.fennark.xyz) | \
Intern ID: DEV-CRAFT-BQ2VPH | Task 3: Security Audit";
pub const LINKEDIN_URL: &str =
    "https://www.linkedin.com/in/audi-siva-bhanuvardhan-sarvepalli-4598a8289/";
pub const GITHUB_URL: &str = "https://github.com/Sarvepalliaudi";

/// Prints the plain-text Linux/VLC-style startup banner with zero ANSI escape sequences.
pub fn print_startup_banner() {
    println!("================================================================================");
    println!("{} v{}", TOOL_NAME, TOOL_VERSION);
    println!("Notice    : {}", PROPRIETARY_NOTICE);
    println!("Author    : {}", AUTHOR);
    println!("University: {}", UNIVERSITY);
    println!("Internship: {}", INTERNSHIP);
    println!("LinkedIn  : {}", LINKEDIN_URL);
    println!("GitHub    : {}", GITHUB_URL);
    println!("================================================================================");
}
