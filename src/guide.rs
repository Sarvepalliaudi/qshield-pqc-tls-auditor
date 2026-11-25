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

use std::io::{self, Write};

pub fn progress_bar(percent: u8) -> String {
    let clamped = percent.min(100);
    let filled = (usize::from(clamped) * 10) / 100;
    let empty = 10usize.saturating_sub(filled);
    format!("[{}{}] {}%", "#".repeat(filled), "-".repeat(empty), clamped)
}

pub fn enter_stage(
    guide_enabled: bool,
    stage: u8,
    total: u8,
    percent: u8,
    title: &str,
    explanation: &str,
) -> Result<(), String> {
    println!();
    println!(
        "[STAGE {}/{}] {} {}",
        stage,
        total,
        title,
        progress_bar(percent)
    );

    if guide_enabled {
        println!("[GUIDE] {}", explanation);
        print!("Press ENTER to execute stage...");
        io::stdout()
            .flush()
            .map_err(|e| format!("Failed to flush stdout: {}", e))?;

        let mut buffer = String::new();
        io::stdin()
            .read_line(&mut buffer)
            .map_err(|e| format!("Failed to read confirmation from stdin: {}", e))?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_progress_bar_formatting() {
        assert_eq!(progress_bar(0), "[----------] 0%");
        assert_eq!(progress_bar(25), "[##--------] 25%");
        assert_eq!(progress_bar(40), "[####------] 40%");
        assert_eq!(progress_bar(75), "[#######---] 75%");
        assert_eq!(progress_bar(100), "[##########] 100%");
        assert_eq!(progress_bar(150), "[##########] 100%");
    }
}
