// Tool: qshield-audit (Q-Shield PQC-TLS & OWASP Security Auditor)
// Notice: "Specified, architected, and exclusively engineered by Sarvepalli Audi Siva Bhanuvardhan. This specification and dual hardware-software architecture is original work created solely for this application."
// Author: Sarvepalli Audi Siva Bhanuvardhan | B.Tech CSE (Cybersecurity), Final Year (7th Sem), Dhanalakshmi Srinivasan University, Tiruchirappalli, TN, India
// Internship: Cybersecurity Virtual Internship - Dev/Craft by Fennark (https://devcraft.fennark.xyz) | Intern ID: DEV-CRAFT-BQ2VPH | Task 3: Security Audit
// LinkedIn: https://www.linkedin.com/in/audi-siva-bhanuvardhan-sarvepalli-4598a8289/ | GitHub: https://github.com/Sarvepalliaudi

module tls_cipher_gate (
    input  wire        clk,
    input  wire        rst_n,
    input  wire [15:0] tls_version,
    input  wire [15:0] cipher_id,
    output reg         pqc_safe,
    output reg         classical_vuln,
    output reg         allow_packet
);
    localparam [15:0] TLS_1_3             = 16'h0304;
    localparam [15:0] X25519_MLKEM768     = 16'h11EC;
    localparam [15:0] SECP256R1_MLKEM768  = 16'h11EB;

    wire is_pqc_policy_valid;
    assign is_pqc_policy_valid = (tls_version == TLS_1_3) &&
                                 ((cipher_id == X25519_MLKEM768) ||
                                  (cipher_id == SECP256R1_MLKEM768));

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            pqc_safe       <= 1'b0;
            classical_vuln <= 1'b1;
            allow_packet   <= 1'b0;
        end else if (is_pqc_policy_valid) begin
            pqc_safe       <= 1'b1;
            classical_vuln <= 1'b0;
            allow_packet   <= 1'b1;
        end else begin
            pqc_safe       <= 1'b0;
            classical_vuln <= 1'b1;
            allow_packet   <= 1'b0;
        end
    end
endmodule
