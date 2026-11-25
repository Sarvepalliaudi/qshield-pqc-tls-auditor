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

`timescale 1ns/1ps

module tb_tls_cipher_gate;
    reg         clk;
    reg         rst_n;
    reg  [15:0] tls_version;
    reg  [15:0] cipher_id;
    wire        pqc_safe;
    wire        classical_vuln;
    wire        allow_packet;

    integer pass_count;
    integer fail_count;

    tls_cipher_gate dut (
        .clk(clk),
        .rst_n(rst_n),
        .tls_version(tls_version),
        .cipher_id(cipher_id),
        .pqc_safe(pqc_safe),
        .classical_vuln(classical_vuln),
        .allow_packet(allow_packet)
    );

    initial clk = 1'b0;
    always #5 clk = ~clk;

    task check_vector;
        input [15:0] v_tls;
        input [15:0] v_cipher;
        input        exp_pqc;
        input        exp_vuln;
        input        exp_allow;
        input [255:0] label;
        begin
            tls_version = v_tls;
            cipher_id   = v_cipher;
            @(posedge clk);
            #1;
            if (pqc_safe === exp_pqc && classical_vuln === exp_vuln && allow_packet === exp_allow) begin
                pass_count = pass_count + 1;
                $display("[OK]   %0s | tls=0x%04h cipher=0x%04h -> pqc_safe=%b classical_vuln=%b allow=%b",
                         label, v_tls, v_cipher, pqc_safe, classical_vuln, allow_packet);
            end else begin
                fail_count = fail_count + 1;
                $display("[FAIL] %0s | tls=0x%04h cipher=0x%04h -> got (%b,%b,%b), expected (%b,%b,%b)",
                         label, v_tls, v_cipher, pqc_safe, classical_vuln, allow_packet,
                         exp_pqc, exp_vuln, exp_allow);
            end
        end
    endtask

    initial begin
        pass_count  = 0;
        fail_count  = 0;
        rst_n       = 1'b0;
        tls_version = 16'h0000;
        cipher_id   = 16'h0000;

        $display("========================================================================");
        $display("[TEST] qshield-audit | tls_cipher_gate Self-Checking Testbench");
        $display("========================================================================");

        #12;
        if (pqc_safe === 1'b0 && classical_vuln === 1'b1 && allow_packet === 1'b0) begin
            pass_count = pass_count + 1;
            $display("[OK]   Reset fail-closed state verified -> pqc_safe=0 classical_vuln=1 allow=0");
        end else begin
            fail_count = fail_count + 1;
            $display("[FAIL] Reset state mismatch -> got (%b,%b,%b)", pqc_safe, classical_vuln, allow_packet);
        end

        rst_n = 1'b1;

        check_vector(16'h0304, 16'h11EC, 1'b1, 1'b0, 1'b1, "TLS 1.3 + X25519MLKEM768");
        check_vector(16'h0304, 16'h11EB, 1'b1, 1'b0, 1'b1, "TLS 1.3 + SecP256r1MLKEM768");
        check_vector(16'h0304, 16'h001D, 1'b0, 1'b1, 1'b0, "TLS 1.3 + Classical X25519");
        check_vector(16'h0303, 16'h11EC, 1'b0, 1'b1, 1'b0, "TLS 1.2 Downgrade + 0x11EC");
        check_vector(16'h0303, 16'h002F, 1'b0, 1'b1, 1'b0, "TLS 1.2 + RSA_AES128");
        check_vector(16'h0000, 16'h0000, 1'b0, 1'b1, 1'b0, "Cleartext / Unencrypted");

        $display("------------------------------------------------------------------------");
        if (fail_count == 0) begin
            $display("[OK] Simulation Complete: %0d passed, 0 failed.", pass_count);
        end else begin
            $display("[FAIL] Simulation Complete: %0d passed, %0d failed.", pass_count, fail_count);
        end
        $display("========================================================================");
        $finish;
    end
endmodule
