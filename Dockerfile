# ==============================================================================
# Tool Name: qshield-audit (Q-Shield PQC-TLS & OWASP Security Auditor)
# Proprietary Notice: "Specified, architected, and exclusively engineered by
# Sarvepalli Audi Siva Bhanuvardhan. This specification and dual
# hardware-software architecture is original work created solely for this
# application."
# Author: Sarvepalli Audi Siva Bhanuvardhan
# University: B.Tech Computer Science and Engineering (Cybersecurity), Final Year
#             (7th Semester), Dhanalakshmi Srinivasan University,
#             Tiruchirappalli, Tamil Nadu, India
# Internship: Cybersecurity Virtual Internship — Dev/Craft by Fennark
#             (https://devcraft.fennark.xyz) | Intern ID: DEV-CRAFT-BQ2VPH |
#             Task 3: Security Audit
# LinkedIn: https://www.linkedin.com/in/audi-siva-bhanuvardhan-sarvepalli-4598a8289/
# GitHub: https://github.com/Sarvepalliaudi
# ==============================================================================

FROM rust:1-slim-bookworm AS builder

RUN apt-get update \
    && apt-get install -y --no-install-recommends cmake \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY Cargo.toml Cargo.lock* ./
COPY src ./src

RUN cargo build --release

FROM debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /app/target/release/qshield-audit /app/qshield-audit

ENV PORT=8080
EXPOSE 8080

CMD ["./qshield-audit", "--serve"]
