# syntax=docker/dockerfile:1

# ---- chef (plan) ----
FROM rust:1-bookworm AS chef
RUN cargo install cargo-chef
WORKDIR /app

# ---- planner ----
FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

# ---- builder ----
FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json
COPY . .
RUN cargo build --release

# ---- runtime ----
FROM gcr.io/distroless/cc-debian12
COPY --from=builder /app/target/release/indic /usr/local/bin/indic
ENV INDIC_DATA_DIR=/data \
    INDIC_BIND=0.0.0.0:8080 \
    INDIC_REFRESH_HOURS=12
VOLUME ["/data"]
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/indic"]
CMD ["serve"]
