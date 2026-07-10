# syntax=docker/dockerfile:1

# ---- build ----
# Image multi-arch : `docker buildx build --platform linux/arm64` pour l'Oracle Ampere.
FROM rust:1-bookworm AS builder
WORKDIR /app
# Cache des deps : on copie d'abord les manifestes.
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo 'fn main() {}' > src/main.rs && cargo build --release && rm -rf src
# Puis le vrai code.
COPY src ./src
RUN touch src/main.rs && cargo build --release

# ---- runtime ----
# distroless/cc : libc + ca-certificates (nécessaires à rustls pour valider le TLS
# lors des refresh de feeds), image minuscule, pas de shell.
FROM gcr.io/distroless/cc-debian12
COPY --from=builder /app/target/release/indic /usr/local/bin/indic
ENV INDIC_DATA_DIR=/data \
    INDIC_BIND=0.0.0.0:8080 \
    INDIC_REFRESH_HOURS=12
VOLUME ["/data"]
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/indic"]
CMD ["serve"]
