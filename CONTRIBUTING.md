# Contributing to indic

Thanks for your interest. indic is a personal project — contributions are
welcome, but please **open an issue first** to discuss what you'd like to change
before investing time in a PR.

## Development

```bash
git clone https://github.com/Wes974/indic.git
cd indic
cp .env.example .env   # fill in any API keys you have (all optional)
cargo run -- serve
```

The server starts on `http://127.0.0.1:8080`.

## Definition of Done

Before opening a pull request, ensure:

- [ ] `cargo fmt` — no diff
- [ ] `cargo clippy --all-targets -- -D warnings` — 0 warnings
- [ ] `cargo test` — all green
- [ ] New enrichers follow the existing pattern (see
      [`src/enrich/abuseipdb.rs`](src/enrich/abuseipdb.rs) for a minimal
      example) and are registered in [`src/registry.rs`](src/registry.rs)
- [ ] New environment variables are documented in
      [`.env.example`](.env.example)

## Conventions

- **Comments**: French or English — match the surrounding code.
- **Enricher modules**: one file per source in `src/enrich/`. Export a single
  public function (`enrich_ip`, `enrich_domain`, etc.) and register it in
  `src/registry.rs` via the `enricher!` macro.
- **API keys**: never hardcoded. Use `ctx.key("ENV_VAR")` — the key is
  automatically scrubbed from error output.
- **Tests**: `#[cfg(test)]` module at the bottom of each file, testing parsing
  logic. No network calls in unit tests.
- **Architecture**: see [`README.md`](README.md#architecture) for the module
  layout.

## Adding an enricher

1. Create `src/enrich/my_source.rs` following the pattern in
   [`abuseipdb.rs`](src/enrich/abuseipdb.rs).
2. Declare the module in [`src/enrich.rs`](src/enrich.rs) (`pub(crate) mod my_source;`).
3. Register it in [`src/registry.rs`](src/registry.rs) with a single
   `enricher!` invocation.
4. Add any new environment variable to [`.env.example`](.env.example).
5. Add a `#[cfg(test)]` module with at least one parsing test.
