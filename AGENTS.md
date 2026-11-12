# Repository Guidelines

## Project Structure & Module Organization

This project is planned in Rust. The current checkout contains only this guide and PhpStorm metadata; there is no `Cargo.toml`, source code, tests, or assets yet. Use Cargo's standard layout as the project is added: `src/main.rs` for an executable or `src/lib.rs` for a library, integration tests under `tests/`, and supporting assets in a clearly named directory. Keep personal IDE state such as `.idea/workspace.xml` out of commits. Commit `Cargo.lock` for executable applications.

## Build, Test, and Development Commands

Once a `Cargo.toml` exists, use these standard commands from the repository root:

- `cargo run` builds and runs the application.
- `cargo build` compiles the project; add `--release` for an optimized build.
- `cargo test` runs unit and integration tests.
- `cargo fmt --check` checks formatting; run `cargo fmt` to apply it.
- `cargo clippy --all-targets --all-features -- -D warnings` runs lint checks.

Document any required setup or project-specific command here and in the README.

## Coding Style & Naming Conventions

Use standard Rust formatting via `rustfmt` and idiomatic names: `snake_case` for functions, modules, and variables; `UpperCamelCase` for types and traits; and `SCREAMING_SNAKE_CASE` for constants. Prefer clear, small functions and handle errors explicitly rather than silently discarding them.

## Testing Guidelines

Add unit tests near the code they cover with `#[cfg(test)]`; put integration tests in `tests/`. Name tests for the behavior they verify, and run `cargo test` before submitting changes. Add regression coverage for bug fixes.

## Commit & Pull Request Guidelines

No Git history is available to establish a commit convention. Use concise imperative subjects, such as `Add credential import`. Pull requests should explain the change and motivation, link related issues, and list validation performed. Include screenshots for visible interface changes.

## Security & Configuration

Treat copied or handled passwords as secrets: never commit credentials or log them. Keep secrets and machine-specific settings out of source control; document safe configuration using examples with secret values omitted.
