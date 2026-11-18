# AGENTS.md

`dev` is the integration branch. Do not create or commit to `main`/`master`.

## Gates

Run from the repository root:

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo build --release --lib
```

Opt-in container tests (require Docker and do not run by default):

```sh
cargo test --test container_vault -- --ignored --nocapture
cargo test --test container_infisical -- --ignored --nocapture
NVAULT_TEST_BW=/path/to/pinned/bw \
  cargo test --test container_vaultwarden -- --ignored --nocapture
```

Each starts only its own pinned containers and never performs broad Docker
cleanup. See `docs/testcontainers.md`.

The C ABI check is:

```sh
cargo build --release --lib
cc examples/ffi_smoke.c -Iinclude -Ltarget/release -lnvault \
   -Wl,-rpath,"$PWD/target/release" -o /tmp/nvault-ffi-smoke
/tmp/nvault-ffi-smoke
```

## Rules

- Never put a credential, token, session, real internal hostname, or secret
  value in source, tests, fixtures, logs, or error text. Test fixtures use
  loopback servers, temporary files, and obviously fake values.
- Credentials are read only from the environment variable or owner-only file
  named by configuration. Do not add a literal `token`, `password`, `secret`,
  or `value` configuration field.
- `set` takes its value from stdin or a hidden prompt. Never add a value flag
  that would put a secret in `argv`.
- Provider errors include a key and status, never a response body or child
  process output.
- Do not claim a provider is verified against a live service unless it was.
  Update the matrix in `README.md` with the exact evidence.
- Read the README and the source before changing a provider contract.
- Preserve user data. Do not clean Docker state, worktrees, or user vaults as
  part of a build or test.

## Layout

- `src/cli.rs`, `src/commands.rs` — command surface and dispatch.
- `src/config.rs` — TOML/YAML discovery, validation, no literal credentials.
- `src/provider/` — adapters and the provider boundary.
- `src/api.rs` — reusable Rust `Client`.
- `src/ffi.rs`, `include/nvault.h` — conservative C ABI.
- `src/shell.rs` — quoting, exports, directory hooks.
- `tests/cli.rs` — end-to-end CLI tests against loopback and process fixtures.
