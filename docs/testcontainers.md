# Container integration tests

These tests are opt-in. They require a working Docker daemon and pull pinned
images. They never use real credentials. Each test starts only its own
container(s); testcontainers removes them on drop. Do not run broad Docker
cleanup or remove unrelated containers, volumes, networks, or images.

## Vault: implemented and exercised

`tests/container_vault.rs` starts:

- image: `hashicorp/vault:1.21.4`
- command: `vault server -dev -dev-listen-address=0.0.0.0:8200`
- dummy root token: `nvault-test-root-token` (not a real credential)
- only its own mapped port and container

The test covers the security fixes directly: after writing `value` and a
sibling `user` field, it replaces `value` without `#field` and asserts that
`user` survives. This proves the adapter uses a merge patch for an existing
secret, not a whole-secret POST replacement. The initial create also exercises
the Vault KV v2 CAS 0 create body on a real server. The same run then calls
`ensure` for a missing path and again with a different value, and asserts the
second call leaves the first value in place. It also ensures a missing field
on the existing secret, checks the sibling field is still there, and then
ensures that same field a second time with a different value. That second call
must report `present` and leave the value unchanged; it is the check that the
adapter reads the documented `data.subkeys` response on a real server.

Run it explicitly:

```sh
cargo test --test container_vault -- --ignored --nocapture
```

Observed in this workspace on 2026-11-17, including the ensure checks above:

```text
test vault_kv_v2_round_trip_preserves_sibling_fields ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
finished in 44.41s
```

The testcontainers-managed container was gone after the run. The pulled image
remains locally; removing it is a separate, explicit decision.

## Cloud providers: implemented and exercised with Floci

`tests/container_cloud.rs` starts one pinned Floci release image per test:

- AWS: `floci/floci:2.5.0` on port 4566
- GCP: `floci/floci-gcp:0.13.0` on port 4588
- Azure: `floci/floci-az:0.17.0` on port 4577, with Azure Functions disabled and
  no Docker socket

Each test maps the port to a random loopback host port, uses only temporary
owner-only credential files with obviously fake values, and lets testcontainers
remove its own container. The full evidence, image digests, and limits are in
[`floci.md`](floci.md).

```sh
cargo test --test container_cloud -- --ignored --nocapture
```

Observed in this workspace on 2026-11-17:

```text
running 3 tests
test gcp_secret_manager_round_trips_through_floci ... ok
test azure_key_vault_round_trips_through_floci ... ok
test aws_secrets_manager_round_trips_through_floci ... ok

test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```

## Infisical: implemented and exercised

`tests/container_infisical.rs` starts three containers, each only for this
test, on the default Docker bridge and reaches each by its own container
address. Only Infisical's port is published to the host.

- `postgres:17-alpine`, with a dummy `infisical` database and password
- `redis:7.4-alpine`
- `infisical/infisical:v0.167.11`, with a fixed dummy `ENCRYPTION_KEY` and
  `AUTH_SECRET`, `HOST=0.0.0.0`, telemetry and the update check disabled

The test polls `/api/status` until the instance answers, then calls the
documented bootstrap endpoint `POST /api/v1/admin/bootstrap` with an
`@example.invalid` address and a fixed fake password. It creates a project with
the `default` template (which creates the `dev` environment) and configures the
adapter with the bootstrap machine token in an owner-only file. The token and
every value live only in this throwaway instance and a temporary directory.

The run covers `set` (create), `get`, `set` (replace), the metadata-only list,
and `ensure`. It proves `ensure` with the adapter: a first call creates, a
second call with a different value reports present and leaves the first value
unchanged.

It also probes the server's Create (`POST`) contract directly. Eight requests
with distinct values are released through one barrier. Exactly one must return
`200`; every other request must return an error status, the winner's value must
be the one read back, and the list must contain one row for that name. The
pinned source for tag v0.167.11 (commit `37b7556`) defines the partial unique
index `uq_secrets_v2_key_folder_id_shared` on (`key`, `folderId`) where
`type = 'shared'`; the concurrent run confirms a losing insert is rejected
instead of replacing the winning row. A loopback fixture also checks that
approval, malformed, empty, and mismatched `200` Create bodies are errors
rather than reported creates.

Run it explicitly:

```sh
cargo test --test container_infisical -- --ignored --nocapture
```

Observed in this workspace on 2026-11-17:

```text
concurrent Create statuses: [(0, 200), (1, 500), (2, 500), (3, 500), (4, 500), (5, 500), (6, 500), (7, 500)]
test infisical_reads_writes_and_lists_against_the_pinned_image ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
finished in 67.72s
```

The three testcontainers-managed containers were gone after the run.

Notes:

- Startup takes roughly two minutes while migrations run; the readiness budget
  is 300 seconds.
- The first run of this test exposed a real adapter defect: the request sent
  the raw machine token in `Authorization`, and Infisical answered `403`. The
  API requires the `Bearer` scheme. `src/provider/infisical.rs` now builds the
  header value with that scheme, and the loopback fixture test asserts it.

## Vaultwarden: implemented and exercised

`tests/container_vaultwarden.rs` starts:

- image: `vaultwarden/server:1.37.5`
- `SIGNUPS_ALLOWED=true`, `I_REALLY_WANT_VOLATILE_STORAGE=true`,
  `WEB_VAULT_ENABLED=false`, only its own mapped port
- a pinned `@bitwarden/cli` supplied through `NVAULT_TEST_BW`

The test creates a throwaway account inside the container through the
documented registration flow (`/identity/accounts/register/send-verification-email`,
then `/identity/accounts/register/finish`). It derives the account keys locally
the way the clients do: PBKDF2-SHA256 over the email, HKDF-Expand with `enc` and
`mac`, and a type-2 EncString over a random 64-byte user key. `100000`
iterations is the minimum this Vaultwarden release accepts. The address is
`@example.invalid` and the password is a fixed fake.

Two independent CLI states are prepared, each with its own
`BITWARDENCLI_APPDATA_DIR`, wrapper script, session file, and configuration.
The second state logs in before the item exists, so its local copy is missing
it. The first state creates `DB`; the second state then sets `DB#username`.
Because a write syncs under the shared lock before the lookup, the second state
sees the item and updates it instead of creating a duplicate. The run asserts
both fields on one item, replaces the password from the first state, adds a
custom field from the second, and checks every sibling survives. The refusal of
`ensure` is checked too.

The second state then acts as an external writer: it edits `login.password`
directly. The adapter's next write syncs, preserves that external password, and
replaces only `notes`. Finally, the test captures the first state's item, lets
the second state advance the revision, and replays the captured stale item
through the CLI; the server must reject it. That checks the residual
sync-to-edit window, not coordination. A loopback fixture with a failing `sync`
asserts that no lookup or write is attempted and no value leaks.

Run it explicitly:

```sh
NVAULT_TEST_BW=/path/to/pinned/bw \
  cargo test --test container_vaultwarden -- --ignored --nocapture
```

Observed in this workspace on 2026-11-17, with `NVAULT_TEST_BW` pointing at
`@bitwarden/cli` 2025.6.1:

```text
test vaultwarden_two_cli_states_preserve_fields ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
finished in 123.68s
```

The testcontainers-managed container was gone after the run. The temporary
Bitwarden CLI state and session file were removed with the test directory.

CLI pinning is deliberate:

- `@bitwarden/cli` 2024.9.0 sends item writes without the `encryptedFor` field
  that Vaultwarden 1.37.5 requires, so an item create fails with `422`.
- `@bitwarden/cli` 2026.10.1 refuses any non-HTTPS server URL before sending a
  request (`InsecureUrlNotAllowedError`), so it cannot reach this plaintext
  loopback container.
- `@bitwarden/cli` 2025.6.1 is the newest release this harness verified against
  the pinned container over loopback HTTP. The adapter's command surface
  (`list items`, `get item`, `create item`, `edit item` reading encoded JSON
  from stdin) is the same surface the newer CLI documents.

The test never logs in to or unlocks a real account, never reads a real vault,
and does not reuse the CLI state of the developer running it.

## What is not claimed

No production Vault, Infisical, or Vaultwarden server was contacted. The
Infisical `ensure` atomicity is a property of the pinned v0.167.11 server: it
depends on the partial unique index named above, and a create that loses a
concurrent insert race is returned as an error rather than `present`. The
Vaultwarden adapter has no `ensure`, and its write path has not been exercised
against a current CLI over HTTPS.
The Vaultwarden test proves the server's stale-revision rejection, not
coordination of external clients; the README states the residual race.
Floci does not validate AWS SigV4 signatures, and passing the cloud tests is
not production verification against AWS, GCP, or Azure. CI does not run
container tests by default; they are explicit opt-in commands.
