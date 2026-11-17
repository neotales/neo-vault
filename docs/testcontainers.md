# Container integration tests

These tests are opt-in. They require a working Docker daemon and pull pinned
images. They never use real credentials. Each test starts only its own
container(s); testcontainers removes them on drop. Do not run broad Docker
cleanup or remove unrelated containers, volumes, networks, or images.

## Vault: implemented and exercised

`tests/container_vault.rs` starts:

- image: `hashicorp/vault:1.21.4`
- command: `vault server -dev -dev-listen-address=0.0.0.0:8200`
- dummy root token: `nsvault-test-root-token` (not a real credential)
- only its own mapped port and container

The test covers the security fixes directly: after writing `value` and a
sibling `user` field, it replaces `value` without `#field` and asserts that
`user` survives. This proves the adapter uses a merge patch for an existing
secret, not a whole-secret POST replacement. The initial create also exercises
the Vault KV v2 CAS 0 create body on a real server. The same run then calls
`ensure` for a missing path and again with a different value, and asserts the
second call leaves the first value in place. It also ensures a missing field
on the existing secret and checks the sibling field is still there.

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

## Vaultwarden: deferred, concrete prerequisites

Not implemented in this increment. The adapter invokes the Bitwarden CLI; the
test image alone is not enough.

A future test must:

1. Start `vaultwarden/server:1.37.5` with `SIGNUPS_ALLOWED=true` and a dummy
   `ADMIN_TOKEN`; use only a loopback mapped port.
2. Install a pinned `bw` CLI in the test runner (the adapter's documented
   dependency; it is not present here).
3. Create an isolated account with a dummy master password, unlock it, and
   export only the resulting test session. Do not use a real account or real
   vault.
4. Run `get`, `ls`, and the read-only refusal paths through `nsvault`.
5. Tear down only the test's Vaultwarden container and temporary `bw` state.

Reason for deferral: the missing pinned `bw` prerequisite and account/session
setup are a separate test-harness increment, not something to fake with the
HTTP API.

## Infisical: deferred, concrete prerequisites

Not implemented in this increment. The official image is not a single-container
service.

A future test must:

1. Start a private testcontainers network with pinned
   `postgres:17-alpine`, `redis:7.4-alpine`, and
   `infisical/infisical:v0.167.11`.
2. Supply dummy local encryption/auth/database/Redis settings. No real
   credential may appear in source, logs, or output.
3. Create a project, environment, and a fixture secret with an obviously fake
   value, then run `nsvault ls/get/set` against a loopback endpoint.
4. Tear down only those three containers and the test network.

Reason for deferral: this is a multi-service harness and its startup contract
needs its own documented verification. Running a half-configured container
would not prove the adapter works.

## What is not claimed

No Vaultwarden or Infisical container test ran. The container tests that ran
are Vault and the three Floci cloud adapters; their evidence is above. Floci
does not validate AWS SigV4 signatures, and passing these tests is not
production verification against AWS, GCP, or Azure. CI does not run container
tests by default; they are explicit opt-in commands.
