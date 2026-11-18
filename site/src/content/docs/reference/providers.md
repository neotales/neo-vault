---
title: Providers
description: What each provider kind can do in this build.
---

No adapter in this repository has been verified against a live production service. The Vault row includes a fixture suite and an opt-in testcontainers run against `hashicorp/vault:1.21.4`. That is not a production server.

| Kind | Read | Write | Ensure | Status in this repository |
| --- | --- | --- | --- | --- |
| `vault` | yes | yes | yes | Fixture plus opt-in container test. Ensure uses metadata, subkeys, and CAS. |
| `openbao` | yes | yes | yes | Same adapter as `vault`. Not exercised as its own server. |
| `keepass` | yes | yes | no | Fake CLI fixture plus an opt-in generated KDBX test for the round trip, concurrent writers, and duplicate add against `keepassxc-cli` 2.7.12. Writes replace or create only an entry's `Password` on stdin. `ensure` is refused because the CLI check-and-save is not atomic against an external writer. |
| `infisical` | yes | yes | yes | List, get, set, and ensure are fixture-shaped in the library, with an opt-in container run against `infisical/infisical:v0.167.11`. `set` is a GET-then-POST/PATCH write. `ensure` sends only Create (`POST`); the server's partial unique index rejects a duplicate with `400`, which is reported present. The `200` Create body must be the documented secret object and identify the requested key, project, environment, and shared type before the adapter reports created. |
| `vaultwarden` | yes | yes | no | Fake `bw` fixture plus an opt-in container test against `vaultwarden/server:1.37.5` with `@bitwarden/cli` 2025.6.1. Writes sync the CLI state and send the encoded item on stdin. Where the server enforces `lastKnownRevisionDate`, a write from a stale synced copy can be rejected, but the check tolerates a one-second difference, a server may not enforce it, and a later accepted write wins. `bw list items` returns full items; the adapter keeps names. |
| `proton` | yes | create only | no | Fake `pass-cli` fixture. `set` creates an absent login with `item create login --from-template -` and the JSON on stdin. An existing title is refused because `item update` still takes the value in `argv`. `ensure` is unsupported. A configured PAT uses a private per-process session directory. |
| `github` | no | yes | no | Sealed-box unit test only. The API never returns a value. Ensure is refused because PUT would overwrite. |
| `aws-secrets-manager` | yes | yes | yes | Opt-in Floci test against `floci/floci:2.5.0`. The SigV4 signer is unit-tested against AWS's published vectors. No AWS account. |
| `gcp-secret-manager` | yes | yes | no | Opt-in Floci test against `floci/floci-gcp:0.13.0`. Static OAuth token or explicit loopback anonymous mode. Ensure is refused because create and add-version are not atomic. No GCP project. |
| `azure-key-vault` | yes | yes | no | Opt-in Floci test against `floci/floci-az:0.17.0`. Static bearer token. Ensure is refused because Key Vault has no conditional create. No Azure account. |

These are emulator results, not production verification. Floci does not
validate AWS SigV4 signatures, and it does not prove real cloud
authentication, IAM, quotas, or regional behavior. Cloud credentials are
static for the process lifetime; there is no STS, ADC, managed identity, or
token refresh. See [`docs/floci.md`](https://github.com/neotales/neo-secrets-vault/blob/dev/docs/floci.md)
for pinned image digests and exact commands.

Key shapes:

- Vault and OpenBao: `path/to/secret` or `path/to/secret#field`.
- KeePass: `Group/Entry` or `Group/Entry#Attribute`. Writes accept only `Password` (or no field); other attributes and `ensure` are unsupported.
- Infisical: secret name. No field suffix.
- Vaultwarden: item name or UUID, optional `#password`, `#username`, `#notes`, `#name`, `#id`, or a custom field.
- Proton: title, optional `#password`, `#username`, or another field.

For Proton, `vault` is a vault name, not a share ID. If a title is
ambiguous, rename the item or configure a vault name where it is unique.
An explicitly configured `token_env` must be set; otherwise the operation
fails instead of using an existing session. When `token_env` is omitted, a
configured `token_file` is used, or else the existing CLI session is used
only if `PROTON_PASS_PERSONAL_ACCESS_TOKEN` is absent. If it is present,
nvault fails instead of silently choosing a session. Automatic discovery is
no longer supported: explicitly set `token_env` to that name to use the
token, or unset the variable to use the session. YAML `null` and programmatic
`None` follow the same rule.
- GitHub: `SECRET_NAME`. List and set only.
- AWS Secrets Manager: `SECRET_NAME`. No field suffix.
- GCP Secret Manager: `SECRET_ID`. No field suffix; latest version only.
- Azure Key Vault: `SECRET_NAME`. No field suffix; latest version only.

`nvault providers` prints `read`, `write`, and `ensure` from the kind. It does not call the provider.
