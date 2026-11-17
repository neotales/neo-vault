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
| `infisical` | yes | yes | no | List, get, and set are fixture-shaped in the library. `set` is a GET-then-POST/PATCH write. `ensure` is refused: the Create endpoint's duplicate behavior is unproven, so no check-then-create is attempted. |
| `vaultwarden` | yes | yes | no | Fake `bw` fixture plus an opt-in container test against `vaultwarden/server:1.37.5` with `@bitwarden/cli` 2025.6.1. Writes sync the CLI state and send the encoded item on stdin; the server revision check covers the sync-to-edit window. `bw list items` returns full items; the adapter keeps names. |
| `proton` | yes | no | no | Fake `pass-cli` fixture. A write would put the value in `argv`, so it is refused. |
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
- GitHub: `SECRET_NAME`. List and set only.
- AWS Secrets Manager: `SECRET_NAME`. No field suffix.
- GCP Secret Manager: `SECRET_ID`. No field suffix; latest version only.
- Azure Key Vault: `SECRET_NAME`. No field suffix; latest version only.

`nsvault providers` prints `read`, `write`, and `ensure` from the kind. It does not call the provider.
