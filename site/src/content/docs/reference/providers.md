---
title: Providers
description: What each provider kind can do in this build.
---

No adapter in this repository has been verified against a live production service. The Vault row includes a fixture suite and an opt-in testcontainers run against `hashicorp/vault:1.21.4`. That is not a production server.

| Kind | Read | Write | Ensure | Status in this repository |
| --- | --- | --- | --- | --- |
| `vault` | yes | yes | yes | Fixture plus opt-in container test. Ensure uses metadata, subkeys, and CAS. |
| `openbao` | yes | yes | yes | Same adapter as `vault`. Not exercised as its own server. |
| `keepass` | yes | no | no | Fake CLI fixture. Writes are refused. |
| `infisical` | yes | yes | yes | List, get, and set are fixture-shaped in the library. Ensure follows the published Create endpoint and has not been run against a live server. |
| `vaultwarden` | yes | no | no | Fake `bw` fixture. `bw list items` returns full items; the adapter keeps names. |
| `proton` | yes | no | no | Fake `pass-cli` fixture. A write would put the value in `argv`, so it is refused. |
| `github` | no | yes | no | Sealed-box unit test only. The API never returns a value. Ensure is refused because PUT would overwrite. |

AWS Secrets Manager, GCP Secret Manager, and Azure Key Vault are not implemented. They were not tested with Floci. Floci was not installed in the workspace that recorded that check.

Key shapes:

- Vault and OpenBao: `path/to/secret` or `path/to/secret#field`.
- KeePass: `Group/Entry` or `Group/Entry#Attribute`.
- Infisical: secret name. No field suffix.
- Vaultwarden: item name or UUID, optional `#password`, `#username`, `#notes`, `#name`, `#id`, or a custom field.
- Proton: title, optional `#password`, `#username`, or another field.
- GitHub: `SECRET_NAME`. List and set only.

`nsvault providers` prints `read`, `write`, and `ensure` from the kind. It does not call the provider.
