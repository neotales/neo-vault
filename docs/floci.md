# Floci emulator plan (conditional, not implemented)

Floci is a local emulator suite for AWS, Azure, GCP, and OCI. It is useful for
testing cloud secret adapters without a real cloud account, but **no cloud
adapter exists in this increment**, so no Floci test runs today.

## Support verified from authoritative documentation

Checked on 2026-11-17 against the vendor documentation:

| Emulator | Secret service | Evidence | Relevant for |
| --- | --- | --- | --- |
| floci (AWS) | Secrets Manager | <https://floci.io/floci/services/secrets-manager> lists `CreateSecret`, `GetSecretValue`, `PutSecretValue`, `ListSecrets`, `DescribeSecret`, `DeleteSecret`, versioning, tagging, and resource policies on port 4566. | A future `aws-secrets-manager` adapter |
| floci-gcp | Secret Manager | <https://floci.io/floci-gcp/services/secret-manager> documents the v1 REST/gRPC surface, `SECRET_MANAGER_EMULATOR_HOST=localhost:4588`, secret versions, access, and IAM bindings. | A future `gcp-secret-manager` adapter |
| floci-az | Key Vault | <https://floci.io/floci-az/services/key-vault/> documents secrets/keys/certificates CRUD, versioning, soft-delete, and the `/{account}-keyvault` path on port 4577. Key Vault requires a bearer token from floci-az's local Entra ID; plain HTTP is the default and some SDKs need an explicit HTTP transport. | A future `azure-key-vault` adapter |

What this does **not** prove:

- That the emulator's behavior matches every production edge case.
- That this repository's future adapter works. No adapter has been written.
- That a provider is safe merely because an emulator accepts a request.
- That Vaultwarden, Proton Pass, Infisical, GitHub, or KeePass can be tested
  with Floci. They cannot; Floci does not emulate those services.

## Conditional test plan

Only start this after an adapter is implemented and its configuration is
documented. Do not run these steps as part of the current gates.

1. Check the tool and document the version:
   `command -v floci && floci version`.
2. Start the relevant emulator (`floci start`, `floci gcp start`, or
   `floci az start`) and export its environment (`eval $(floci env)` and the
   cloud-specific equivalents).
3. Create only obviously fake fixture values, for example a secret named
   `nsvault-fixture` with the value `not-a-real-secret`. Do not copy a real
   cloud secret into the emulator.
4. Configure the future provider with a loopback HTTP endpoint only if the
   adapter's validation explicitly permits it for tests.
5. Exercise list, get, set, and search. Search must make metadata-only
   requests; the fake fixture value must not appear in test logs.
6. Stop only the emulator this test started. Do not run global Docker cleanup
   (`docker system prune`, `docker volume prune`, `docker rm -f $(docker ps -aq)`)
   and do not remove shared containers or volumes. Those require explicit
   verification and permission.
7. Record the exact emulator version, adapter commit, commands, and outcomes in
   the README verification matrix. Until then the cloud provider remains
   **fixture-only or unimplemented**, never "verified."

## Check on 2026-11-17

`command -v floci` found no executable in this workspace. No emulator was
started. No container was created for this check, and no Docker cleanup was
run. AWS, GCP, and Azure adapters are still unimplemented, so they were not
tested against Floci. Installing Floci was not attempted: there is no adapter
to point at an emulator, and an install without a test would not change that.

## Why it is deferred

Adding one cloud adapter requires an authentication design that does not put
credential values in argv, request signing, region/endpoint validation, and a
test fixture policy. Those are separate increments; skipping them to satisfy an
emulator would create a fake integration.
