# Floci emulator verification

The AWS Secrets Manager, GCP Secret Manager, and Azure Key Vault adapters were
tested against pinned Floci release images on 2026-11-17. The Floci CLI was not
installed; the images were run directly with Docker. No cloud account, real
credential, or production service was used.

This is emulator evidence, not production verification. The emulator does not
validate AWS SigV4 signatures, and it does not prove real cloud authentication,
IAM enforcement, quotas, regional endpoints, or service edge cases.

## Pinned images

| Emulator | Image | Manifest digest (multi-arch) | Service | Endpoint |
| --- | --- | --- | --- | --- |
| floci (AWS) | `floci/floci:2.5.0` | `sha256:a0fbf944d7f338cc0856f1ef83831ea749ff2be71956eb7a7fce08fc21458e19` | Secrets Manager | `http://127.0.0.1:4566/` |
| floci-gcp | `floci/floci-gcp:0.13.0` | `sha256:a59403d43d524b1a08282d67d541a6d37bf7868cbd9d1311caa0d2983adf6f46` | Secret Manager | `http://127.0.0.1:4588/` |
| floci-az | `floci/floci-az:0.17.0` | `sha256:40f1bbf1ef13569c6eacb47e565bf4cd28785ca833208dcc074910e13aec64ea` | Key Vault | `http://127.0.0.1:4577/devstoreaccount1-keyvault` |

The `id` values in Key Vault responses use the emulator's synthetic
`https://devstoreaccount1.vault.azure.net/...` host. The adapter extracts the
name from that id but keeps sending requests to the configured loopback
`vault_url`; it never follows a provider-supplied host.

## Vendor documentation used

- AWS Secrets Manager: <https://floci.io/floci/services/secrets-manager>
  documents the JSON 1.1 protocol (`X-Amz-Target: secretsmanager.*`),
  `CreateSecret`, `GetSecretValue`, `PutSecretValue`, `ListSecrets`, and
  `DescribeSecret` on port 4566.
- GCP Secret Manager: <https://floci.io/floci-gcp/services/secret-manager/>
  documents the v1 REST/gRPC surface, secret versions, access, and IAM
  bindings. The REST API is served under `/v1/projects/{project}/secrets/...`
  on port 4588.
- Azure Key Vault: <https://floci.io/floci-az/services/key-vault/> documents
  secrets CRUD, versioning, soft-delete, the `/{account}-keyvault` path, and
  the `api-version` query parameter on port 4577.
- Release tags and digests came from Docker Hub (`floci/floci`,
  `floci/floci-gcp`, `floci/floci-az`) and were checked with
  `docker buildx imagetools inspect`.

## Start commands

```sh
docker pull floci/floci:2.5.0@sha256:a0fbf944d7f338cc0856f1ef83831ea749ff2be71956eb7a7fce08fc21458e19
docker pull floci/floci-gcp:0.13.0@sha256:a59403d43d524b1a08282d67d541a6d37bf7868cbd9d1311caa0d2983adf6f46
docker pull floci/floci-az:0.17.0@sha256:40f1bbf1ef13569c6eacb47e565bf4cd28785ca833208dcc074910e13aec64ea

docker run -d --rm --name nsvault-floci-aws -p 127.0.0.1:4566:4566 \
  floci/floci:2.5.0@sha256:a0fbf944d7f338cc0856f1ef83831ea749ff2be71956eb7a7fce08fc21458e19
docker run -d --rm --name nsvault-floci-gcp -p 127.0.0.1:4588:4588 \
  floci/floci-gcp:0.13.0@sha256:a59403d43d524b1a08282d67d541a6d37bf7868cbd9d1311caa0d2983adf6f46
docker run -d --rm --name nsvault-floci-az \
  -e FLOCI_AZ_SERVICES_FUNCTIONS_ENABLED=false -p 127.0.0.1:4577:4577 \
  floci/floci-az:0.17.0@sha256:40f1bbf1ef13569c6eacb47e565bf4cd28785ca833208dcc074910e13aec64ea
```

The manual `docker run` commands bind to loopback only. The automated test
uses Docker's default random host-port mapping. Azure Functions is disabled so
the Azure emulator needs no Docker socket. Stop only these names if they are
still running:

```sh
docker stop nsvault-floci-aws nsvault-floci-gcp nsvault-floci-az
```

Do not run `docker system prune`, `docker volume prune`, or a broad
`docker rm -f $(docker ps -aq)` for this work. The integration test uses
testcontainers on random host ports and lets it remove only its own containers.

## Automated tests

The default gate does not start containers. Run the opt-in test explicitly:

```sh
cargo test --test container_cloud -- --ignored --nocapture
```

Observed on 2026-11-17:

```text
running 3 tests
test gcp_secret_manager_round_trips_through_floci ... ok
test azure_key_vault_round_trips_through_floci ... ok
test aws_secrets_manager_round_trips_through_floci ... ok

test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```

The final run finished in 5.42s once the pinned images were cached; the first
run took longer while pulling them.

A focused rerun of the AWS test alone, against the same pinned image, passed
in 2.02s. A raw `PutSecretValue` request for a missing secret returned
`HTTP/1.1 400 Bad Request` with a JSON body beginning
`{"__type":"ResourceNotFoundException"`. AWS documents HTTP 400 for that error,
and the adapter creates only on that exact response.

The AWS test uses access key `test` and secret key `test` from owner-only
temporary files. The GCP test uses `allow_anonymous = true` on a loopback
endpoint. The Azure test uses `floci-fake-token` from an owner-only temporary
file. All fixture values are obviously fake.

What the test covers:

- AWS: `set` on a missing name (PutSecretValue HTTP 400 with
  `ResourceNotFoundException`, then CreateSecret), `get`,
  metadata-only `list`, and `ensure` create then present without overwrite.
- GCP: `set` on a missing name (AddVersion 404, CreateSecret, AddVersion),
  `get` of the latest version, a second `set` that adds a version, metadata-only
  `list`, and refusal of `ensure` without creating a secret. Listing accepts
  both `projects/{project-id}/secrets/{id}` and
  `projects/{project-number}/secrets/{id}` resource names.
- Azure: `set`, `get` of the latest version, a second `set` that creates a new
  version, metadata-only `list`, `nextLink` pagination across 27 secrets, and
  refusal of `ensure`.

A separate loopback fixture test (`tests/aws_contract.rs`) records the
`CreateSecret` and `PutSecretValue` JSON bodies. It asserts that every write
carries a valid `ClientRequestToken` and that the Put retry after a create
conflict reuses the same logical request token.

The AWS signer is also unit-tested against AWS's published SigV4 vectors:
`get-vanilla` and `post-vanilla-query` from the AWS SigV4 test suite. Those
tests assert the full `Authorization` header, including the known signatures
`5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31` and
`28038455d6de14eafc1f9222cf5aa6f1a96197d7deb8263271d420d138af7f11`.
This proves the signing algorithm on known inputs. It does not prove that a
live AWS endpoint accepts a request built by this adapter.

## Manual CLI run

With the three fixed-port containers running, a manual run used
`.nsvault.toml` files and owner-only credential files in a private temporary
directory. The values were `not-a-real-secret`, `first-value`, and
`second-value`. The observed outcomes:

```text
AWS:   set ok; get byte-identical; ls and search returned cli-fixture-aws;
       ensure -> {"status":"created"} then {"status":"present"};
       second ensure left first-value unchanged.
GCP:   set ok; get byte-identical; ls and search returned cli-fixture-gcp;
       ensure exited 1 with "gcp does not support ensure in this build";
       the value was not written and was not echoed.
Azure: set ok; get byte-identical; ls and search returned cli-fixture-az;
       ensure exited 1 with "azure does not support ensure in this build";
       the value was not written and was not echoed.
```

`nsvault providers` printed:

```text
aws	aws-secrets-manager	read=true	write=true	ensure=true
gcp	gcp-secret-manager	read=true	write=true	ensure=false
```

No secret value appeared in an `nsvault` command argument or in error output.
The `get` comparisons used `cmp` against a fixture file, so values were not
printed to the session log.

## Adapter limits

- AWS: static access key, secret key, and optional session token. No STS
  AssumeRole, IMDS, credential chain, or refresh. SigV4 is signed locally for
  the `secretsmanager` service. The emulator accepts unsigned requests, so only
  the unit vectors validate the signature.
- GCP: static OAuth 2.0 access token, no ADC, service-account JWT exchange, or
  refresh. Anonymous access is an explicit loopback-emulator switch and is
  refused for non-loopback endpoints. `ensure` is refused because create and
  add-version are separate, non-atomic calls.
- Azure: static bearer token, no Entra ID client-credential flow, managed
  identity, or refresh. `ensure` is refused because Key Vault has no
  conditional create and a read-then-PUT would race. Only the latest version is
  read.
- None of the three adapters supports fields (`#field`), delete, rotation,
  binary values other than AWS `SecretBinary` reads, or multiple versions by
  id. GCP `ensure` is not implemented; use `set` to write a version.
