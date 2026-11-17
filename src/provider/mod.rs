//! Provider boundary, shared credential loading, and HTTP helpers.

#[allow(unsafe_code)]
mod lock;

pub mod aws;
pub mod azure;
pub mod gcp;
pub mod github;
pub mod infisical;
pub mod keepass;
pub mod proton;
pub mod vault;
pub mod vaultwarden;

use std::fmt;
use std::fs;
use std::io::Read;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use crate::config::{Config, ProviderConfig};
use crate::error::{Error, Result};
use crate::secret::Secret;

/// Maximum bytes read for a credential file.
const MAX_CREDENTIAL_BYTES: u64 = 64 * 1024;

/// Maximum bytes accepted in one HTTP response.
const MAX_RESPONSE_BYTES: u64 = 8 * 1024 * 1024;

/// One key returned by a metadata-only listing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ListedKey {
    /// Provider-native key, including an optional `#field`.
    pub key: String,
}

impl ListedKey {
    /// Creates a listed key.
    #[must_use]
    pub fn new(key: impl Into<String>) -> Self {
        Self { key: key.into() }
    }
}

/// Result of a create-if-absent write.
///
/// Neither variant carries a secret. `Present` means the provider confirmed
/// the key already existed and this call did not write.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnsureStatus {
    /// This call created the key.
    Created,
    /// The key was already present. The existing value was not read or replaced.
    Present,
}

/// What a provider can do in this build.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Capabilities {
    /// Values can be read.
    pub read: bool,
    /// Values can be written, including over an existing key.
    pub write: bool,
    /// Names can be enumerated without reading values.
    pub list: bool,
    /// Create-if-absent is implemented and will not overwrite.
    pub ensure: bool,
}

impl Capabilities {
    /// Read-only capabilities.
    pub const READ_ONLY: Self = Self {
        read: true,
        write: false,
        list: true,
        ensure: false,
    };

    /// Read and write capabilities. `ensure` stays false until the adapter
    /// has a race-safe create-if-absent path.
    #[allow(dead_code)]
    pub const READ_WRITE: Self = Self {
        read: true,
        write: true,
        list: true,
        ensure: false,
    };
}

/// A configured secret provider.
pub trait Provider: Send + Sync {
    /// Configuration profile name.
    fn name(&self) -> &str;

    /// Provider kind.
    fn kind(&self) -> &'static str;

    /// Capabilities implemented by this adapter.
    fn capabilities(&self) -> Capabilities;

    /// Lists key names under a prefix. Must not fetch or return values.
    fn list(&self, prefix: &str) -> Result<Vec<ListedKey>>;

    /// Reads one value.
    fn get(&self, key: &str) -> Result<Secret>;

    /// Writes one value. The default is an explicit unsupported error.
    fn set(&self, _key: &str, _value: &Secret) -> Result<()> {
        Err(crate::error::unsupported("set", self.name()))
    }

    /// Creates a key only when the provider confirms it is absent.
    ///
    /// The default is unsupported. An implementation must not treat an auth,
    /// network, or ambiguous error as absence, and must not overwrite a key
    /// that appears during a race. There is no delete path on this trait.
    fn ensure(&self, _key: &str, _value: &Secret) -> Result<EnsureStatus> {
        Err(crate::error::unsupported("ensure", self.name()))
    }
}

impl fmt::Debug for dyn Provider {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Provider")
            .field("name", &self.name())
            .field("kind", &self.kind())
            .finish_non_exhaustive()
    }
}

/// A provider selected from a configuration profile.
#[derive(Clone)]
pub struct SelectedProvider {
    /// Configured profile name.
    pub name: String,
    /// Adapter.
    pub provider: Arc<dyn Provider>,
}

impl fmt::Debug for SelectedProvider {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SelectedProvider")
            .field("name", &self.name)
            .field("kind", &self.provider.kind())
            .finish()
    }
}

/// Selects and builds a provider.
///
/// # Errors
///
/// Returns an error when no profile is configured, the selected profile does
/// not exist, or the provider's configuration is invalid.
pub fn select(config: &Config, requested: Option<&str>) -> Result<SelectedProvider> {
    let name = match requested {
        Some(name) => name.to_owned(),
        None => match &config.document.provider {
            Some(name) => name.clone(),
            None if config.document.providers.len() == 1 => config
                .document
                .providers
                .keys()
                .next()
                .cloned()
                .expect("one provider"),
            None => {
                return Err(Error::new(
                    "no provider selected: set `provider` in .nsvault.toml or pass --provider",
                ));
            }
        },
    };
    let profile = config
        .document
        .providers
        .get(&name)
        .ok_or_else(|| Error::new(format!("provider profile {name:?} is not defined")))?;
    let provider = build(&name, profile, &config.root)?;
    Ok(SelectedProvider { name, provider })
}

fn build(name: &str, profile: &ProviderConfig, root: &Path) -> Result<Arc<dyn Provider>> {
    let provider: Arc<dyn Provider> = match profile {
        ProviderConfig::Vault(config) => Arc::new(vault::VaultProvider::new(
            name,
            vault::VaultFlavor::Vault,
            config,
            root,
        )?),
        ProviderConfig::Openbao(config) => Arc::new(vault::VaultProvider::new(
            name,
            vault::VaultFlavor::OpenBao,
            config,
            root,
        )?),
        ProviderConfig::Keepass(config) => {
            Arc::new(keepass::KeepassProvider::new(name, config, root)?)
        }
        ProviderConfig::Infisical(config) => {
            Arc::new(infisical::InfisicalProvider::new(name, config, root)?)
        }
        ProviderConfig::Vaultwarden(config) => {
            Arc::new(vaultwarden::VaultwardenProvider::new(name, config, root)?)
        }
        ProviderConfig::Proton(config) => {
            Arc::new(proton::ProtonProvider::new(name, config, root)?)
        }
        ProviderConfig::Github(config) => {
            Arc::new(github::GithubProvider::new(name, config, root)?)
        }
        ProviderConfig::AwsSecretsManager(config) => {
            Arc::new(aws::AwsSecretsManagerProvider::new(name, config, root)?)
        }
        ProviderConfig::GcpSecretManager(config) => {
            Arc::new(gcp::GcpSecretManagerProvider::new(name, config, root)?)
        }
        ProviderConfig::AzureKeyVault(config) => {
            Arc::new(azure::AzureKeyVaultProvider::new(name, config, root)?)
        }
    };
    Ok(provider)
}

/// Returns the configured default prefix.
#[must_use]
pub fn default_prefix(config: &Config, requested: Option<&str>) -> String {
    requested
        .map(str::to_owned)
        .or_else(|| config.document.prefix.clone())
        .unwrap_or_default()
}

/// Reads a credential from an environment variable.
///
/// # Errors
///
/// Returns an error naming the variable when it is unset or contains an
/// embedded NUL or newline. The value is never included in the error.
pub fn credential_from_env(variable: &str) -> Result<Secret> {
    let value = std::env::var_os(variable).ok_or_else(|| {
        Error::new(format!(
            "required environment variable {variable} is not set"
        ))
    })?;
    let bytes = value.as_encoded_bytes();
    validate_credential_bytes(bytes, "environment variable")?;
    Ok(Secret::new(bytes.to_vec()))
}

/// Reads a credential from an owner-only file.
///
/// # Errors
///
/// Returns an error when the file is missing, larger than 64 KiB, not a regular
/// file, or contains NUL or a newline in the middle.
pub fn credential_from_file(path: &Path) -> Result<Secret> {
    // Open first and validate the opened handle. A separate metadata(path)
    // call followed by open() would let the path be replaced between the two.
    let file = fs::File::open(path).map_err(|_| Error::new("credential file is not readable"))?;
    let metadata = file
        .metadata()
        .map_err(|_| Error::new("credential file metadata is not readable"))?;
    if !metadata.is_file() {
        return Err(Error::new("credential path is not a regular file"));
    }
    if metadata.len() > MAX_CREDENTIAL_BYTES {
        return Err(Error::new(format!(
            "credential file is larger than {MAX_CREDENTIAL_BYTES} bytes"
        )));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(Error::new(
                "credential file must not be accessible by group or others",
            ));
        }
    }
    // Read through the same handle and take one extra byte so a file that grew
    // after the metadata check is still bounded and rejected, not truncated.
    let mut bytes = Vec::new();
    file.take(MAX_CREDENTIAL_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| Error::new("cannot read credential file"))?;
    if bytes.len() > MAX_CREDENTIAL_BYTES as usize {
        return Err(Error::new(format!(
            "credential file is larger than {MAX_CREDENTIAL_BYTES} bytes"
        )));
    }
    while bytes
        .last()
        .is_some_and(|byte| matches!(byte, b'\n' | b'\r'))
    {
        bytes.pop();
    }
    validate_credential_bytes(&bytes, "credential file")?;
    Ok(Secret::new(bytes))
}
fn validate_credential_bytes(bytes: &[u8], source: &str) -> Result<()> {
    if bytes.is_empty() {
        return Err(Error::new(format!("{source} is empty")));
    }
    if bytes
        .iter()
        .any(|byte| *byte == 0 || *byte == b'\n' || *byte == b'\r')
    {
        return Err(Error::new(format!("{source} contains a NUL or newline")));
    }
    Ok(())
}

/// Reads the first configured credential source.
///
/// # Errors
///
/// Returns an error when neither source is configured or the selected source
/// cannot be read.
pub fn load_credential(
    environment: Option<&str>,
    file: Option<&Path>,
    what: &str,
) -> Result<Secret> {
    if let Some(variable) = environment
        && let Some(value) = std::env::var_os(variable)
    {
        let bytes = value.as_encoded_bytes();
        validate_credential_bytes(bytes, what)?;
        return Ok(Secret::new(bytes.to_vec()));
    }
    if let Some(path) = file {
        return credential_from_file(path);
    }
    Err(Error::new(format!(
        "{what} is not configured: set an environment variable or credential file"
    )))
}

/// Joins URL path segments onto a validated base URL.
///
/// # Errors
///
/// Returns an error when the base cannot be a path base.
pub fn endpoint(base: &url::Url, segments: &[&str]) -> Result<url::Url> {
    let mut url = base.clone();
    {
        let mut path = url
            .path_segments_mut()
            .map_err(|()| Error::new("invalid base URL"))?;
        path.pop_if_empty();
        for segment in segments {
            path.push(segment);
        }
    }
    Ok(url)
}

/// A bounded HTTP response.
pub struct HttpResponse {
    /// Status code.
    pub status: u16,
    /// Body bytes, capped at 8 MiB.
    pub body: Vec<u8>,
}

/// A minimal HTTP client with redirects disabled and a fixed timeout.
#[derive(Clone)]
pub struct HttpClient {
    agent: ureq::Agent,
}

impl fmt::Debug for HttpClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("HttpClient([REDACTED])")
    }
}

impl HttpClient {
    /// Builds a client.
    #[must_use]
    pub fn new() -> Self {
        let config = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .max_redirects(0)
            .timeout_global(Some(Duration::from_secs(20)))
            .build();
        Self {
            agent: ureq::Agent::new_with_config(config),
        }
    }

    /// Performs a request, optionally with an authentication header and body.
    ///
    /// The caller supplies the token as a secret; it is never logged.
    ///
    /// # Errors
    ///
    /// Returns a redacted transport error or response-too-large error. HTTP
    /// status codes are returned to the caller, not turned into errors here.
    pub fn request(
        &self,
        method: &str,
        url: &url::Url,
        token_header: Option<(&str, &Secret)>,
        extra_headers: &[(&str, &str)],
        content_type: &str,
        body: Option<&[u8]>,
    ) -> Result<HttpResponse> {
        let token = match token_header {
            Some((name, token)) => Some((
                name,
                std::str::from_utf8(token.expose())
                    .map_err(|_| Error::new("credential is not valid UTF-8"))?,
            )),
            None => None,
        };
        self.send(method, url, token, extra_headers, content_type, body)
    }

    /// Performs a request with `Authorization: Bearer <token>`.
    ///
    /// The temporary header value is zeroized when the request returns.
    ///
    /// # Errors
    ///
    /// Returns a redacted credential, transport, or response-too-large error.
    /// HTTP status codes are returned to the caller.
    pub fn request_bearer(
        &self,
        method: &str,
        url: &url::Url,
        token: &Secret,
        extra_headers: &[(&str, &str)],
        content_type: &str,
        body: Option<&[u8]>,
    ) -> Result<HttpResponse> {
        let token = std::str::from_utf8(token.expose())
            .map_err(|_| Error::new("credential is not valid UTF-8"))?;
        let value = zeroize::Zeroizing::new(format!("Bearer {token}"));
        self.send(
            method,
            url,
            Some(("Authorization", value.as_str())),
            extra_headers,
            content_type,
            body,
        )
    }

    fn send(
        &self,
        method: &str,
        url: &url::Url,
        token: Option<(&str, &str)>,
        extra_headers: &[(&str, &str)],
        content_type: &str,
        body: Option<&[u8]>,
    ) -> Result<HttpResponse> {
        let response = match method {
            "GET" => {
                let mut request = self
                    .agent
                    .get(url.as_str())
                    .header("Accept", "application/json")
                    .header("User-Agent", concat!("nsvault/", env!("CARGO_PKG_VERSION")));
                if let Some((name, token)) = token {
                    request = request.header(name, token);
                }
                for (name, value) in extra_headers {
                    request = request.header(*name, *value);
                }
                request.call()
            }
            "DELETE" => {
                let mut request = self
                    .agent
                    .delete(url.as_str())
                    .header("Accept", "application/json")
                    .header("User-Agent", concat!("nsvault/", env!("CARGO_PKG_VERSION")));
                if let Some((name, token)) = token {
                    request = request.header(name, token);
                }
                for (name, value) in extra_headers {
                    request = request.header(*name, *value);
                }
                request.call()
            }
            "POST" | "PUT" | "PATCH" => {
                let request = match method {
                    "POST" => self.agent.post(url.as_str()),
                    "PUT" => self.agent.put(url.as_str()),
                    _ => self.agent.patch(url.as_str()),
                };
                let mut request = request
                    .header("Accept", "application/json")
                    .header("User-Agent", concat!("nsvault/", env!("CARGO_PKG_VERSION")))
                    .header("Content-Type", content_type);
                if let Some((name, token)) = token {
                    request = request.header(name, token);
                }
                for (name, value) in extra_headers {
                    request = request.header(*name, *value);
                }
                request.send(body.unwrap_or(&[]))
            }
            _ => return Err(Error::new("unsupported HTTP method")),
        };
        let response = response.map_err(|error| transport_error(&error))?;
        let status = response.status().as_u16();
        let body = response
            .into_body()
            .with_config()
            .limit(MAX_RESPONSE_BYTES)
            .read_to_vec()
            .map_err(|_| Error::new("response body could not be read within the size limit"))?;
        Ok(HttpResponse { status, body })
    }

    /// Parses a JSON response body.
    ///
    /// # Errors
    ///
    /// Returns a redacted parse error; the body is not included.
    pub fn json<T: serde::de::DeserializeOwned>(response: &HttpResponse) -> Result<T> {
        serde_json::from_slice(&response.body)
            .map_err(|_| Error::new("response is not the expected JSON shape"))
    }
}

impl Default for HttpClient {
    fn default() -> Self {
        Self::new()
    }
}

fn transport_error(error: &ureq::Error) -> Error {
    match error {
        ureq::Error::StatusCode(status) => Error::new(format!("HTTP status {status}")),
        ureq::Error::Timeout(_) => Error::new("request timed out"),
        ureq::Error::HostNotFound => Error::new("host not found"),
        ureq::Error::RedirectFailed => Error::new("redirect refused"),
        _ => Error::new("HTTP transport failed"),
    }
}

/// Returns whether an executable exists on `PATH` or as an absolute path.
#[must_use]
pub fn command_available(command: &str) -> bool {
    let path = Path::new(command);
    if path.is_absolute() || command.contains(std::path::MAIN_SEPARATOR) {
        return path.is_file();
    }
    std::env::var_os("PATH").is_some_and(|paths| {
        std::env::split_paths(&paths).any(|directory| {
            let candidate = directory.join(command);
            candidate.is_file()
        })
    })
}

#[cfg(test)]
mod tests {
    use super::{MAX_CREDENTIAL_BYTES, credential_from_file, endpoint, validate_credential_bytes};

    #[test]
    fn endpoint_preserves_a_base_path_prefix() {
        let base = url::Url::parse("https://example.test/prefix/").expect("url");
        let result = endpoint(&base, &["api", "v4", "secrets", "A B"]).expect("endpoint");
        assert_eq!(
            result.as_str(),
            "https://example.test/prefix/api/v4/secrets/A%20B"
        );
    }

    #[test]
    fn credentials_reject_header_injection() {
        assert!(validate_credential_bytes(b"token\nInjected: yes", "test").is_err());
        assert!(validate_credential_bytes(b"", "test").is_err());
        assert!(validate_credential_bytes(b"ok", "test").is_ok());
    }

    #[test]
    fn credential_file_rejects_content_over_the_bound() {
        let path = std::env::temp_dir().join(format!(
            "nsvault-large-credential-{}-{}.token",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time")
                .as_nanos()
        ));
        std::fs::write(&path, vec![b'x'; (MAX_CREDENTIAL_BYTES + 1) as usize])
            .expect("write credential");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
                .expect("chmod 600");
        }
        assert!(credential_from_file(&path).is_err());
        std::fs::remove_file(path).expect("remove credential");
    }

    #[cfg(unix)]
    #[test]
    fn credential_files_must_not_be_group_or_world_readable() {
        use std::os::unix::fs::PermissionsExt;

        let path = std::env::temp_dir().join(format!(
            "nsvault-credential-{}-{}.token",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time")
                .as_nanos()
        ));
        std::fs::write(&path, b"not-a-real-token").expect("write credential");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("chmod 644");
        assert!(credential_from_file(&path).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("chmod 600");
        assert!(credential_from_file(&path).is_ok());
        std::fs::remove_file(path).expect("remove credential");
    }
}
