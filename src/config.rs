//! Directory-scoped configuration.
//!
//! The file is data, never code. It cannot contain a raw credential: token,
//! password, and session fields name an environment variable or a file, and the
//! process reads the credential at the point of use. Unknown fields are
//! rejected so a typo cannot silently disable a security setting.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::error::{Error, Result};

/// Directory-scoped configuration names, in precedence order.
pub const CONFIG_NAMES: &[&str] = &[".nvault.toml", ".nvault.yaml", ".nvault.yml"];

/// User-scoped configuration names, in precedence order.
pub const USER_CONFIG_NAMES: &[&str] = &["config.toml", "config.yaml", "config.yml"];

fn first_existing(directory: &Path, names: &[&str]) -> Option<PathBuf> {
    names
        .iter()
        .map(|name| directory.join(name))
        .find(|candidate| candidate.is_file())
}

/// Maximum accepted configuration size.
const MAX_CONFIG_BYTES: u64 = 256 * 1024;

/// The supported configuration version.
const CONFIG_VERSION: u32 = 1;

/// A loaded configuration and the directory that owns it.
#[derive(Debug)]
pub struct Config {
    /// Directory used to resolve relative file paths.
    pub root: PathBuf,
    /// Parsed document.
    pub document: Document,
}

/// The on-disk document.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Document {
    /// Format version. Only `1` is accepted.
    #[serde(default = "default_version")]
    pub version: u32,
    /// Default provider profile for commands run in this directory.
    #[serde(default)]
    pub provider: Option<String>,
    /// Default key prefix for list, search, exec, and env.
    #[serde(default)]
    pub prefix: Option<String>,
    /// Named provider profiles.
    #[serde(default)]
    pub providers: BTreeMap<String, ProviderConfig>,
}

const fn default_version() -> u32 {
    CONFIG_VERSION
}

/// One provider profile.
///
/// Every variant names credentials by environment variable or file. None
/// accepts a literal token or password.
#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum ProviderConfig {
    /// `HashiCorp` Vault KV v2.
    Vault(VaultConfig),
    /// `OpenBao` KV v2, which uses the Vault-compatible HTTP API.
    Openbao(VaultConfig),
    /// A local KeePass KDBX database read through `keepassxc-cli`.
    Keepass(KeepassConfig),
    /// Infisical shared secrets through the v4 HTTP API.
    Infisical(InfisicalConfig),
    /// `Vaultwarden` through the Bitwarden `bw` CLI.
    Vaultwarden(VaultwardenConfig),
    /// Proton Pass through the official `pass-cli`.
    Proton(ProtonConfig),
    /// GitHub Actions repository secrets through the `GitHub` REST API.
    Github(GithubConfig),
    /// AWS Secrets Manager through the JSON 1.1 API and SigV4.
    AwsSecretsManager(AwsSecretsManagerConfig),
    /// Google Cloud Secret Manager through the v1 REST API.
    GcpSecretManager(GcpSecretManagerConfig),
    /// Azure Key Vault through the secrets data-plane REST API.
    AzureKeyVault(AzureKeyVaultConfig),
}

/// Shared Vault/OpenBao configuration.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VaultConfig {
    /// Server root, for example `https://vault.example`.
    pub address: String,
    /// KV v2 mount path. Defaults to `secret`.
    #[serde(default = "default_mount")]
    pub mount: String,
    /// Environment variable holding the token. Defaults to `VAULT_TOKEN`.
    #[serde(default = "default_vault_token_env")]
    pub token_env: Option<String>,
    /// Owner-only file holding the token. Used only when `token_env` is unset
    /// or its variable is absent.
    #[serde(default)]
    pub token_file: Option<PathBuf>,
    /// Optional Vault enterprise namespace.
    #[serde(default)]
    pub namespace: Option<String>,
    /// Permit plaintext HTTP only for a loopback address. Intended for local
    /// development and tests; refused for every other host.
    #[serde(default)]
    pub allow_http_loopback: bool,
}

/// KeePass configuration.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeepassConfig {
    /// KDBX database path.
    pub database: PathBuf,
    /// Optional key file.
    #[serde(default)]
    pub key_file: Option<PathBuf>,
    /// Environment variable holding the database password.
    #[serde(default)]
    pub password_env: Option<String>,
    /// Owner-only file holding the database password.
    #[serde(default)]
    pub password_file: Option<PathBuf>,
    /// Executable name or absolute path. Defaults to `keepassxc-cli`.
    #[serde(default = "default_keepassxc")]
    pub command: String,
}

/// Infisical configuration.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InfisicalConfig {
    /// Instance root, for example `https://app.infisical.com`.
    #[serde(default = "default_infisical_address")]
    pub address: String,
    /// Project identifier.
    pub project_id: String,
    /// Environment slug.
    pub environment: String,
    /// Secret folder. Defaults to `/`.
    #[serde(default = "default_secret_path")]
    pub path: String,
    /// Environment variable holding a service token or machine access token.
    /// Defaults to `INFISICAL_TOKEN`.
    #[serde(default = "default_infisical_token_env")]
    pub token_env: Option<String>,
    /// Owner-only file holding the token.
    #[serde(default)]
    pub token_file: Option<PathBuf>,
    /// Environment variable holding a Universal Auth client id.
    #[serde(default)]
    pub client_id_env: Option<String>,
    /// Environment variable holding a Universal Auth client secret.
    #[serde(default)]
    pub client_secret_env: Option<String>,
    /// Permit plaintext HTTP only for a loopback address.
    #[serde(default)]
    pub allow_http_loopback: bool,
}

/// `Vaultwarden` configuration backed by the Bitwarden CLI.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VaultwardenConfig {
    /// Executable name or absolute path. Defaults to `bw`.
    #[serde(default = "default_bw")]
    pub command: String,
    /// Environment variable holding `BW_SESSION`. Defaults to `BW_SESSION`.
    #[serde(default = "default_bw_session_env")]
    pub session_env: Option<String>,
    /// Owner-only file holding `BW_SESSION`.
    #[serde(default)]
    pub session_file: Option<PathBuf>,
}

/// Proton Pass configuration backed by `pass-cli`.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtonConfig {
    /// Executable name or absolute path. Defaults to `pass-cli`.
    #[serde(default = "default_pass_cli")]
    pub command: String,
    /// Vault name, passed to `pass-cli` as `--vault-name`. Omit to search
    /// without a vault-name filter.
    #[serde(default)]
    pub vault: Option<String>,
    /// Environment variable holding a personal access token. If explicitly
    /// configured it must be set. When omitted, the standard
    /// `PROTON_PASS_PERSONAL_ACCESS_TOKEN` is used if present.
    #[serde(default)]
    pub token_env: Option<String>,
    /// Owner-only file holding the personal access token.
    #[serde(default)]
    pub token_file: Option<PathBuf>,
    /// Reason passed to the agent-scoped CLI through
    /// `PROTON_PASS_AGENT_REASON`. Required by agent tokens, harmless otherwise.
    #[serde(default)]
    pub reason: Option<String>,
}

/// GitHub Actions repository secret configuration.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GithubConfig {
    /// Repository owner.
    pub owner: String,
    /// Repository name.
    pub repo: String,
    /// API root. Defaults to `https://api.github.com`.
    #[serde(default = "default_github_api")]
    pub api_url: String,
    /// Environment variable holding the API token. Defaults to
    /// `GITHUB_TOKEN`.
    #[serde(default = "default_github_token_env")]
    pub token_env: Option<String>,
    /// Owner-only file holding the API token.
    #[serde(default)]
    pub token_file: Option<PathBuf>,
}

/// AWS Secrets Manager configuration.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AwsSecretsManagerConfig {
    /// AWS region used for the credential scope and the default endpoint.
    pub region: String,
    /// API root. Defaults to `https://secretsmanager.{region}.amazonaws.com`.
    #[serde(default)]
    pub endpoint: Option<String>,
    /// Environment variable holding the access key id. Defaults to
    /// `AWS_ACCESS_KEY_ID`.
    #[serde(default = "default_aws_access_key_env")]
    pub access_key_env: Option<String>,
    /// Owner-only file holding the access key id.
    #[serde(default)]
    pub access_key_file: Option<PathBuf>,
    /// Environment variable holding the secret access key. Defaults to
    /// `AWS_SECRET_ACCESS_KEY`.
    #[serde(default = "default_aws_secret_key_env")]
    pub secret_key_env: Option<String>,
    /// Owner-only file holding the secret access key.
    #[serde(default)]
    pub secret_key_file: Option<PathBuf>,
    /// Environment variable holding a temporary session token. Defaults to
    /// `AWS_SESSION_TOKEN`; an absent variable means no session token.
    #[serde(default = "default_aws_session_token_env")]
    pub session_token_env: Option<String>,
    /// Owner-only file holding a temporary session token.
    #[serde(default)]
    pub session_token_file: Option<PathBuf>,
    /// Permit plaintext HTTP only for a loopback address. Intended for the
    /// local emulator; refused for every other host.
    #[serde(default)]
    pub allow_http_loopback: bool,
}

/// Google Cloud Secret Manager configuration.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GcpSecretManagerConfig {
    /// Project id or number used in the resource path.
    pub project: String,
    /// API root. Defaults to `https://secretmanager.googleapis.com`.
    #[serde(default = "default_gcp_endpoint")]
    pub endpoint: String,
    /// Environment variable holding an OAuth 2.0 access token. Defaults to
    /// `GOOGLE_OAUTH_ACCESS_TOKEN`.
    #[serde(default = "default_gcp_token_env")]
    pub token_env: Option<String>,
    /// Owner-only file holding an OAuth 2.0 access token.
    #[serde(default)]
    pub token_file: Option<PathBuf>,
    /// Send no credential. Accepted only for a loopback emulator endpoint;
    /// real Secret Manager requires a token.
    #[serde(default)]
    pub allow_anonymous: bool,
    /// Permit plaintext HTTP only for a loopback address.
    #[serde(default)]
    pub allow_http_loopback: bool,
}

/// Azure Key Vault configuration.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AzureKeyVaultConfig {
    /// Vault data-plane root, for example `https://myvault.vault.azure.net` or
    /// the local emulator's `http://127.0.0.1:4577/devstoreaccount1-keyvault`.
    pub vault_url: String,
    /// Key Vault data-plane API version. Defaults to `7.4`.
    #[serde(default = "default_azure_api_version")]
    pub api_version: String,
    /// Environment variable holding a bearer token. Defaults to
    /// `AZURE_ACCESS_TOKEN`.
    #[serde(default = "default_azure_token_env")]
    pub token_env: Option<String>,
    /// Owner-only file holding a bearer token.
    #[serde(default)]
    pub token_file: Option<PathBuf>,
    /// Permit plaintext HTTP only for a loopback address. Intended for the
    /// local emulator; refused for every other host.
    #[serde(default)]
    pub allow_http_loopback: bool,
}

fn default_mount() -> String {
    "secret".to_owned()
}

fn default_vault_token_env() -> Option<String> {
    Some("VAULT_TOKEN".to_owned())
}

fn default_keepassxc() -> String {
    "keepassxc-cli".to_owned()
}

fn default_infisical_address() -> String {
    "https://app.infisical.com".to_owned()
}

fn default_secret_path() -> String {
    "/".to_owned()
}

fn default_infisical_token_env() -> Option<String> {
    Some("INFISICAL_TOKEN".to_owned())
}

fn default_bw() -> String {
    "bw".to_owned()
}

fn default_bw_session_env() -> Option<String> {
    Some("BW_SESSION".to_owned())
}

fn default_pass_cli() -> String {
    "pass-cli".to_owned()
}

fn default_github_api() -> String {
    "https://api.github.com".to_owned()
}

fn default_github_token_env() -> Option<String> {
    Some("GITHUB_TOKEN".to_owned())
}

fn default_aws_access_key_env() -> Option<String> {
    Some("AWS_ACCESS_KEY_ID".to_owned())
}

fn default_aws_secret_key_env() -> Option<String> {
    Some("AWS_SECRET_ACCESS_KEY".to_owned())
}

fn default_aws_session_token_env() -> Option<String> {
    Some("AWS_SESSION_TOKEN".to_owned())
}

fn default_gcp_endpoint() -> String {
    "https://secretmanager.googleapis.com".to_owned()
}

fn default_gcp_token_env() -> Option<String> {
    Some("GOOGLE_OAUTH_ACCESS_TOKEN".to_owned())
}

fn default_azure_api_version() -> String {
    "7.4".to_owned()
}

fn default_azure_token_env() -> Option<String> {
    Some("AZURE_ACCESS_TOKEN".to_owned())
}

impl Config {
    /// Loads and validates a configuration file.
    ///
    /// # Errors
    ///
    /// Returns an error for an unreadable file, a size over 256 KiB, a parse
    /// failure, an unsupported version, an invalid provider name, or an invalid
    /// field value.
    pub fn load(path: &Path) -> Result<Self> {
        let metadata =
            fs::metadata(path).map_err(|_| Error::new("configuration file is not readable"))?;
        if metadata.len() > MAX_CONFIG_BYTES {
            return Err(Error::new(format!(
                "configuration is larger than {MAX_CONFIG_BYTES} bytes"
            )));
        }
        let bytes = fs::read(path).map_err(|_| Error::new("configuration file is not readable"))?;
        let text = std::str::from_utf8(&bytes)
            .map_err(|_| Error::new("configuration is not valid UTF-8"))?;
        let document: Document = match path.extension().and_then(std::ffi::OsStr::to_str) {
            Some("yaml" | "yml") => serde_yaml_ng::from_str(text).map_err(|error| {
                Error::new("configuration is not valid YAML").with_source(error)
            })?,
            _ => toml::from_str(text).map_err(|error| {
                Error::new("configuration is not valid TOML").with_source(error)
            })?,
        };
        let config = Self {
            root: path
                .parent()
                .unwrap_or_else(|| Path::new("."))
                .to_path_buf(),
            document,
        };
        config.validate()?;
        Ok(config)
    }

    /// Discovers a configuration from the current directory upwards, then from
    /// the user configuration directory.
    ///
    /// `NVAULT_CONFIG`, when set, wins and may point at a file or a directory.
    #[must_use]
    pub fn discover(start: &Path) -> Option<PathBuf> {
        if let Some(explicit) = std::env::var_os("NVAULT_CONFIG") {
            let path = PathBuf::from(explicit);
            if path.is_dir() {
                return first_existing(&path, CONFIG_NAMES)
                    .or_else(|| first_existing(&path, USER_CONFIG_NAMES));
            }
            return Some(path);
        }
        for directory in start.ancestors() {
            if let Some(candidate) = first_existing(directory, CONFIG_NAMES) {
                return Some(candidate);
            }
        }
        let config_home = std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")))?;
        first_existing(&config_home.join("nvault"), USER_CONFIG_NAMES)
    }

    fn validate(&self) -> Result<()> {
        if self.document.version != CONFIG_VERSION {
            return Err(Error::new(format!(
                "unsupported configuration version {}; expected {CONFIG_VERSION}",
                self.document.version
            )));
        }
        for name in self.document.providers.keys() {
            if !is_profile_name(name) {
                return Err(Error::new(format!(
                    "invalid provider profile name {name:?}: use lowercase letters, digits, '-' and '_'"
                )));
            }
        }
        if let Some(provider) = &self.document.provider
            && !self.document.providers.contains_key(provider)
        {
            return Err(Error::new(format!(
                "default provider {provider:?} is not defined under [providers]"
            )));
        }
        for (name, provider) in &self.document.providers {
            validate_provider(name, provider)?;
        }
        Ok(())
    }
}

fn validate_provider(name: &str, provider: &ProviderConfig) -> Result<()> {
    let invalid = |message: String| Error::new(format!("provider {name:?}: {message}"));
    match provider {
        ProviderConfig::Vault(config) | ProviderConfig::Openbao(config) => {
            validate_http_base(&config.address, config.allow_http_loopback)
                .map_err(|error| invalid(error.message().to_owned()))?;
            if config.mount.is_empty() || config.mount.contains('/') {
                return Err(invalid(
                    "mount must be a single non-empty path segment".to_owned(),
                ));
            }
            validate_env_optional(config.token_env.as_deref(), "token_env")
                .map_err(|error| invalid(error.message().to_owned()))?;
            validate_namespace(config.namespace.as_deref())
                .map_err(|error| invalid(error.message().to_owned()))?;
        }
        ProviderConfig::Keepass(config) => {
            if config.database.as_os_str().is_empty() {
                return Err(invalid("database must not be empty".to_owned()));
            }
            if config.command.trim().is_empty() {
                return Err(invalid("command must not be empty".to_owned()));
            }
            validate_env_optional(config.password_env.as_deref(), "password_env")
                .map_err(|error| invalid(error.message().to_owned()))?;
        }
        ProviderConfig::Infisical(config) => {
            validate_http_base(&config.address, config.allow_http_loopback)
                .map_err(|error| invalid(error.message().to_owned()))?;
            if config.project_id.is_empty() {
                return Err(invalid("project_id must not be empty".to_owned()));
            }
            if config.environment.is_empty() {
                return Err(invalid("environment must not be empty".to_owned()));
            }
            if !config.path.starts_with('/') {
                return Err(invalid("path must start with '/'".to_owned()));
            }
            validate_env_optional(config.token_env.as_deref(), "token_env")
                .map_err(|error| invalid(error.message().to_owned()))?;
            validate_env_optional(config.client_id_env.as_deref(), "client_id_env")
                .map_err(|error| invalid(error.message().to_owned()))?;
            validate_env_optional(config.client_secret_env.as_deref(), "client_secret_env")
                .map_err(|error| invalid(error.message().to_owned()))?;
            if config.client_id_env.is_some() != config.client_secret_env.is_some() {
                return Err(invalid(
                    "client_id_env and client_secret_env must be set together".to_owned(),
                ));
            }
        }
        ProviderConfig::Vaultwarden(config) => {
            if config.command.trim().is_empty() {
                return Err(invalid("command must not be empty".to_owned()));
            }
            validate_env_optional(config.session_env.as_deref(), "session_env")
                .map_err(|error| invalid(error.message().to_owned()))?;
        }
        ProviderConfig::Proton(config) => {
            if config.command.trim().is_empty() {
                return Err(invalid("command must not be empty".to_owned()));
            }
            validate_env_optional(config.token_env.as_deref(), "token_env")
                .map_err(|error| invalid(error.message().to_owned()))?;
        }
        ProviderConfig::Github(config) => {
            validate_http_base(&config.api_url, false)
                .map_err(|error| invalid(error.message().to_owned()))?;
            if !valid_github_component(&config.owner) || !valid_github_component(&config.repo) {
                return Err(invalid(
                    "owner and repo must contain only letters, digits, '.', '_' and '-'".to_owned(),
                ));
            }
            validate_env_optional(config.token_env.as_deref(), "token_env")
                .map_err(|error| invalid(error.message().to_owned()))?;
        }
        ProviderConfig::AwsSecretsManager(config) => {
            if !valid_aws_region(&config.region) {
                return Err(invalid(
                    "region must contain only lowercase letters, digits, and '-'".to_owned(),
                ));
            }
            if let Some(endpoint) = &config.endpoint {
                validate_http_base(endpoint, config.allow_http_loopback)
                    .map_err(|error| invalid(error.message().to_owned()))?;
            }
            for (value, field) in [
                (config.access_key_env.as_deref(), "access_key_env"),
                (config.secret_key_env.as_deref(), "secret_key_env"),
                (config.session_token_env.as_deref(), "session_token_env"),
            ] {
                validate_env_optional(value, field)
                    .map_err(|error| invalid(error.message().to_owned()))?;
            }
        }
        ProviderConfig::GcpSecretManager(config) => {
            validate_http_base(&config.endpoint, config.allow_http_loopback)
                .map_err(|error| invalid(error.message().to_owned()))?;
            if !valid_gcp_project(&config.project) {
                return Err(invalid(
                    "project must contain only letters, digits, '_' and '-'".to_owned(),
                ));
            }
            validate_env_optional(config.token_env.as_deref(), "token_env")
                .map_err(|error| invalid(error.message().to_owned()))?;
            if config.allow_anonymous {
                let endpoint = url::Url::parse(&config.endpoint)
                    .map_err(|_| invalid("endpoint is not a valid URL".to_owned()))?;
                if !is_loopback_url(&endpoint) {
                    return Err(invalid(
                        "allow_anonymous is accepted only for a loopback endpoint".to_owned(),
                    ));
                }
            }
        }
        ProviderConfig::AzureKeyVault(config) => {
            validate_http_base(&config.vault_url, config.allow_http_loopback)
                .map_err(|error| invalid(error.message().to_owned()))?;
            if !valid_api_version(&config.api_version) {
                return Err(invalid(
                    "api_version must contain only digits and '.'".to_owned(),
                ));
            }
            validate_env_optional(config.token_env.as_deref(), "token_env")
                .map_err(|error| invalid(error.message().to_owned()))?;
        }
    }
    Ok(())
}

pub(crate) fn valid_aws_region(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

pub(crate) fn valid_gcp_project(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

pub(crate) fn valid_api_version(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 20
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || byte == b'.')
}

fn is_profile_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-' || byte == b'_'
        })
}

fn valid_github_component(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 100
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn validate_env_optional(value: Option<&str>, field: &str) -> Result<()> {
    if let Some(value) = value
        && (value.is_empty()
            || value.len() > 128
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_'))
    {
        return Err(Error::new(format!(
            "{field} must be a non-empty environment variable name"
        )));
    }
    Ok(())
}

fn validate_namespace(value: Option<&str>) -> Result<()> {
    if let Some(value) = value
        && (value.is_empty() || value.len() > 512 || value.bytes().any(|byte| byte < 0x20))
    {
        return Err(Error::new("namespace is invalid"));
    }
    Ok(())
}

pub(crate) fn validate_http_base(value: &str, allow_loopback: bool) -> Result<()> {
    let url = url::Url::parse(value).map_err(|_| Error::new("invalid URL"))?;
    if !url.username().is_empty() || url.password().is_some() {
        return Err(Error::new("URL must not contain credentials"));
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err(Error::new("URL must not contain a query or fragment"));
    }
    match url.scheme() {
        "https" => {}
        "http" if allow_loopback && is_loopback_url(&url) => {}
        "http" => {
            return Err(Error::new(
                "plaintext HTTP is refused; use HTTPS or explicitly allow loopback HTTP",
            ));
        }
        _ => return Err(Error::new("URL must use HTTPS")),
    }
    Ok(())
}

/// Returns whether a URL points at loopback.
#[must_use]
pub fn is_loopback_url(url: &url::Url) -> bool {
    match url.host() {
        Some(url::Host::Ipv4(address)) => address.is_loopback(),
        Some(url::Host::Ipv6(address)) => address.is_loopback(),
        Some(url::Host::Domain(domain)) => domain.eq_ignore_ascii_case("localhost"),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::{Config, Document, is_loopback_url};

    #[test]
    fn accepts_a_directory_scoped_vault_profile() {
        let document = r#"
version = 1
provider = "vault"
prefix = "apps/prod"

[providers.vault]
kind = "vault"
address = "https://vault.example"
mount = "secret"
token_env = "VAULT_TOKEN"
"#;
        let parsed: Document = toml::from_str(document).expect("document");
        assert_eq!(parsed.provider.as_deref(), Some("vault"));
        assert_eq!(parsed.providers.len(), 1);
    }

    #[test]
    fn rejects_literal_credentials_as_unknown_fields() {
        let document = r#"
version = 1
[providers.gh]
kind = "github"
owner = "neotales"
repo = "example"
token = "not-a-real-token"
"#;
        assert!(toml::from_str::<Document>(document).is_err());
    }

    #[test]
    fn rejects_plaintext_http_outside_loopback() {
        let document = r#"
version = 1
[providers.vault]
kind = "vault"
address = "http://vault.example"
"#;
        let parsed: Document = toml::from_str(document).expect("document");
        let config = Config {
            root: "test".into(),
            document: parsed,
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn loads_yaml_configuration() {
        let path = std::env::temp_dir().join(format!(
            "nvault-config-{}-{}.yaml",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time")
                .as_nanos()
        ));
        std::fs::write(
            &path,
            r#"version: 1
provider: v
providers:
  v:
    kind: vault
    address: https://vault.example
    mount: secret
    token_env: VAULT_TOKEN
"#,
        )
        .expect("write yaml");
        let config = Config::load(&path).expect("yaml config");
        assert_eq!(config.document.provider.as_deref(), Some("v"));
        std::fs::remove_file(path).expect("remove yaml");
    }

    #[test]
    fn accepts_cloud_profiles_for_loopback_emulators() {
        let document = r#"
version = 1
provider = "aws"

[providers.aws]
kind = "aws-secrets-manager"
region = "us-east-1"
endpoint = "http://127.0.0.1:4566"
access_key_env = "TEST_AWS_ACCESS_KEY_ID"
secret_key_env = "TEST_AWS_SECRET_ACCESS_KEY"
allow_http_loopback = true

[providers.gcp]
kind = "gcp-secret-manager"
project = "floci-local"
endpoint = "http://127.0.0.1:4588"
allow_anonymous = true
allow_http_loopback = true

[providers.azure]
kind = "azure-key-vault"
vault_url = "http://127.0.0.1:4577/devstoreaccount1-keyvault"
token_env = "TEST_AZURE_ACCESS_TOKEN"
allow_http_loopback = true
"#;
        let parsed: Document = toml::from_str(document).expect("document");
        let config = Config {
            root: "test".into(),
            document: parsed,
        };
        config.validate().expect("cloud profiles");
    }

    #[test]
    fn gcp_anonymous_is_refused_outside_loopback() {
        let document = r#"
version = 1
[providers.gcp]
kind = "gcp-secret-manager"
project = "example"
endpoint = "https://secretmanager.googleapis.com"
allow_anonymous = true
"#;
        let parsed: Document = toml::from_str(document).expect("document");
        let config = Config {
            root: "test".into(),
            document: parsed,
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn cloud_endpoints_refuse_plaintext_http_outside_loopback() {
        for body in [
            "kind = \"aws-secrets-manager\"\nregion = \"us-east-1\"\nendpoint = \"http://secrets.example\"",
            "kind = \"gcp-secret-manager\"\nproject = \"example\"\nendpoint = \"http://secretmanager.example\"",
            "kind = \"azure-key-vault\"\nvault_url = \"http://vault.example\"",
        ] {
            let document = format!("version = 1\n[providers.p]\n{body}\n");
            let parsed: Document = toml::from_str(&document).expect("document");
            let config = Config {
                root: "test".into(),
                document: parsed,
            };
            assert!(config.validate().is_err(), "accepted {body}");
        }
    }

    #[test]
    fn azure_api_version_rejects_query_injection() {
        let document = r#"
version = 1
[providers.az]
kind = "azure-key-vault"
vault_url = "https://vault.example"
api_version = "7.4&x=y"
"#;
        let parsed: Document = toml::from_str(document).expect("document");
        let config = Config {
            root: "test".into(),
            document: parsed,
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn loopback_detection_matches_localhost_and_addresses() {
        assert!(is_loopback_url(
            &url::Url::parse("http://127.0.0.1:8200").unwrap()
        ));
        assert!(is_loopback_url(
            &url::Url::parse("http://[::1]:8200").unwrap()
        ));
        assert!(is_loopback_url(
            &url::Url::parse("http://LOCALHOST:8200").unwrap()
        ));
        assert!(!is_loopback_url(
            &url::Url::parse("http://10.0.0.1:8200").unwrap()
        ));
    }
}
