//! Google Cloud Secret Manager provider.
//!
//! The adapter uses the v1 REST API. It accepts a static OAuth 2.0 access
//! token from an environment variable or owner-only file; it does not perform
//! the service-account JWT exchange, Application Default Credentials, or token
//! refresh. Anonymous requests are accepted only for a loopback emulator and
//! must be opted into with `allow_anonymous`.

use std::path::Path;

use base64::Engine;
use serde::Deserialize;
use serde_json::json;

use crate::config::GcpSecretManagerConfig;
use crate::error::{Error, Result};
use crate::key::Key;
use crate::provider::{Capabilities, HttpClient, HttpResponse, ListedKey, Provider, endpoint};
use crate::secret::Secret;

/// Maximum pages followed for one listing.
const MAX_PAGES: usize = 100;

/// Maximum keys returned by one listing.
const MAX_LISTED: usize = 10_000;

/// Product family used in the same-user write-lock identity.
const LOCK_KIND: &str = "gcp-secret-manager";

/// Google Cloud Secret Manager provider.
#[derive(Debug)]
pub struct GcpSecretManagerProvider {
    name: String,
    base: url::Url,
    project: String,
    token: Option<Secret>,
    client: HttpClient,
}

impl GcpSecretManagerProvider {
    /// Builds a Google Cloud Secret Manager provider.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid endpoint or project, or when a token is
    /// required but not configured.
    pub fn new(name: &str, config: &GcpSecretManagerConfig, root: &Path) -> Result<Self> {
        crate::config::validate_http_base(&config.endpoint, config.allow_http_loopback)
            .map_err(|error| Error::new(format!("GCP endpoint: {}", error.message())))?;
        if !crate::config::valid_gcp_project(&config.project) {
            return Err(Error::new("GCP project is invalid"));
        }
        let base = url::Url::parse(&config.endpoint)
            .map_err(|_| Error::new("GCP endpoint is not a valid URL"))?;
        if config.allow_anonymous && !crate::config::is_loopback_url(&base) {
            return Err(Error::new(
                "GCP allow_anonymous is accepted only for a loopback endpoint",
            ));
        }
        let token = match (&config.token_env, &config.token_file) {
            (Some(variable), _) if std::env::var_os(variable).is_some() => {
                Some(crate::provider::credential_from_env(variable)?)
            }
            (_, Some(path)) => Some(crate::provider::credential_from_file(&root.join(path))?),
            _ if config.allow_anonymous => None,
            (Some(variable), _) => {
                return Err(Error::new(format!(
                    "GCP token is not configured: set {variable}, use token_file, or enable allow_anonymous for a loopback emulator"
                )));
            }
            (None, None) => {
                return Err(Error::new(
                    "GCP token is not configured: set token_env/token_file, or enable allow_anonymous for a loopback emulator",
                ));
            }
        };
        Ok(Self {
            name: name.to_owned(),
            base,
            project: config.project.clone(),
            token,
            client: HttpClient::new(),
        })
    }

    fn request(&self, method: &str, url: &url::Url, body: Option<&[u8]>) -> Result<HttpResponse> {
        match &self.token {
            Some(token) => {
                self.client
                    .request_bearer(method, url, token, &[], "application/json", body)
            }
            None => self
                .client
                .request(method, url, None, &[], "application/json", body),
        }
    }

    fn secrets_url(&self) -> Result<url::Url> {
        endpoint(&self.base, &["v1", "projects", &self.project, "secrets"])
    }

    fn secret_url(&self, name: &str, tail: &[&str]) -> Result<url::Url> {
        let mut segments = vec!["v1", "projects", self.project.as_str(), "secrets", name];
        segments.extend_from_slice(tail);
        endpoint(&self.base, &segments)
    }

    fn add_version(&self, name: &str, value: &[u8]) -> Result<HttpResponse> {
        let action = format!("{name}:addVersion");
        let url = endpoint(
            &self.base,
            &["v1", "projects", &self.project, "secrets", action.as_str()],
        )?;
        let body = json!({
            "payload": {
                "data": base64::engine::general_purpose::STANDARD.encode(value)
            }
        })
        .to_string();
        self.request("POST", &url, Some(body.as_bytes()))
    }

    fn access_url(&self, name: &str) -> Result<url::Url> {
        self.secret_url(name, &["versions", "latest:access"])
    }

    fn create_secret(&self, name: &str) -> Result<HttpResponse> {
        let mut url = self.secrets_url()?;
        url.query_pairs_mut().append_pair("secretId", name);
        let body = json!({ "replication": { "automatic": {} } }).to_string();
        self.request("POST", &url, Some(body.as_bytes()))
    }

    /// Returns the same-user write-lock identity for this endpoint.
    ///
    /// A recognized Google Secret Manager hostname maps to one broad lock for
    /// the service, so endpoint aliases share it. A custom endpoint keeps its
    /// canonical origin. The project is deliberately not an input: a project
    /// id and its numeric project number are two spellings of one project, and
    /// nsvault cannot map one to the other locally. The token, profile name,
    /// and config path are also excluded.
    fn write_identity(&self) -> Result<String> {
        lock_identity(&self.base)
    }
}

impl Provider for GcpSecretManagerProvider {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> &'static str {
        "gcp-secret-manager"
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities {
            read: true,
            write: true,
            list: true,
            // Secret Manager has no create-with-version call. A create that
            // succeeds followed by a failed add-version would leave an empty
            // secret; a retry would then report Present. Do not advertise a
            // create-if-absent path that is not atomic.
            ensure: false,
        }
    }

    fn list(&self, prefix: &str) -> Result<Vec<ListedKey>> {
        let mut keys = Vec::new();
        let mut page_token: Option<String> = None;
        for _ in 0..MAX_PAGES {
            let mut url = self.secrets_url()?;
            url.query_pairs_mut().append_pair("pageSize", "100");
            if let Some(token) = &page_token {
                url.query_pairs_mut().append_pair("pageToken", token);
            }
            let response = self.request("GET", &url, None)?;
            if response.status != 200 {
                return Err(gcp_status_error(&response, "secret list"));
            }
            #[derive(Deserialize)]
            struct Envelope {
                #[serde(default)]
                secrets: Vec<SecretEntry>,
                #[serde(rename = "nextPageToken", default)]
                next_page_token: Option<String>,
            }
            #[derive(Deserialize)]
            struct SecretEntry {
                name: String,
            }
            let envelope: Envelope = HttpClient::json(&response)?;
            for entry in envelope.secrets {
                let Some(name) = secret_name_from_resource(&entry.name, &self.project) else {
                    continue;
                };
                if !valid_secret_name(name) {
                    continue;
                }
                if prefix.is_empty() || name.starts_with(prefix) {
                    keys.push(ListedKey::new(name.to_owned()));
                    if keys.len() >= MAX_LISTED {
                        return Err(Error::new(format!(
                            "GCP Secret Manager listing exceeded {MAX_LISTED} keys"
                        )));
                    }
                }
            }
            match envelope.next_page_token {
                Some(token) if !token.is_empty() => page_token = Some(token),
                _ => return Ok(keys),
            }
        }
        Err(Error::new(
            "GCP Secret Manager listing exceeded the page limit",
        ))
    }

    fn get(&self, raw_key: &str) -> Result<Secret> {
        let key = Key::parse(raw_key)?;
        if key.field().is_some() {
            return Err(Error::new("GCP Secret Manager keys do not have fields"));
        }
        if !valid_secret_name(key.path()) {
            return Err(Error::new(
                "GCP secret names must contain only letters, digits, '-' and '_'",
            ));
        }
        let response = self.request("GET", &self.access_url(key.path())?, None)?;
        if response.status != 200 {
            return Err(gcp_status_error(&response, key.path()));
        }
        #[derive(Deserialize)]
        struct Envelope {
            payload: Option<Payload>,
        }
        #[derive(Deserialize)]
        struct Payload {
            data: String,
        }
        let envelope: Envelope = HttpClient::json(&response)?;
        let payload = envelope.payload.ok_or_else(|| {
            Error::new(format!(
                "GCP Secret Manager response for {:?} has no payload",
                key.path()
            ))
        })?;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(payload.data)
            .map_err(|_| Error::new("GCP returned a payload that is not valid base64"))?;
        Ok(Secret::new(bytes))
    }

    fn set(&self, raw_key: &str, value: &Secret) -> Result<()> {
        let key = Key::parse(raw_key)?;
        if key.field().is_some() {
            return Err(Error::new("GCP Secret Manager keys do not have fields"));
        }
        if !valid_secret_name(key.path()) {
            return Err(Error::new(
                "GCP secret names must contain only letters, digits, '-' and '_'",
            ));
        }
        let _write_lock = crate::provider::lock::acquire(&self.write_identity()?)?;
        let response = self.add_version(key.path(), value.expose())?;
        if matches!(response.status, 200 | 201) {
            return Ok(());
        }
        if response.status == 404 {
            let created = self.create_secret(key.path())?;
            if !matches!(created.status, 200 | 201 | 409) {
                return Err(gcp_status_error(&created, key.path()));
            }
            let retried = self.add_version(key.path(), value.expose())?;
            if matches!(retried.status, 200 | 201) {
                return Ok(());
            }
            return Err(gcp_status_error(&retried, key.path()));
        }
        Err(gcp_status_error(&response, key.path()))
    }
}

/// Builds the write-lock identity from a recognized Google service hostname
/// or, for a custom endpoint, its canonical origin.
///
/// Every recognized Google Secret Manager hostname (`secretmanager.*.googleapis.com`,
/// including the plain host, mTLS, and regional `rep` spellings) maps to one
/// broad lock for the service. The project is not an input, because a project
/// id and its project number name the same project and cannot be mapped
/// locally. A custom endpoint (an emulator, proxy, or arbitrary DNS name)
/// keeps its canonical origin, so two custom names for one vault are not
/// serialized by this mechanism.
fn lock_identity(base: &url::Url) -> Result<String> {
    if is_google_secret_manager_host(base) {
        return Ok(crate::provider::lock::identity(
            LOCK_KIND,
            "google-secret-manager",
            &[],
        ));
    }
    let origin = crate::provider::lock::canonical_origin(base)?;
    Ok(crate::provider::lock::identity(LOCK_KIND, &origin, &[]))
}

/// Returns whether the URL host is a Google Secret Manager service endpoint.
fn is_google_secret_manager_host(base: &url::Url) -> bool {
    let Some(host) = base.host_str() else {
        return false;
    };
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    (host.starts_with("secretmanager.") || host.starts_with("secretmanager-fips."))
        && host.ends_with(".googleapis.com")
}

/// Maps a response status to a fixed message without echoing response fields.
fn gcp_status_error(response: &HttpResponse, key: &str) -> Error {
    match response.status {
        400 => Error::new(format!(
            "GCP Secret Manager rejected the request for {key:?}"
        )),
        401 | 403 => Error::new(format!("GCP Secret Manager denied access to {key:?}")),
        404 => Error::new(format!("GCP Secret Manager has no secret {key:?}")),
        409 => Error::new(format!("GCP Secret Manager already has a secret {key:?}")),
        status => Error::new(format!(
            "GCP Secret Manager returned HTTP {status} for {key:?}"
        )),
    }
}

/// Extracts the secret id from `projects/{project}/secrets/{secret}`.
///
/// The API may return the project number instead of the configured project id,
/// so a numeric project is accepted alongside the configured identifier.
fn secret_name_from_resource<'a>(resource: &'a str, project: &str) -> Option<&'a str> {
    let rest = resource.strip_prefix("projects/")?;
    let (resource_project, secret) = rest.split_once("/secrets/")?;
    if resource_project.is_empty() || secret.is_empty() || secret.contains('/') {
        return None;
    }
    if resource_project != project && !resource_project.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    Some(secret)
}

fn valid_secret_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 255
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::{
        GcpSecretManagerProvider, gcp_status_error, lock_identity, secret_name_from_resource,
        valid_secret_name,
    };
    use crate::config::GcpSecretManagerConfig;
    use crate::provider::{HttpResponse, Provider};
    use crate::secret::Secret;

    fn loopback_config() -> GcpSecretManagerConfig {
        GcpSecretManagerConfig {
            project: "floci-local".to_owned(),
            endpoint: "http://127.0.0.1:4588".to_owned(),
            token_env: None,
            token_file: None,
            allow_anonymous: true,
            allow_http_loopback: true,
        }
    }

    #[test]
    fn accepts_documented_secret_names() {
        assert!(valid_secret_name("apps-prod-db"));
        assert!(valid_secret_name("apps_prod_db"));
        assert!(!valid_secret_name("apps/prod/db"));
        assert!(!valid_secret_name(""));
    }

    #[test]
    fn constructor_revalidates_endpoint_security() {
        let mut config = loopback_config();
        config.endpoint = "http://secretmanager.example".to_owned();
        config.allow_anonymous = false;
        assert!(GcpSecretManagerProvider::new("gcp", &config, Path::new(".")).is_err());

        let mut config = loopback_config();
        config.endpoint = "https://secretmanager.googleapis.com".to_owned();
        config.allow_http_loopback = false;
        assert!(GcpSecretManagerProvider::new("gcp", &config, Path::new(".")).is_err());

        let mut config = loopback_config();
        config.project = "bad/project".to_owned();
        assert!(GcpSecretManagerProvider::new("gcp", &config, Path::new(".")).is_err());
    }

    #[test]
    fn ensure_is_not_advertised_or_attempted() {
        let provider = GcpSecretManagerProvider::new("gcp", &loopback_config(), Path::new("."))
            .expect("loopback provider");
        assert!(!provider.capabilities().ensure);
        let error = provider
            .ensure("app-db", &Secret::new(b"not-a-real-secret".to_vec()))
            .expect_err("ensure must be refused");
        assert!(error.message().contains("does not support ensure"));
    }

    #[test]
    fn accepts_project_numbers_in_resource_names() {
        assert_eq!(
            secret_name_from_resource("projects/floci-local/secrets/app-db", "floci-local"),
            Some("app-db")
        );
        assert_eq!(
            secret_name_from_resource("projects/123456789012/secrets/app-db", "floci-local"),
            Some("app-db")
        );
        assert_eq!(
            secret_name_from_resource("projects/other/secrets/app-db", "floci-local"),
            None
        );
        assert_eq!(
            secret_name_from_resource("projects/123/secrets/app-db/versions/1", "floci-local"),
            None
        );
        assert_eq!(
            secret_name_from_resource("projects//secrets/app-db", "floci-local"),
            None
        );
    }

    #[test]
    fn error_messages_do_not_echo_response_fields() {
        let response = HttpResponse {
            status: 400,
            body: br#"{"error":{"status":"INJECTED_STATUS","message":"INJECTED_MESSAGE"}}"#
                .to_vec(),
        };
        let error = gcp_status_error(&response, "app-db");
        assert!(!error.message().contains("INJECTED"));
        assert!(error.message().contains("HTTP 400") || error.message().contains("rejected"));
    }

    #[test]
    fn write_identity_maps_recognized_gcp_endpoints_to_one_service_lock() {
        let plain = url::Url::parse("https://secretmanager.googleapis.com").expect("plain");
        let mtls = url::Url::parse("https://secretmanager.mtls.googleapis.com").expect("mtls");
        let regional = url::Url::parse("https://secretmanager.us-central1.rep.googleapis.com")
            .expect("regional");
        assert_eq!(
            lock_identity(&plain).expect("plain"),
            lock_identity(&mtls).expect("mtls")
        );
        assert_eq!(
            lock_identity(&plain).expect("plain"),
            lock_identity(&regional).expect("regional")
        );
    }

    #[test]
    fn write_identity_keeps_custom_gcp_endpoints_apart() {
        let endpoint = url::Url::parse("http://127.0.0.1:4588").expect("url");
        let trailing = url::Url::parse("HTTP://127.0.0.1:4588/").expect("url");
        let other = url::Url::parse("http://127.0.0.1:4589").expect("url");
        assert_eq!(
            lock_identity(&endpoint).expect("endpoint"),
            lock_identity(&trailing).expect("trailing")
        );
        assert_ne!(
            lock_identity(&endpoint).expect("endpoint"),
            lock_identity(&other).expect("other endpoint")
        );
        let google = url::Url::parse("https://secretmanager.googleapis.com").expect("google");
        assert_ne!(
            lock_identity(&endpoint).expect("endpoint"),
            lock_identity(&google).expect("google")
        );
    }
}
