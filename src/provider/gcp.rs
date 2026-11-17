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
use crate::provider::{
    Capabilities, EnsureStatus, HttpClient, HttpResponse, ListedKey, Provider, endpoint,
};
use crate::secret::Secret;

/// Maximum pages followed for one listing.
const MAX_PAGES: usize = 100;

/// Maximum keys returned by one listing.
const MAX_LISTED: usize = 10_000;

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
        let base = url::Url::parse(&config.endpoint)
            .map_err(|_| Error::new("GCP endpoint is not a valid URL"))?;
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

    fn status_error(&self, response: &HttpResponse, key: &str) -> Error {
        match response.status {
            400 => match gcp_error_status(response).as_deref() {
                Some(kind) => Error::new(format!("GCP Secret Manager returned {kind} for {key:?}")),
                None => Error::new(format!("GCP Secret Manager returned HTTP 400 for {key:?}")),
            },
            401 | 403 => Error::new(format!("GCP Secret Manager denied access to {key:?}")),
            404 => Error::new(format!("GCP Secret Manager has no secret {key:?}")),
            409 => Error::new(format!("GCP Secret Manager already has a secret {key:?}")),
            status => Error::new(format!(
                "GCP Secret Manager returned HTTP {status} for {key:?}"
            )),
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
            ensure: true,
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
                return Err(self.status_error(&response, "secret list"));
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
            let resource_prefix = format!("projects/{}/secrets/", self.project);
            for entry in envelope.secrets {
                let Some(name) = entry.name.strip_prefix(&resource_prefix) else {
                    continue;
                };
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
            return Err(self.status_error(&response, key.path()));
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
        let response = self.add_version(key.path(), value.expose())?;
        if matches!(response.status, 200 | 201) {
            return Ok(());
        }
        if response.status == 404 {
            let created = self.create_secret(key.path())?;
            if !matches!(created.status, 200 | 201 | 409) {
                return Err(self.status_error(&created, key.path()));
            }
            let retried = self.add_version(key.path(), value.expose())?;
            if matches!(retried.status, 200 | 201) {
                return Ok(());
            }
            return Err(self.status_error(&retried, key.path()));
        }
        Err(self.status_error(&response, key.path()))
    }

    fn ensure(&self, raw_key: &str, value: &Secret) -> Result<EnsureStatus> {
        let key = Key::parse(raw_key)?;
        if key.field().is_some() {
            return Err(Error::new("GCP Secret Manager keys do not have fields"));
        }
        if !valid_secret_name(key.path()) {
            return Err(Error::new(
                "GCP secret names must contain only letters, digits, '-' and '_'",
            ));
        }
        let response = self.create_secret(key.path())?;
        if matches!(response.status, 200 | 201) {
            // Secret Manager has no create-with-payload call. If adding the
            // first version fails, report the failure rather than claiming the
            // secret is usable.
            let version = self.add_version(key.path(), value.expose())?;
            if matches!(version.status, 200 | 201) {
                return Ok(EnsureStatus::Created);
            }
            return Err(self.status_error(&version, key.path()));
        }
        if response.status == 409 {
            return Ok(EnsureStatus::Present);
        }
        Err(self.status_error(&response, key.path()))
    }
}

fn gcp_error_status(response: &HttpResponse) -> Option<String> {
    #[derive(Deserialize)]
    struct Envelope {
        error: Option<ErrorBody>,
    }
    #[derive(Deserialize)]
    struct ErrorBody {
        status: Option<String>,
    }
    let envelope: Envelope = serde_json::from_slice(&response.body).ok()?;
    envelope.error?.status
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
    use super::valid_secret_name;

    #[test]
    fn accepts_documented_secret_names() {
        assert!(valid_secret_name("apps-prod-db"));
        assert!(valid_secret_name("apps_prod_db"));
        assert!(!valid_secret_name("apps/prod/db"));
        assert!(!valid_secret_name(""));
    }
}
