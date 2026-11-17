//! Infisical shared-secrets provider.
//!
//! Authentication supports a service token/machine token supplied directly as
//! a bearer token, or Universal Auth client credentials exchanged for a
//! short-lived access token. The adapter uses the documented v4 secrets API and
//! never prints a response body in an error.

use std::path::Path;
use std::sync::Mutex;

use serde::Deserialize;
use serde_json::json;

use crate::config::InfisicalConfig;
use crate::error::{Error, Result};
use crate::key::Key;
use crate::provider::{Capabilities, HttpClient, ListedKey, Provider, endpoint};
use crate::secret::Secret;

/// Infisical provider.
#[derive(Debug)]
pub struct InfisicalProvider {
    name: String,
    base: url::Url,
    project_id: String,
    environment: String,
    path: String,
    direct_token: Option<Secret>,
    client_id_env: Option<String>,
    client_secret_env: Option<String>,
    client: HttpClient,
    machine_token: Mutex<Option<Secret>>,
}

impl InfisicalProvider {
    /// Builds an Infisical provider.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid address or an unreadable direct token.
    pub fn new(name: &str, config: &InfisicalConfig, root: &Path) -> Result<Self> {
        let base = url::Url::parse(&config.address)
            .map_err(|_| Error::new("Infisical address is not a valid URL"))?;
        let direct_token = match (&config.token_env, &config.token_file) {
            (Some(variable), _) if std::env::var_os(variable).is_some() => {
                Some(crate::provider::credential_from_env(variable)?)
            }
            (_, Some(path)) => Some(crate::provider::credential_from_file(&root.join(path))?),
            (Some(_), None) => None,
            (None, None) => None,
        };
        Ok(Self {
            name: name.to_owned(),
            base,
            project_id: config.project_id.clone(),
            environment: config.environment.clone(),
            path: normalize_path(&config.path),
            direct_token,
            client_id_env: config.client_id_env.clone(),
            client_secret_env: config.client_secret_env.clone(),
            client: HttpClient::new(),
            machine_token: Mutex::new(None),
        })
    }

    fn token(&self) -> Result<Secret> {
        if let Some(token) = &self.direct_token {
            return Ok(Secret::new(token.expose().to_vec()));
        }
        let mut cached = self
            .machine_token
            .lock()
            .map_err(|_| Error::new("Infisical token state is unavailable"))?;
        if let Some(token) = cached.as_ref() {
            return Ok(Secret::new(token.expose().to_vec()));
        }
        let client_id = self
            .client_id_env
            .as_deref()
            .map(crate::provider::credential_from_env)
            .transpose()?;
        let client_secret = self
            .client_secret_env
            .as_deref()
            .map(crate::provider::credential_from_env)
            .transpose()?;
        let (Some(client_id), Some(client_secret)) = (client_id, client_secret) else {
            return Err(Error::new(
                "Infisical token is not configured: set token_env/file or Universal Auth client credentials",
            ));
        };
        let client_id = std::str::from_utf8(client_id.expose())
            .map_err(|_| Error::new("Infisical client id is not UTF-8"))?;
        let client_secret = std::str::from_utf8(client_secret.expose())
            .map_err(|_| Error::new("Infisical client secret is not UTF-8"))?;
        let url = endpoint(
            &self.base,
            &["api", "v1", "auth", "universal-auth", "login"],
        )?;
        let body = json!({
            "clientId": client_id,
            "clientSecret": client_secret,
        })
        .to_string();
        let response = self.client.request(
            "POST",
            &url,
            None,
            &[],
            "application/json",
            Some(body.as_bytes()),
        )?;
        if response.status != 200 {
            return Err(Error::new(format!(
                "Infisical authentication failed with HTTP {}",
                response.status
            )));
        }
        #[derive(Deserialize)]
        struct Login {
            #[serde(rename = "accessToken")]
            access_token: String,
        }
        let login: Login = HttpClient::json(&response)?;
        if login.access_token.is_empty() {
            return Err(Error::new("Infisical returned an empty access token"));
        }
        let token = Secret::new(login.access_token.into_bytes());
        *cached = Some(Secret::new(token.expose().to_vec()));
        Ok(token)
    }

    fn secret_url(&self, name: &str) -> Result<url::Url> {
        let mut url = endpoint(&self.base, &["api", "v4", "secrets", name])?;
        url.query_pairs_mut()
            .append_pair("projectId", &self.project_id)
            .append_pair("environment", &self.environment)
            .append_pair("secretPath", &self.path);
        Ok(url)
    }

    fn map_status(&self, status: u16, key: &str) -> Result<()> {
        match status {
            200 | 201 | 204 => Ok(()),
            401 | 403 => Err(Error::new(format!("Infisical denied access to {key:?}"))),
            404 => Err(Error::new(format!("Infisical has no key {key:?}"))),
            _ => Err(Error::new(format!(
                "Infisical returned HTTP {status} for {key:?}"
            ))),
        }
    }
}

impl Provider for InfisicalProvider {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> &'static str {
        "infisical"
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities::READ_WRITE
    }

    fn list(&self, prefix: &str) -> Result<Vec<ListedKey>> {
        let token = self.token()?;
        let mut url = endpoint(&self.base, &["api", "v4", "secrets"])?;
        url.query_pairs_mut()
            .append_pair("projectId", &self.project_id)
            .append_pair("environment", &self.environment)
            .append_pair("secretPath", &self.path)
            .append_pair("viewSecretValue", "false")
            .append_pair("expandSecretReferences", "false")
            .append_pair("recursive", "false")
            .append_pair("includeImports", "false")
            .append_pair("includePersonalOverrides", "false");
        let response = self.client.request(
            "GET",
            &url,
            Some(("Authorization", &token)),
            &[],
            "application/json",
            None,
        )?;
        if response.status == 404 {
            return Ok(Vec::new());
        }
        self.map_status(response.status, prefix)?;
        #[derive(Deserialize)]
        struct Envelope {
            #[serde(default)]
            secrets: Vec<SecretEntry>,
        }
        #[derive(Deserialize)]
        struct SecretEntry {
            #[serde(rename = "secretKey")]
            key: String,
        }
        let envelope: Envelope = HttpClient::json(&response)?;
        let mut keys = Vec::new();
        for entry in envelope.secrets {
            if prefix.is_empty() || entry.key.starts_with(prefix) {
                keys.push(ListedKey::new(entry.key));
            }
        }
        Ok(keys)
    }

    fn get(&self, raw_key: &str) -> Result<Secret> {
        let key = Key::parse(raw_key)?;
        if key.field().is_some() {
            return Err(Error::new(
                "Infisical keys do not have fields; use the secret name directly",
            ));
        }
        let token = self.token()?;
        let url = self.secret_url(key.path())?;
        let response = self.client.request(
            "GET",
            &url,
            Some(("Authorization", &token)),
            &[],
            "application/json",
            None,
        )?;
        self.map_status(response.status, key.path())?;
        #[derive(Deserialize)]
        struct Envelope {
            secret: SecretValue,
        }
        #[derive(Deserialize)]
        struct SecretValue {
            #[serde(rename = "secretValue", default)]
            value: Option<String>,
            #[serde(rename = "secretValueHidden", default)]
            hidden: bool,
        }
        let envelope: Envelope = HttpClient::json(&response)?;
        if envelope.secret.hidden {
            return Err(Error::new(format!(
                "Infisical hid the value for {:?}",
                key.path()
            )));
        }
        let value = envelope.secret.value.ok_or_else(|| {
            Error::new(format!(
                "Infisical response for {:?} has no value",
                key.path()
            ))
        })?;
        Ok(Secret::new(value.into_bytes()))
    }

    fn set(&self, raw_key: &str, value: &Secret) -> Result<()> {
        let key = Key::parse(raw_key)?;
        if key.field().is_some() {
            return Err(Error::new(
                "Infisical keys do not have fields; use the secret name directly",
            ));
        }
        let value = std::str::from_utf8(value.expose())
            .map_err(|_| Error::new("Infisical values must be UTF-8 text"))?;
        let token = self.token()?;
        let url = self.secret_url(key.path())?;
        let body = json!({
            "projectId": &self.project_id,
            "environment": &self.environment,
            "secretPath": &self.path,
            "secretValue": value,
            "type": "shared",
            "skipMultilineEncoding": true,
        })
        .to_string();
        let existing = self.client.request(
            "GET",
            &url,
            Some(("Authorization", &token)),
            &[],
            "application/json",
            None,
        )?;
        let method = if existing.status == 200 {
            "PATCH"
        } else {
            "POST"
        };
        let response = self.client.request(
            method,
            &url,
            Some(("Authorization", &token)),
            &[],
            "application/json",
            Some(body.as_bytes()),
        )?;
        self.map_status(response.status, key.path())
    }
}

fn normalize_path(path: &str) -> String {
    if path.is_empty() || path == "/" {
        "/".to_owned()
    } else if path.starts_with('/') {
        path.trim_end_matches('/').to_owned()
    } else {
        format!("/{}", path.trim_end_matches('/'))
    }
}

#[cfg(test)]
mod tests {
    use super::normalize_path;

    #[test]
    fn normalizes_folder_paths() {
        assert_eq!(normalize_path(""), "/");
        assert_eq!(normalize_path("/"), "/");
        assert_eq!(normalize_path("apps/"), "/apps");
        assert_eq!(normalize_path("/apps/"), "/apps");
    }
}
