//! Azure Key Vault secrets provider.
//!
//! The adapter uses the Key Vault data-plane REST API. It accepts a static
//! bearer token from an environment variable or owner-only file; it does not
//! perform the Microsoft Entra ID token exchange, managed-identity refresh, or
//! challenge-based authentication some SDKs use. Listing is metadata-only.
//! Key Vault has no conditional create, so `ensure` is not implemented.

use std::path::Path;

use serde::Deserialize;
use serde_json::json;

use crate::config::AzureKeyVaultConfig;
use crate::error::{Error, Result};
use crate::key::Key;
use crate::provider::{
    Capabilities, HttpClient, HttpResponse, ListedKey, Provider, endpoint, load_credential,
};
use crate::secret::Secret;

/// Page size requested from Key Vault.
const PAGE_SIZE: &str = "25";

/// Maximum pages followed for one listing.
const MAX_PAGES: usize = 100;

/// Maximum keys returned by one listing.
const MAX_LISTED: usize = 10_000;

/// Azure Key Vault secrets provider.
#[derive(Debug)]
pub struct AzureKeyVaultProvider {
    name: String,
    base: url::Url,
    api_version: String,
    token: Secret,
    client: HttpClient,
}

impl AzureKeyVaultProvider {
    /// Builds an Azure Key Vault provider.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid vault URL or when the bearer token is
    /// not configured.
    pub fn new(name: &str, config: &AzureKeyVaultConfig, root: &Path) -> Result<Self> {
        crate::config::validate_http_base(&config.vault_url, config.allow_http_loopback).map_err(
            |error| Error::new(format!("Azure Key Vault endpoint: {}", error.message())),
        )?;
        if !crate::config::valid_api_version(&config.api_version) {
            return Err(Error::new("Azure Key Vault api_version is invalid"));
        }
        let base = url::Url::parse(&config.vault_url)
            .map_err(|_| Error::new("Azure Key Vault URL is not valid"))?;
        let token = load_credential(
            config.token_env.as_deref(),
            config
                .token_file
                .as_deref()
                .map(|path| root.join(path))
                .as_deref(),
            "Azure Key Vault token",
        )?;
        Ok(Self {
            name: name.to_owned(),
            base,
            api_version: config.api_version.clone(),
            token,
            client: HttpClient::new(),
        })
    }

    fn request(&self, method: &str, url: &url::Url, body: Option<&[u8]>) -> Result<HttpResponse> {
        self.client
            .request_bearer(method, url, &self.token, &[], "application/json", body)
    }

    fn status_error(&self, response: &HttpResponse, key: &str) -> Error {
        match response.status {
            400 => Error::new(format!("Azure Key Vault rejected the request for {key:?}")),
            401 | 403 => Error::new(format!("Azure Key Vault denied access to {key:?}")),
            404 => Error::new(format!("Azure Key Vault has no secret {key:?}")),
            409 => Error::new(format!("Azure Key Vault conflicted on {key:?}")),
            status => Error::new(format!(
                "Azure Key Vault returned HTTP {status} for {key:?}"
            )),
        }
    }

    fn secrets_url(&self) -> Result<url::Url> {
        let mut url = endpoint(&self.base, &["secrets"])?;
        url.query_pairs_mut()
            .append_pair("api-version", &self.api_version)
            .append_pair("maxresults", PAGE_SIZE);
        Ok(url)
    }

    fn secret_url(&self, name: &str) -> Result<url::Url> {
        let mut url = endpoint(&self.base, &["secrets", name])?;
        url.query_pairs_mut()
            .append_pair("api-version", &self.api_version);
        Ok(url)
    }

    /// Builds the next page from `$skiptoken` without following the provider's
    /// host. A forged or unexpected `nextLink` must not receive the token.
    fn next_page(&self, link: &str) -> Result<url::Url> {
        let parsed = url::Url::parse(link)
            .map_err(|_| Error::new("Azure Key Vault returned an invalid nextLink"))?;
        let mut skiptoken = None;
        for (name, value) in parsed.query_pairs() {
            if name == "$skiptoken" {
                skiptoken = Some(value.into_owned());
            }
        }
        let Some(skiptoken) = skiptoken else {
            return Err(Error::new(
                "Azure Key Vault nextLink has no $skiptoken; refusing to guess a page",
            ));
        };
        let mut url = self.secrets_url()?;
        url.query_pairs_mut().append_pair("$skiptoken", &skiptoken);
        Ok(url)
    }
}

impl Provider for AzureKeyVaultProvider {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> &'static str {
        "azure-key-vault"
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities {
            read: true,
            write: true,
            list: true,
            ensure: false,
        }
    }

    fn list(&self, prefix: &str) -> Result<Vec<ListedKey>> {
        let mut keys = Vec::new();
        let mut url = self.secrets_url()?;
        for _ in 0..MAX_PAGES {
            let response = self.request("GET", &url, None)?;
            if response.status != 200 {
                return Err(self.status_error(&response, "secret list"));
            }
            #[derive(Deserialize)]
            struct Envelope {
                #[serde(default)]
                value: Vec<Item>,
                #[serde(rename = "nextLink", default)]
                next_link: Option<String>,
            }
            #[derive(Deserialize)]
            struct Item {
                id: String,
            }
            let envelope: Envelope = HttpClient::json(&response)?;
            for item in envelope.value {
                let Some(name) = item_name(&item.id) else {
                    continue;
                };
                if (prefix.is_empty() || name.starts_with(prefix)) && valid_secret_name(&name) {
                    keys.push(ListedKey::new(name));
                    if keys.len() >= MAX_LISTED {
                        return Err(Error::new(format!(
                            "Azure Key Vault listing exceeded {MAX_LISTED} keys"
                        )));
                    }
                }
            }
            match envelope.next_link {
                Some(link) if !link.is_empty() => url = self.next_page(&link)?,
                _ => return Ok(keys),
            }
        }
        Err(Error::new(
            "Azure Key Vault listing exceeded the page limit",
        ))
    }

    fn get(&self, raw_key: &str) -> Result<Secret> {
        let key = Key::parse(raw_key)?;
        if key.field().is_some() {
            return Err(Error::new("Azure Key Vault keys do not have fields"));
        }
        if !valid_secret_name(key.path()) {
            return Err(Error::new(
                "Azure Key Vault secret names must contain only letters, digits, and '-'",
            ));
        }
        let response = self.request("GET", &self.secret_url(key.path())?, None)?;
        if response.status != 200 {
            return Err(self.status_error(&response, key.path()));
        }
        #[derive(Deserialize)]
        struct Envelope {
            value: Option<String>,
        }
        let envelope: Envelope = HttpClient::json(&response)?;
        let value = envelope.value.ok_or_else(|| {
            Error::new(format!(
                "Azure Key Vault response for {:?} has no value",
                key.path()
            ))
        })?;
        Ok(Secret::new(value.into_bytes()))
    }

    fn set(&self, raw_key: &str, value: &Secret) -> Result<()> {
        let key = Key::parse(raw_key)?;
        if key.field().is_some() {
            return Err(Error::new("Azure Key Vault keys do not have fields"));
        }
        if !valid_secret_name(key.path()) {
            return Err(Error::new(
                "Azure Key Vault secret names must contain only letters, digits, and '-'",
            ));
        }
        let text = std::str::from_utf8(value.expose())
            .map_err(|_| Error::new("Azure Key Vault values must be UTF-8 text"))?;
        let body = json!({ "value": text }).to_string();
        let response = self.request("PUT", &self.secret_url(key.path())?, Some(body.as_bytes()))?;
        if matches!(response.status, 200 | 201) {
            return Ok(());
        }
        Err(self.status_error(&response, key.path()))
    }
}

fn item_name(id: &str) -> Option<String> {
    let path = match url::Url::parse(id) {
        Ok(url) => url.path().to_owned(),
        Err(_) => id.to_owned(),
    };
    let segments = path
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect::<Vec<_>>();
    let index = segments.iter().position(|segment| *segment == "secrets")?;
    let encoded = segments.get(index + 1)?;
    Some(
        percent_encoding::percent_decode_str(encoded)
            .decode_utf8_lossy()
            .into_owned(),
    )
}

fn valid_secret_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 127
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::{AzureKeyVaultProvider, item_name, valid_secret_name};
    use crate::config::AzureKeyVaultConfig;

    fn config(vault_url: &str) -> AzureKeyVaultConfig {
        AzureKeyVaultConfig {
            vault_url: vault_url.to_owned(),
            api_version: "7.4".to_owned(),
            token_env: None,
            token_file: None,
            allow_http_loopback: false,
        }
    }

    #[test]
    fn constructor_revalidates_endpoint_security() {
        assert!(
            AzureKeyVaultProvider::new("az", &config("http://vault.example"), Path::new("."))
                .is_err()
        );

        let mut invalid_version = config("https://vault.example");
        invalid_version.api_version = "7.4&x=y".to_owned();
        assert!(AzureKeyVaultProvider::new("az", &invalid_version, Path::new(".")).is_err());
    }

    #[test]
    fn extracts_a_name_from_a_vault_id() {
        assert_eq!(
            item_name("https://example.vault.azure.net/secrets/app-db/version"),
            Some("app-db".to_owned())
        );
        assert_eq!(
            item_name("https://example.vault.azure.net/secrets/app-db"),
            Some("app-db".to_owned())
        );
        assert_eq!(item_name("secrets/app%2Ddb"), Some("app-db".to_owned()));
    }

    #[test]
    fn accepts_documented_secret_names() {
        assert!(valid_secret_name("app-db"));
        assert!(!valid_secret_name("app/db"));
        assert!(!valid_secret_name(""));
    }
}
