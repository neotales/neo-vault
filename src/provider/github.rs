//! GitHub Actions repository-secret provider.
//!
//! GitHub never returns a secret value, so reads are explicitly unsupported.
//! Listing returns names only. Writing encrypts the value with the repository's
//! libsodium sealed-box public key, as the REST API requires.

use std::path::Path;

use base64::Engine;
use crypto_box::{PublicKey, aead::rand_core::OsRng};
use serde::Deserialize;
use serde_json::json;

use crate::config::GithubConfig;
use crate::error::{Error, Result, unsupported};
use crate::key::Key;
use crate::provider::{
    Capabilities, EnsureStatus, HttpClient, ListedKey, Provider, endpoint, load_credential,
};
use crate::secret::Secret;

const PER_PAGE: u32 = 100;
const MAX_PAGES: u32 = 100;

/// GitHub Actions repository-secret provider.
#[derive(Debug)]
pub struct GithubProvider {
    name: String,
    base: url::Url,
    owner: String,
    repo: String,
    token: Secret,
    client: HttpClient,
}

impl GithubProvider {
    /// Builds a GitHub provider.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid API URL or missing token.
    pub fn new(name: &str, config: &GithubConfig, root: &Path) -> Result<Self> {
        let base = url::Url::parse(&config.api_url)
            .map_err(|_| Error::new("GitHub API URL is not valid"))?;
        let token = load_credential(
            config.token_env.as_deref(),
            config
                .token_file
                .as_deref()
                .map(|path| root.join(path))
                .as_deref(),
            "GitHub token",
        )?;
        Ok(Self {
            name: name.to_owned(),
            base,
            owner: config.owner.clone(),
            repo: config.repo.clone(),
            token,
            client: HttpClient::new(),
        })
    }

    fn request(
        &self,
        method: &str,
        url: &url::Url,
        body: Option<&[u8]>,
    ) -> Result<crate::provider::HttpResponse> {
        self.client.request(
            method,
            url,
            Some(("Authorization", &self.token)),
            &[],
            "application/json",
            body,
        )
    }

    fn map_status(&self, status: u16, key: &str) -> Result<()> {
        match status {
            200 | 201 | 204 => Ok(()),
            401 | 403 => Err(Error::new(format!("GitHub denied access to {key:?}"))),
            404 => Err(Error::new(format!(
                "GitHub has no repository or secret {key:?}"
            ))),
            422 => Err(Error::new(format!(
                "GitHub rejected the secret name or value for {key:?}"
            ))),
            _ => Err(Error::new(format!(
                "GitHub returned HTTP {status} for {key:?}"
            ))),
        }
    }

    fn secrets_url(&self, page: u32) -> Result<url::Url> {
        let mut url = endpoint(
            &self.base,
            &["repos", &self.owner, &self.repo, "actions", "secrets"],
        )?;
        url.query_pairs_mut()
            .append_pair("per_page", &PER_PAGE.to_string())
            .append_pair("page", &page.to_string());
        Ok(url)
    }

    fn public_key(&self) -> Result<(PublicKey, String)> {
        let url = endpoint(
            &self.base,
            &[
                "repos",
                &self.owner,
                &self.repo,
                "actions",
                "secrets",
                "public-key",
            ],
        )?;
        let response = self.request("GET", &url, None)?;
        self.map_status(response.status, "public key")?;
        #[derive(Deserialize)]
        struct PublicKeyResponse {
            key_id: String,
            key: String,
        }
        let key: PublicKeyResponse = HttpClient::json(&response)?;
        if key.key_id.is_empty() {
            return Err(Error::new("GitHub returned an empty public key id"));
        }
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(key.key.as_bytes())
            .map_err(|_| Error::new("GitHub public key is not valid base64"))?;
        let bytes: [u8; 32] = bytes
            .try_into()
            .map_err(|_| Error::new("GitHub public key has the wrong length"))?;
        Ok((PublicKey::from_bytes(bytes), key.key_id))
    }

    fn write_identity(&self) -> Result<String> {
        let origin = crate::provider::lock::canonical_origin(&self.base)?;
        let owner = self.owner.to_ascii_lowercase();
        let repo = self.repo.to_ascii_lowercase();
        Ok(crate::provider::lock::identity(
            "github-actions",
            &origin,
            &[&owner, &repo],
        ))
    }
}

impl Provider for GithubProvider {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> &'static str {
        "github"
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities {
            read: false,
            write: true,
            list: true,
            ensure: false,
        }
    }

    fn list(&self, prefix: &str) -> Result<Vec<ListedKey>> {
        let mut keys = Vec::new();
        for page in 1..=MAX_PAGES {
            let url = self.secrets_url(page)?;
            let response = self.request("GET", &url, None)?;
            self.map_status(response.status, "secret list")?;
            #[derive(Deserialize)]
            struct Envelope {
                #[serde(default)]
                secrets: Vec<SecretEntry>,
            }
            #[derive(Deserialize)]
            struct SecretEntry {
                name: String,
            }
            let envelope: Envelope = HttpClient::json(&response)?;
            let count = envelope.secrets.len();
            for secret in envelope.secrets {
                if prefix.is_empty() || secret.name.starts_with(prefix) {
                    keys.push(ListedKey::new(secret.name));
                }
            }
            if count < PER_PAGE as usize {
                break;
            }
        }
        Ok(keys)
    }

    fn get(&self, key: &str) -> Result<Secret> {
        let parsed = Key::parse(key)?;
        Err(unsupported(
            &format!(
                "get {:?} (GitHub never returns secret values)",
                parsed.path()
            ),
            &self.name,
        ))
    }

    fn set(&self, raw_key: &str, value: &Secret) -> Result<()> {
        let key = Key::parse(raw_key)?;
        if key.field().is_some() {
            return Err(Error::new("GitHub secret names do not have fields"));
        }
        if !valid_secret_name(key.path()) {
            return Err(Error::new(
                "GitHub secret names must start with a letter or '_' and contain only letters, digits, and '_'",
            ));
        }
        let _write_lock = crate::provider::lock::acquire(&self.write_identity()?)?;
        let (public_key, key_id) = self.public_key()?;
        let encrypted = public_key
            .seal(&mut OsRng, value.expose())
            .map_err(|_| Error::new("could not encrypt the GitHub secret"))?;
        let encrypted_value = base64::engine::general_purpose::STANDARD.encode(encrypted);
        let body = json!({
            "encrypted_value": encrypted_value,
            "key_id": key_id,
        })
        .to_string();
        let url = endpoint(
            &self.base,
            &[
                "repos",
                &self.owner,
                &self.repo,
                "actions",
                "secrets",
                key.path(),
            ],
        )?;
        let response = self.request("PUT", &url, Some(body.as_bytes()))?;
        self.map_status(response.status, key.path())
    }

    fn ensure(&self, _key: &str, _value: &Secret) -> Result<EnsureStatus> {
        // The Actions secrets API exposes one PUT that creates or updates.
        // A list-then-PUT race would overwrite a secret this process cannot
        // read back. There is no create-if-absent or conditional header.
        Err(crate::error::unsupported(
            "ensure (GitHub secret writes are unconditional updates)",
            &self.name,
        ))
    }
}

fn valid_secret_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    (first.is_ascii_alphabetic() || first == b'_')
        && name.len() <= 256
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

#[cfg(test)]
mod tests {
    use super::valid_secret_name;
    use crypto_box::SecretKey;
    use crypto_box::aead::rand_core::OsRng;

    #[test]
    fn sealed_box_round_trips_and_adds_the_expected_overhead() {
        let recipient = SecretKey::generate(&mut OsRng);
        let public = recipient.public_key();
        let sealed = public
            .seal(&mut OsRng, b"secret-value")
            .expect("sealed box");
        assert_eq!(sealed.len(), 32 + 16 + b"secret-value".len());
        let opened = recipient.unseal(&sealed).expect("open sealed box");
        assert_eq!(opened, b"secret-value");
    }

    #[test]
    fn accepts_only_github_secret_names() {
        assert!(valid_secret_name("DEPLOY_TOKEN"));
        assert!(valid_secret_name("_internal"));
        assert!(!valid_secret_name("1TOKEN"));
        assert!(!valid_secret_name("HAS-DASH"));
        assert!(!valid_secret_name(""));
    }
}
