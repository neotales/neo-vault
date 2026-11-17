//! HashiCorp Vault and OpenBao KV v2 providers.
//!
//! Both products expose the same documented KV v2 HTTP API and are kept as
//! separate kind labels so a configuration cannot accidentally claim one
//! product while talking to another. This adapter speaks KV v2 only.

use std::collections::BTreeSet;
use std::path::Path;

use serde::Deserialize;
use serde_json::{Value, json};

use crate::config::VaultConfig;
use crate::error::{Error, Result};
use crate::key::Key;
use crate::provider::{
    Capabilities, EnsureStatus, HttpClient, ListedKey, Provider, endpoint, load_credential,
};
use crate::secret::Secret;

/// Vault product label.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VaultFlavor {
    /// HashiCorp Vault.
    Vault,
    /// OpenBao, the open-source Vault-compatible fork.
    OpenBao,
}

impl VaultFlavor {
    const fn kind(self) -> &'static str {
        match self {
            Self::Vault => "vault",
            Self::OpenBao => "openbao",
        }
    }
}

/// KV v2 provider.
#[derive(Debug)]
pub struct VaultProvider {
    name: String,
    flavor: VaultFlavor,
    base: url::Url,
    mount: String,
    token: Secret,
    namespace: Option<String>,
    client: HttpClient,
}

impl VaultProvider {
    /// Builds a provider from validated configuration.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid address, mount, or missing token.
    pub fn new(name: &str, flavor: VaultFlavor, config: &VaultConfig, root: &Path) -> Result<Self> {
        let base = url::Url::parse(&config.address)
            .map_err(|_| Error::new("Vault address is not a valid URL"))?;
        let token = load_credential(
            config.token_env.as_deref(),
            config
                .token_file
                .as_deref()
                .map(|path| root.join(path))
                .as_deref(),
            "Vault token",
        )?;
        Ok(Self {
            name: name.to_owned(),
            flavor,
            base,
            mount: config.mount.clone(),
            token,
            namespace: config.namespace.clone(),
            client: HttpClient::new(),
        })
    }

    fn write_identity(&self) -> Result<String> {
        let origin = crate::provider::lock::canonical_origin(&self.base)?;
        let mount = self.mount.trim().trim_matches('/');
        let namespace = self.namespace.as_deref().unwrap_or("").trim();
        Ok(crate::provider::lock::identity(
            "kv2",
            &origin,
            &[mount, namespace],
        ))
    }

    fn data_url(&self, path: &str) -> Result<url::Url> {
        let segments = split_path(path)?;
        let mut parts = vec!["v1", self.mount.as_str(), "data"];
        parts.extend(segments.iter().map(String::as_str));
        endpoint(&self.base, &parts)
    }

    fn subkeys_url(&self, path: &str) -> Result<url::Url> {
        let segments = split_path(path)?;
        let mut parts = vec!["v1", self.mount.as_str(), "subkeys"];
        parts.extend(segments.iter().map(String::as_str));
        endpoint(&self.base, &parts)
    }

    fn metadata_url(&self, path: &str) -> Result<url::Url> {
        let segments = split_path(path)?;
        let mut parts = vec!["v1", self.mount.as_str(), "metadata"];
        parts.extend(segments.iter().map(String::as_str));
        endpoint(&self.base, &parts)
    }

    fn request(
        &self,
        method: &str,
        url: &url::Url,
        body: Option<&[u8]>,
    ) -> Result<crate::provider::HttpResponse> {
        let headers: Vec<(&str, &str)> = self
            .namespace
            .as_deref()
            .map(|namespace| vec![("X-Vault-Namespace", namespace)])
            .unwrap_or_default();
        let content_type = if method == "PATCH" {
            "application/merge-patch+json"
        } else {
            "application/json"
        };
        self.client.request(
            method,
            url,
            Some(("X-Vault-Token", &self.token)),
            &headers,
            content_type,
            body,
        )
    }

    fn map_status(&self, status: u16, key: &str) -> Result<()> {
        match status {
            200 | 204 => Ok(()),
            401 | 403 => Err(Error::new(format!(
                "{} denied access to {key:?}",
                self.flavor.kind()
            ))),
            404 => Err(Error::new(format!(
                "{} has no key {key:?} (not found)",
                self.flavor.kind()
            ))),
            _ => Err(Error::new(format!(
                "{} returned HTTP {status} for {key:?}",
                self.flavor.kind()
            ))),
        }
    }

    /// Reads KV v2 metadata only. `Ok(None)` is a confirmed 404. Every other
    /// failure is an error, including a body that cannot be parsed.
    fn metadata_version(&self, path: &str) -> Result<Option<u64>> {
        let url = self.metadata_url(path)?;
        let response = self.request("GET", &url, None)?;
        match response.status {
            404 => Ok(None),
            200 => {
                #[derive(Deserialize)]
                struct Envelope {
                    data: Option<Meta>,
                }
                #[derive(Deserialize)]
                struct Meta {
                    #[serde(default)]
                    current_version: u64,
                }
                let envelope: Envelope = HttpClient::json(&response)?;
                Ok(Some(
                    envelope.data.map(|meta| meta.current_version).unwrap_or(0),
                ))
            }
            401 | 403 => Err(Error::new(format!(
                "{} denied access to {path:?}",
                self.flavor.kind()
            ))),
            status => Err(Error::new(format!(
                "{} returned HTTP {status} for metadata {path:?}; not treating that as absence",
                self.flavor.kind()
            ))),
        }
    }

    /// Field names only. Subkeys replaces leaf values with null, so this does
    /// not read a secret value. A 404 here is not absence when metadata exists.
    fn field_present(&self, path: &str, field: &str) -> Result<bool> {
        let url = self.subkeys_url(path)?;
        let response = self.request("GET", &url, None)?;
        match response.status {
            200 => {
                #[derive(Deserialize)]
                struct Envelope {
                    #[serde(default)]
                    subkeys: serde_json::Map<String, Value>,
                }
                let envelope: Envelope = HttpClient::json(&response)?;
                Ok(envelope.subkeys.contains_key(field))
            }
            401 | 403 => Err(Error::new(format!(
                "{} denied access to {path:?}",
                self.flavor.kind()
            ))),
            404 => Err(Error::new(format!(
                "{} has metadata for {path:?} but subkeys are unavailable; refusing to treat that as field absence",
                self.flavor.kind()
            ))),
            status => Err(Error::new(format!(
                "{} returned HTTP {status} for subkeys {path:?}; not treating that as absence",
                self.flavor.kind()
            ))),
        }
    }

    fn create_if_absent(
        &self,
        path: &str,
        field: Option<&str>,
        text: &str,
    ) -> Result<EnsureStatus> {
        let field_name = field.unwrap_or("value");
        let url = self.data_url(path)?;
        let body = json!({
            "data": { field_name: text },
            "options": { "cas": 0 }
        })
        .to_string();
        let response = self.request("POST", &url, Some(body.as_bytes()))?;
        match response.status {
            200 | 204 => Ok(EnsureStatus::Created),
            400 | 409 => self.after_create_conflict(path, field, text),
            401 | 403 => Err(Error::new(format!(
                "{} denied access to {path:?}",
                self.flavor.kind()
            ))),
            status => Err(Error::new(format!(
                "{} returned HTTP {status} creating {path:?}; not treating that as absence",
                self.flavor.kind()
            ))),
        }
    }

    fn after_create_conflict(
        &self,
        path: &str,
        field: Option<&str>,
        text: &str,
    ) -> Result<EnsureStatus> {
        // CAS 0 lost. Do not POST again. A path-level ensure stops here.
        // A field ensure may still add that field with its own CAS.
        match (self.metadata_version(path)?, field) {
            (None, _) => Err(Error::new(format!(
                "{} refused to create {path:?} with CAS 0 and the key is still absent",
                self.flavor.kind()
            ))),
            (Some(_), None) => Ok(EnsureStatus::Present),
            (Some(_), Some(field)) => self.ensure_missing_field(path, field, text),
        }
    }

    fn ensure_missing_field(&self, path: &str, field: &str, text: &str) -> Result<EnsureStatus> {
        if self.field_present(path, field)? {
            return Ok(EnsureStatus::Present);
        }
        let Some(version) = self.metadata_version(path)? else {
            return Err(Error::new(format!(
                "{} key {path:?} disappeared before a conditional field write",
                self.flavor.kind()
            )));
        };
        if version == 0 {
            return Err(Error::new(format!(
                "{} has no current version for {path:?}; refusing an unconditional field write",
                self.flavor.kind()
            )));
        }
        let url = self.data_url(path)?;
        let body = json!({
            "data": { field: text },
            "options": { "cas": version }
        })
        .to_string();
        let response = self.request("PATCH", &url, Some(body.as_bytes()))?;
        match response.status {
            200 | 204 => Ok(EnsureStatus::Created),
            400 | 409 => {
                if self.field_present(path, field)? {
                    Ok(EnsureStatus::Present)
                } else {
                    Err(Error::new(format!(
                        "{} lost a CAS race adding field {field:?} on {path:?} and the field is still absent",
                        self.flavor.kind()
                    )))
                }
            }
            401 | 403 => Err(Error::new(format!(
                "{} denied access to {path:?}",
                self.flavor.kind()
            ))),
            status => Err(Error::new(format!(
                "{} returned HTTP {status} patching {path:?}; the existing secret was not replaced",
                self.flavor.kind()
            ))),
        }
    }

    fn list_recursive(
        &self,
        path: &str,
        depth: usize,
        output: &mut BTreeSet<String>,
    ) -> Result<()> {
        if depth > 16 {
            return Err(Error::new("Vault listing exceeded the depth limit"));
        }
        let mut url = self.metadata_url(path)?;
        url.query_pairs_mut().append_pair("list", "true");
        let response = self.request("GET", &url, None)?;
        if response.status == 404 {
            return Ok(());
        }
        self.map_status(response.status, path)?;
        #[derive(Deserialize)]
        struct Envelope {
            data: Option<Data>,
        }
        #[derive(Deserialize)]
        struct Data {
            #[serde(default)]
            keys: Vec<String>,
        }
        let envelope: Envelope = HttpClient::json(&response)?;
        let keys = envelope.data.map_or_else(Vec::new, |data| data.keys);
        for key in keys {
            if key.ends_with('/') {
                let child = join_path(path, key.trim_end_matches('/'));
                self.list_recursive(&child, depth + 1, output)?;
            } else {
                output.insert(join_path(path, &key));
            }
        }
        Ok(())
    }

    fn read_data(&self, path: &str) -> Result<serde_json::Map<String, Value>> {
        let url = self.data_url(path)?;
        let response = self.request("GET", &url, None)?;
        self.map_status(response.status, path)?;
        #[derive(Deserialize)]
        struct Envelope {
            data: Option<Payload>,
        }
        #[derive(Deserialize)]
        struct Payload {
            data: Option<serde_json::Map<String, Value>>,
        }
        let envelope: Envelope = HttpClient::json(&response)?;
        envelope
            .data
            .and_then(|payload| payload.data)
            .ok_or_else(|| Error::new(format!("Vault response for {path:?} has no data")))
    }
}

impl Provider for VaultProvider {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> &'static str {
        self.flavor.kind()
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
        let normalized = prefix.trim_matches('/');
        let mut keys = BTreeSet::new();
        self.list_recursive(normalized, 0, &mut keys)?;
        Ok(keys.into_iter().map(ListedKey::new).collect())
    }

    fn get(&self, raw_key: &str) -> Result<Secret> {
        let key = Key::parse(raw_key)?;
        let data = self.read_data(key.path())?;
        if let Some(field) = key.field() {
            let value = data.get(field).ok_or_else(|| {
                Error::new(format!("Vault key {:?} has no field {field:?}", key.path()))
            })?;
            return scalar_to_secret(value, key.path(), field);
        }
        if let Some(value) = data.get("value") {
            return scalar_to_secret(value, key.path(), "value");
        }
        if data.len() == 1 {
            let (field, value) = data.iter().next().expect("one field");
            return scalar_to_secret(value, key.path(), field);
        }
        Err(Error::new(format!(
            "Vault key {:?} has multiple fields {}; select one with #field",
            key.path(),
            data.keys()
                .map(String::as_str)
                .collect::<Vec<_>>()
                .join(", ")
        )))
    }

    fn set(&self, raw_key: &str, value: &Secret) -> Result<()> {
        let _write_lock = crate::provider::lock::acquire(&self.write_identity()?)?;
        let key = Key::parse(raw_key)?;
        let text = std::str::from_utf8(value.expose())
            .map_err(|_| Error::new("Vault values must be UTF-8 text"))?;
        let url = self.data_url(key.path())?;
        let body = if let Some(field) = key.field() {
            json!({ "data": { field: text } }).to_string()
        } else {
            json!({ "data": { "value": text } }).to_string()
        };
        // PATCH merges the field into the existing version. A POST would
        // replace the whole secret and silently delete sibling fields, so it is
        // used only to create a path that does not exist yet.
        let response = self.request("PATCH", &url, Some(body.as_bytes()))?;
        if response.status == 404 && key.field().is_none() {
            // CAS 0 means "create only if this path still does not exist".
            // Without it, a concurrent creator could lose its fields to this
            // unconditional overwrite.
            let create = json!({
                "data": { "value": text },
                "options": { "cas": 0 }
            })
            .to_string();
            let response = self.request("POST", &url, Some(create.as_bytes()))?;
            if matches!(response.status, 400 | 409) {
                return Err(Error::new(format!(
                    "Vault refused to create {:?} with CAS 0; the secret may have been created concurrently",
                    key.path()
                )));
            }
            return self.map_status(response.status, key.path());
        }
        self.map_status(response.status, key.path())
    }

    fn ensure(&self, raw_key: &str, value: &Secret) -> Result<EnsureStatus> {
        let _write_lock = crate::provider::lock::acquire(&self.write_identity()?)?;
        let key = Key::parse(raw_key)?;
        let text = std::str::from_utf8(value.expose())
            .map_err(|_| Error::new("Vault values must be UTF-8 text"))?;
        if text.is_empty() {
            return Err(Error::new("refusing to store an empty secret"));
        }
        // A path with no `#field` is the secret itself. Metadata existence is
        // enough; this does not add a missing `value` field to an existing
        // secret, because that would be a write. `#field` uses the subkeys
        // API so the check does not fetch values, then a CAS patch.
        match (self.metadata_version(key.path())?, key.field()) {
            (None, field) => self.create_if_absent(key.path(), field, text),
            (Some(_), None) => Ok(EnsureStatus::Present),
            (Some(_), Some(field)) => self.ensure_missing_field(key.path(), field, text),
        }
    }
}

fn scalar_to_secret(value: &Value, path: &str, field: &str) -> Result<Secret> {
    match value {
        Value::String(text) => Ok(Secret::new(text.as_bytes().to_vec())),
        Value::Bool(flag) => Ok(Secret::new(flag.to_string().into_bytes())),
        Value::Number(number) => Ok(Secret::new(number.to_string().into_bytes())),
        _ => Err(Error::new(format!(
            "Vault field {field:?} on {path:?} is not a scalar"
        ))),
    }
}

fn split_path(path: &str) -> Result<Vec<String>> {
    let trimmed = path.trim_matches('/');
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }
    let mut segments = Vec::new();
    for segment in trimmed.split('/') {
        if segment.is_empty() || segment == "." || segment == ".." {
            return Err(Error::new("invalid Vault path"));
        }
        segments.push(segment.to_owned());
    }
    Ok(segments)
}

fn join_path(base: &str, child: &str) -> String {
    let base = base.trim_matches('/');
    if base.is_empty() {
        child.to_owned()
    } else {
        format!("{base}/{child}")
    }
}

#[cfg(test)]
mod tests {
    use super::{join_path, split_path};

    #[test]
    fn rejects_traversal_paths() {
        assert!(split_path("../secret").is_err());
        assert!(split_path("a//b").is_err());
        assert_eq!(split_path("apps/prod").expect("path").len(), 2);
    }

    #[test]
    fn joins_prefixes_without_double_slashes() {
        assert_eq!(join_path("", "a"), "a");
        assert_eq!(join_path("apps/", "a"), "apps/a");
    }
}
