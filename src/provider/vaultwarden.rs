//! Vaultwarden/Bitwarden provider backed by the `bw` CLI.
//!
//! The adapter never logs in, unlocks, or changes CLI state; the caller
//! supplies an unlocked session through `BW_SESSION` (or a file). Reads parse
//! the CLI's JSON in memory. A write sends the complete item to the CLI on
//! stdin as encoded JSON, so the value never appears in `argv`, and the CLI's
//! echoed item is discarded rather than printed. Values never echo to an error.
//!
//! A write is a whole-item read-modify-write through the CLI. The CLI sends
//! `lastKnownRevisionDate` from its local copy, and both the Bitwarden server
//! and Vaultwarden reject a stale revision, so an external client's update
//! since that copy fails the write instead of being overwritten. That check is
//! not coordination: the CLI's local copy can be stale until it is synced, a
//! server may not enforce the check, the check tolerates a one-second
//! difference, and an update accepted after this one simply wins later. This
//! adapter does not claim to preserve concurrent external changes.

use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

use base64::Engine;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::config::VaultwardenConfig;
use crate::error::{Error, Result};
use crate::key::Key;
use crate::provider::{Capabilities, ListedKey, Provider, command_available};
use crate::secret::Secret;

/// Maximum bytes accepted for one write.
///
/// The value travels inside a base64 JSON document on the CLI's stdin; the
/// bound keeps that document, and the item the CLI returns, bounded.
const MAX_SET_BYTES: usize = 1024 * 1024;

/// Vaultwarden/Bitwarden provider.
#[derive(Debug)]
pub struct VaultwardenProvider {
    name: String,
    command: String,
    session: Option<Secret>,
}

impl VaultwardenProvider {
    /// Builds a Vaultwarden provider.
    ///
    /// # Errors
    ///
    /// Returns an error when the `bw` executable is unavailable or the session
    /// file cannot be read.
    pub fn new(name: &str, config: &VaultwardenConfig, root: &Path) -> Result<Self> {
        if !command_available(&config.command) && !Path::new(&config.command).is_file() {
            return Err(Error::new(format!(
                "Vaultwarden command {:?} is not available; install the Bitwarden CLI",
                config.command
            )));
        }
        let session = match (&config.session_env, &config.session_file) {
            (Some(variable), _) if std::env::var_os(variable).is_some() => {
                Some(crate::provider::credential_from_env(variable)?)
            }
            (_, Some(path)) => Some(crate::provider::credential_from_file(&root.join(path))?),
            _ => None,
        };
        Ok(Self {
            name: name.to_owned(),
            command: config.command.clone(),
            session,
        })
    }

    fn command(&self, arguments: &[&str]) -> Result<Command> {
        let mut command = Command::new(&self.command);
        command
            .arg("--nointeraction")
            .args(arguments)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if let Some(session) = &self.session {
            command.env(
                "BW_SESSION",
                std::str::from_utf8(session.expose())
                    .map_err(|_| Error::new("Bitwarden session is not valid UTF-8"))?,
            );
        }
        Ok(command)
    }

    fn run(&self, arguments: &[&str]) -> Result<Vec<u8>> {
        let output = self
            .command(arguments)?
            .stdin(Stdio::null())
            .spawn()
            .map_err(|_| Error::new("could not start the Bitwarden CLI"))?
            .wait_with_output()
            .map_err(|_| Error::new("Bitwarden CLI did not finish"))?;
        if !output.status.success() {
            return Err(Error::new(
                "Bitwarden CLI failed; is the vault unlocked and BW_SESSION current?",
            ));
        }
        if output.stdout.len() > 16 * 1024 * 1024 {
            return Err(Error::new("Bitwarden CLI output exceeded the size limit"));
        }
        Ok(output.stdout)
    }

    /// Writes one encoded item to the CLI and discards its response.
    ///
    /// The response echoes the item, including the value, so it is never
    /// captured or logged. Only the exit status is observed.
    fn write(&self, arguments: &[&str], input: &[u8]) -> Result<()> {
        let mut command = self.command(arguments)?;
        command.stdout(Stdio::null()).stderr(Stdio::null());
        let mut child = command
            .stdin(Stdio::piped())
            .spawn()
            .map_err(|_| Error::new("could not start the Bitwarden CLI"))?;
        child
            .stdin
            .take()
            .ok_or_else(|| Error::new("Bitwarden CLI stdin is unavailable"))?
            .write_all(input)
            .map_err(|_| Error::new("Bitwarden CLI did not accept the item"))?;
        let status = child
            .wait()
            .map_err(|_| Error::new("Bitwarden CLI did not finish"))?;
        if !status.success() {
            return Err(Error::new(
                "Bitwarden CLI refused the write; the vault may be locked, the session stale, or the item changed since the last sync",
            ));
        }
        Ok(())
    }

    fn items(&self) -> Result<Vec<Value>> {
        let output = self.run(&["list", "items"])?;
        parse_items(&output)
    }

    fn item(&self, id: &str) -> Result<Value> {
        let output = self.run(&["get", "item", id])?;
        parse_item(&output)
    }

    fn find_item(&self, selector: &str) -> Result<Option<Value>> {
        if is_uuid(selector) {
            return self.item(selector).map(Some);
        }
        let matches: Vec<String> = self
            .items()?
            .into_iter()
            .filter(|item| item.get("name").and_then(Value::as_str) == Some(selector))
            .filter_map(|item| item.get("id").and_then(Value::as_str).map(str::to_owned))
            .collect();
        match matches.len() {
            1 => self.item(&matches[0]).map(Some),
            0 => Ok(None),
            _ => Err(Error::new(format!(
                "Vaultwarden item name {selector:?} is ambiguous; use the item UUID"
            ))),
        }
    }

    fn resolve_item(&self, selector: &str) -> Result<Value> {
        self.find_item(selector)?
            .ok_or_else(|| Error::new(format!("Vaultwarden item {selector:?} was not found")))
    }

    /// Lock identity for Vaultwarden writes.
    ///
    /// The configuration has no server address, and two profiles can name
    /// different wrapper scripts that reach the same vault. A per-executable
    /// identity would let those profiles write concurrently and lose an item
    /// field, so every Vaultwarden write on this machine shares one
    /// conservative lock. It is coarser than the vault, never finer.
    fn write_identity(&self) -> String {
        crate::provider::lock::identity("vaultwarden", "shared", &[])
    }

    fn write_item(&self, id: Option<&str>, item: &Value) -> Result<()> {
        let document = serde_json::to_vec(item)
            .map_err(|_| Error::new("cannot encode the Vaultwarden item"))?;
        let encoded = base64::engine::general_purpose::STANDARD.encode(document);
        match id {
            Some(id) => self.write(&["edit", "item", id], encoded.as_bytes()),
            None => self.write(&["create", "item"], encoded.as_bytes()),
        }
    }
}

impl Provider for VaultwardenProvider {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> &'static str {
        "vaultwarden"
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities::READ_WRITE
    }

    fn list(&self, prefix: &str) -> Result<Vec<ListedKey>> {
        let mut keys = Vec::new();
        for item in self.items()? {
            if let Some(name) = item.get("name").and_then(Value::as_str)
                && (prefix.is_empty() || name.starts_with(prefix))
            {
                keys.push(ListedKey::new(name.to_owned()));
            }
        }
        Ok(keys)
    }

    fn get(&self, raw_key: &str) -> Result<Secret> {
        let key = Key::parse(raw_key)?;
        let selector = key.path();
        let item = self.resolve_item(selector)?;
        let field = key.field();
        let value = match field {
            Some("password") => item
                .pointer("/login/password")
                .and_then(Value::as_str)
                .map(str::to_owned),
            Some("username") => item
                .pointer("/login/username")
                .and_then(Value::as_str)
                .map(str::to_owned),
            Some("notes") => item.get("notes").and_then(Value::as_str).map(str::to_owned),
            Some("name") => item.get("name").and_then(Value::as_str).map(str::to_owned),
            Some("id") => item.get("id").and_then(Value::as_str).map(str::to_owned),
            Some(custom) => custom_field(&item, custom),
            None => default_field(&item),
        };
        value
            .map(|value| Secret::new(value.into_bytes()))
            .ok_or_else(|| {
                Error::new(format!(
                    "Vaultwarden item {selector:?} has no value for field {:?}",
                    field.unwrap_or("password")
                ))
            })
    }

    /// Writes one field by reading the item, changing that field, and sending
    /// the whole item back. Sibling fields are preserved within this call.
    /// Concurrent external clients are not coordinated; the server's revision
    /// check can reject a stale write, but it is not a guarantee.
    fn set(&self, raw_key: &str, value: &Secret) -> Result<()> {
        let _write_lock = crate::provider::lock::acquire(&self.write_identity())?;
        let key = Key::parse(raw_key)?;
        if key.field() == Some("id") {
            return Err(Error::new("Vaultwarden item ids cannot be set"));
        }
        let text = std::str::from_utf8(value.expose())
            .map_err(|_| Error::new("Vaultwarden values must be UTF-8 text"))?;
        if text.is_empty() {
            return Err(Error::new("refusing to store an empty secret"));
        }
        if value.expose().len() > MAX_SET_BYTES {
            return Err(Error::new(format!(
                "Vaultwarden values are limited to {MAX_SET_BYTES} bytes"
            )));
        }
        match self.find_item(key.path())? {
            Some(mut item) => {
                let id = item
                    .get("id")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
                    .ok_or_else(|| Error::new("Bitwarden CLI returned an item without an id"))?;
                apply_field(&mut item, key.field(), text)?;
                self.write_item(Some(&id), &item)
            }
            None => {
                let item = new_item(key.path(), key.field(), text)?;
                self.write_item(None, &item)
            }
        }
    }
}

/// Builds the smallest item that can hold one value under `name`.
///
/// The item is a login by default; `#notes` creates a secure note. A missing
/// item has no name field to change, so `#name` is refused rather than
/// inventing an item named after a secret.
fn new_item(name: &str, field: Option<&str>, text: &str) -> Result<Value> {
    let mut item = json!({
        "type": 1,
        "name": name,
        "notes": "",
        "login": { "username": null, "password": null },
        "fields": [],
    });
    match field {
        None | Some("password") => {
            set_login(&mut item, "password", text)?;
        }
        Some("username") => {
            set_login(&mut item, "username", text)?;
        }
        Some("notes") => {
            item["type"] = Value::from(2);
            set_text(&mut item, "notes", text)?;
            if let Some(object) = item.as_object_mut() {
                object.remove("login");
            }
        }
        Some("name") => {
            return Err(Error::new(
                "Vaultwarden item names come from the key; create the item with another field",
            ));
        }
        Some("id") => return Err(Error::new("Vaultwarden item ids cannot be set")),
        Some(custom) => set_custom_field(&mut item, custom, text)?,
    }
    Ok(item)
}

/// Applies one value to the field a key selects.
///
/// Without a field, a secure note writes `notes` and a login writes
/// `password`; other item types need an explicit field. Unknown field names
/// become custom fields, uppercase and lowercase names matching one entry.
fn apply_field(item: &mut Value, field: Option<&str>, text: &str) -> Result<()> {
    let item_type = item.get("type").and_then(Value::as_u64);
    match field {
        None => {
            if item_type == Some(2) {
                set_text(item, "notes", text)?;
            } else if item_type == Some(1) || item.get("login").is_some() {
                set_login(item, "password", text)?;
            } else {
                return Err(Error::new(
                    "Vaultwarden item has no default field; name one with #field",
                ));
            }
        }
        Some("password") => set_login(item, "password", text)?,
        Some("username") => set_login(item, "username", text)?,
        Some("notes") => set_text(item, "notes", text)?,
        Some("name") => set_text(item, "name", text)?,
        Some("id") => return Err(Error::new("Vaultwarden item ids cannot be set")),
        Some(custom) => set_custom_field(item, custom, text)?,
    }
    Ok(())
}

fn set_login(item: &mut Value, name: &str, text: &str) -> Result<()> {
    if item.get("type").and_then(Value::as_u64) == Some(2) {
        return Err(Error::new(
            "Vaultwarden item is a secure note; #password and #username need a login item",
        ));
    }
    let object = item
        .as_object_mut()
        .ok_or_else(|| Error::new("Bitwarden CLI returned an unexpected item"))?;
    let login = object.entry("login").or_insert_with(|| json!({}));
    let login = login
        .as_object_mut()
        .ok_or_else(|| Error::new("Vaultwarden item has no login object"))?;
    login.insert(name.to_owned(), Value::String(text.to_owned()));
    Ok(())
}

fn set_text(item: &mut Value, name: &str, text: &str) -> Result<()> {
    let object = item
        .as_object_mut()
        .ok_or_else(|| Error::new("Bitwarden CLI returned an unexpected item"))?;
    object.insert(name.to_owned(), Value::String(text.to_owned()));
    Ok(())
}

fn set_custom_field(item: &mut Value, name: &str, text: &str) -> Result<()> {
    let object = item
        .as_object_mut()
        .ok_or_else(|| Error::new("Bitwarden CLI returned an unexpected item"))?;
    let fields = object
        .entry("fields")
        .or_insert_with(|| Value::Array(Vec::new()));
    let fields = fields
        .as_array_mut()
        .ok_or_else(|| Error::new("Vaultwarden item has no field list"))?;
    if let Some(existing) = fields.iter_mut().find(|field| {
        field
            .get("name")
            .and_then(Value::as_str)
            .is_some_and(|candidate| candidate.eq_ignore_ascii_case(name))
    }) {
        let existing = existing
            .as_object_mut()
            .ok_or_else(|| Error::new("Vaultwarden item has an unexpected field entry"))?;
        existing.insert("value".to_owned(), Value::String(text.to_owned()));
        return Ok(());
    }
    fields.push(json!({ "name": name, "value": text, "type": 0 }));
    Ok(())
}

fn parse_items(bytes: &[u8]) -> Result<Vec<Value>> {
    if let Ok(value) = serde_json::from_slice::<Value>(bytes) {
        if let Some(data) = value.get("data")
            && let Some(items) = data.as_array()
        {
            return Ok(items.clone());
        }
        if let Some(items) = value.as_array() {
            return Ok(items.clone());
        }
    }
    Err(Error::new(
        "Bitwarden CLI returned an unexpected item list; is the session valid?",
    ))
}

fn parse_item(bytes: &[u8]) -> Result<Value> {
    #[derive(Deserialize)]
    struct Envelope {
        data: Value,
    }
    if let Ok(envelope) = serde_json::from_slice::<Envelope>(bytes) {
        return Ok(envelope.data);
    }
    serde_json::from_slice(bytes)
        .map_err(|_| Error::new("Bitwarden CLI returned an unexpected item"))
}

fn default_field(item: &Value) -> Option<String> {
    if let Some(password) = item
        .pointer("/login/password")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
    {
        return Some(password.to_owned());
    }
    if item.get("type").and_then(Value::as_u64) == Some(2) {
        return item.get("notes").and_then(Value::as_str).map(str::to_owned);
    }
    None
}

fn custom_field(item: &Value, name: &str) -> Option<String> {
    item.get("fields")
        .and_then(Value::as_array)?
        .iter()
        .find(|field| {
            field
                .get("name")
                .and_then(Value::as_str)
                .is_some_and(|candidate| candidate.eq_ignore_ascii_case(name))
        })
        .and_then(|field| field.get("value"))
        .and_then(Value::as_str)
        .map(str::to_owned)
}

fn is_uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => byte == b'-',
            _ => byte.is_ascii_hexdigit(),
        })
}

#[cfg(test)]
mod tests {
    use super::{apply_field, default_field, is_uuid, new_item, parse_item};
    use serde_json::json;

    #[test]
    fn accepts_uuid_and_rejects_a_name() {
        assert!(is_uuid("123e4567-e89b-12d3-a456-426614174000"));
        assert!(!is_uuid("my item"));
    }

    #[test]
    fn default_login_field_is_the_password() {
        let item = json!({"login":{"password":"value"},"notes":"note"});
        assert_eq!(default_field(&item).as_deref(), Some("value"));
    }

    #[test]
    fn parses_a_response_envelope_without_printing_it() {
        let item = parse_item(br#"{"success":true,"data":{"name":"x"}}"#).expect("item");
        assert_eq!(item["name"], "x");
    }

    #[test]
    fn a_login_field_update_keeps_the_other_fields() {
        let mut item = json!({
            "type": 1,
            "name": "DB",
            "login": {"username": "alice", "password": "old"},
            "fields": [{"name": "api", "value": "key"}],
        });
        apply_field(&mut item, Some("password"), "new").expect("update");
        assert_eq!(item["login"]["password"], "new");
        assert_eq!(item["login"]["username"], "alice");
        assert_eq!(item["fields"][0]["value"], "key");
    }

    #[test]
    fn custom_fields_match_case_insensitively() {
        let mut item =
            json!({"type": 1, "name": "DB", "fields": [{"name": "API", "value": "old"}]});
        apply_field(&mut item, Some("api"), "new").expect("update");
        assert_eq!(item["fields"].as_array().expect("fields").len(), 1);
        assert_eq!(item["fields"][0]["value"], "new");
    }

    #[test]
    fn a_secure_note_refuses_login_fields() {
        let mut item = json!({"type": 2, "name": "Note", "notes": "old"});
        assert!(apply_field(&mut item, Some("password"), "new").is_err());
        apply_field(&mut item, None, "new").expect("default field");
        assert_eq!(item["notes"], "new");
    }

    #[test]
    fn a_new_named_field_is_refused() {
        assert!(new_item("DB", Some("name"), "other").is_err());
        let item = new_item("DB", Some("notes"), "text").expect("secure note");
        assert_eq!(item["type"], 2);
        assert_eq!(item["notes"], "text");
        assert!(item.get("login").is_none());
    }
}
