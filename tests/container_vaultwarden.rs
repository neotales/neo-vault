//! Opt-in, isolated Vaultwarden integration test.
//!
//! Run explicitly:
//!
//! ```sh
//! NVAULT_TEST_BW=/path/to/pinned/bw \
//!   cargo test --test container_vaultwarden -- --ignored --nocapture
//! ```
//!
//! It requires a working Docker daemon and a pinned `bw` CLI on `PATH` or at
//! `NVAULT_TEST_BW`. The image is pinned and the test starts only its own
//! container; testcontainers removes that container on drop. It never touches
//! another container, network, volume, or image.
//!
//! Two independent CLI states (separate `BITWARDENCLI_APPDATA_DIR` values)
//! exercise the shared lock and the sync-before-write behavior: the second
//! state logs in before the item exists, the first creates it, and the second
//! updates a sibling field. The run asserts one item with both fields, not a
//! duplicate. It then uses the second state as an external writer and checks
//! that a change made before a write is preserved (the adapter syncs) while a
//! stale whole-item replay is rejected by the server's revision check. That
//! check is not coordination; nvault does not claim to preserve concurrent
//! external changes.
//!
//! The CLI must accept a plaintext loopback server URL. Packages after
//! `@bitwarden/cli` 2025.6.1 reject any non-HTTPS server URL before sending a
//! request, and `@bitwarden/cli` 2024.9.0 is too old for this Vaultwarden
//! version's item schema. The test therefore pins the CLI through the
//! environment variable rather than guessing at `PATH`.
//!
//! Every account, password, session, and value here is a throwaway fixture for
//! this container. No real account or vault is read or written.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use aes::Aes256;
use base64::Engine;
use cbc::cipher::{BlockEncryptMut, KeyIvInit, block_padding::Pkcs7};
use hmac::{Hmac, Mac};
use nvault::{Client, Secret};
use serde_json::{Value, json};
use sha2::Sha256;
use testcontainers::{
    GenericImage, ImageExt,
    core::{IntoContainerPort, WaitFor},
    runners::SyncRunner,
};

const EMAIL: &str = "nvault-container-test@example.invalid";
const PASSWORD: &str = "not-a-real-password";
const KDF_ITERATIONS: u32 = 100_000;

fn agent() -> ureq::Agent {
    let config = ureq::Agent::config_builder()
        .http_status_as_error(false)
        .max_redirects(0)
        .timeout_global(Some(Duration::from_secs(30)))
        .build();
    ureq::Agent::new_with_config(config)
}

fn post(agent: &ureq::Agent, url: &str, body: &Value) -> (u16, String) {
    let mut response = agent
        .post(url)
        .header("Content-Type", "application/json")
        .send(body.to_string())
        .expect("request to the local container failed");
    let status = response.status().as_u16();
    let text = response.body_mut().read_to_string().unwrap_or_default();
    (status, text)
}

fn get(agent: &ureq::Agent, url: &str) -> u16 {
    agent
        .get(url)
        .call()
        .expect("request to the local container failed")
        .status()
        .as_u16()
}

fn bw_path() -> PathBuf {
    std::env::var_os("NVAULT_TEST_BW")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("bw"))
}

fn run_bw(
    bw: &Path,
    appdata: &Path,
    arguments: &[&str],
    password: Option<&str>,
    session: Option<&str>,
    input: Option<&[u8]>,
) -> std::process::Output {
    let mut command = Command::new(bw);
    command
        .args(arguments)
        .env("BITWARDENCLI_APPDATA_DIR", appdata)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    if let Some(password) = password {
        command.env("BW_PASSWORD", password);
    }
    if let Some(session) = session {
        command.env("BW_SESSION", session);
    }
    if let Some(input) = input {
        let mut child = command
            .stdin(std::process::Stdio::piped())
            .spawn()
            .expect("run the pinned Bitwarden CLI");
        use std::io::Write;
        child
            .stdin
            .take()
            .expect("CLI stdin")
            .write_all(input)
            .expect("write the encoded item");
        child.wait_with_output().expect("wait for the pinned CLI")
    } else {
        command
            .stdin(std::process::Stdio::null())
            .output()
            .expect("run the pinned Bitwarden CLI")
    }
}

fn pbkdf2(password: &[u8], salt: &[u8], iterations: u32) -> [u8; 32] {
    let mut output = [0_u8; 32];
    pbkdf2::pbkdf2_hmac::<Sha256>(password, salt, iterations, &mut output);
    output
}

/// HKDF-Expand with SHA-256, the way the Bitwarden clients stretch a 32-byte
/// master key. `prk` is the master key itself; only the expand step is used.
fn hkdf_expand(prk: &[u8], info: &[u8]) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(prk).expect("HMAC accepts a 32-byte key");
    mac.update(info);
    mac.update(&[1]);
    let output = mac.finalize().into_bytes();
    let mut key = [0_u8; 32];
    key.copy_from_slice(&output);
    key
}

fn random_bytes<const N: usize>() -> [u8; N] {
    let mut bytes = [0_u8; N];
    getrandom::fill(&mut bytes).expect("operating system randomness");
    bytes
}

/// Encodes a 64-byte user key as a Bitwarden type-2 EncString.
fn protected_user_key(enc_key: &[u8; 32], mac_key: &[u8; 32], user_key: &[u8; 64]) -> String {
    let iv = random_bytes::<16>();
    let ciphertext = cbc::Encryptor::<Aes256>::new_from_slices(enc_key, &iv)
        .expect("key and IV lengths")
        .encrypt_padded_vec_mut::<Pkcs7>(user_key);
    let mut mac = Hmac::<Sha256>::new_from_slice(mac_key).expect("HMAC accepts a 32-byte key");
    mac.update(&iv);
    mac.update(&ciphertext);
    let mac = mac.finalize().into_bytes();
    let standard = base64::engine::general_purpose::STANDARD;
    format!(
        "2.{}|{}|{}",
        standard.encode(iv),
        standard.encode(&ciphertext),
        standard.encode(mac)
    )
}

struct Profile {
    appdata: PathBuf,
    session: String,
    config: PathBuf,
}

/// Prepares one independent Bitwarden CLI state (its own data directory).
fn prepare_profile(bw: &Path, directory: &Path, name: &str, base: &str) -> Profile {
    let appdata = directory.join(format!("state-{name}"));
    let configured = run_bw(bw, &appdata, &["config", "server", base], None, None, None);
    assert!(configured.status.success(), "bw config server failed");
    let login = run_bw(
        bw,
        &appdata,
        &["login", EMAIL, "--passwordenv", "BW_PASSWORD", "--raw"],
        Some(PASSWORD),
        None,
        None,
    );
    assert!(
        login.status.success(),
        "bw login failed: {}",
        String::from_utf8_lossy(&login.stderr)
    );
    let login_session = String::from_utf8(login.stdout)
        .expect("login session is UTF-8")
        .trim()
        .to_owned();
    // `login` can return a session while the vault is still locked, and
    // `unlock` can return no session when login already unlocked it. Take
    // whichever non-empty session the CLI produced and verify it is unlocked.
    let unlock = run_bw(
        bw,
        &appdata,
        &["unlock", "--passwordenv", "BW_PASSWORD", "--raw"],
        Some(PASSWORD),
        None,
        None,
    );
    assert!(
        unlock.status.success(),
        "bw unlock failed after login; the session is not usable for writes"
    );
    let unlock_session = String::from_utf8(unlock.stdout)
        .expect("unlock session is UTF-8")
        .trim()
        .to_owned();
    let session = if unlock_session.is_empty() {
        login_session
    } else {
        unlock_session
    };
    assert!(
        !session.is_empty(),
        "bw returned no session after login or unlock"
    );
    let status = run_bw(bw, &appdata, &["status"], None, Some(&session), None);
    assert!(status.status.success(), "bw status failed");
    assert!(
        String::from_utf8_lossy(&status.stdout).contains("\"status\":\"unlocked\""),
        "bw session is not unlocked"
    );

    let session_name = format!("session-{name}");
    let session_file = directory.join(&session_name);
    std::fs::write(&session_file, &session).expect("write session file");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&session_file, std::fs::Permissions::from_mode(0o600))
            .expect("chmod session");
    }

    let wrapper = directory.join(format!("bw-{name}"));
    std::fs::write(
        &wrapper,
        format!(
            "#!/bin/sh\nexport BITWARDENCLI_APPDATA_DIR='{}'\nexec '{}' \"$@\"\n",
            appdata.display(),
            bw.display()
        ),
    )
    .expect("write bw wrapper");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&wrapper, std::fs::Permissions::from_mode(0o700))
            .expect("chmod wrapper");
    }

    let config = directory.join(format!("config-{name}.toml"));
    std::fs::write(
        &config,
        format!(
            r#"version = 1
provider = "vw"
[providers.vw]
kind = "vaultwarden"
command = "{}"
session_file = "{}"
"#,
            wrapper.display(),
            session_name
        ),
    )
    .expect("write config");

    Profile {
        appdata,
        session,
        config,
    }
}

fn bw_item(bw: &Path, profile: &Profile, id_or_name: &str) -> Value {
    let output = run_bw(
        bw,
        &profile.appdata,
        &["get", "item", id_or_name],
        None,
        Some(&profile.session),
        None,
    );
    assert!(output.status.success(), "bw get item failed");
    serde_json::from_slice(&output.stdout).expect("item JSON")
}

fn bw_edit_item(bw: &Path, profile: &Profile, id: &str, item: &Value) -> std::process::Output {
    let encoded = base64::engine::general_purpose::STANDARD.encode(item.to_string());
    run_bw(
        bw,
        &profile.appdata,
        &["edit", "item", id],
        None,
        Some(&profile.session),
        Some(encoded.as_bytes()),
    )
}

fn register_account(agent: &ureq::Agent, base: &str) {
    let (status, token) = post(
        agent,
        &format!("{base}/identity/accounts/register/send-verification-email"),
        &json!({ "email": EMAIL, "name": "nvault container test" }),
    );
    assert_eq!(status, 200, "registration token request failed");
    assert!(!token.is_empty(), "registration token is empty");

    let master_key = pbkdf2(PASSWORD.as_bytes(), EMAIL.as_bytes(), KDF_ITERATIONS);
    let enc_key = hkdf_expand(&master_key, b"enc");
    let mac_key = hkdf_expand(&master_key, b"mac");
    let user_key = random_bytes::<64>();
    let key = protected_user_key(&enc_key, &mac_key, &user_key);
    let password_hash = pbkdf2(&master_key, PASSWORD.as_bytes(), 1);

    let (status, _body) = post(
        agent,
        &format!("{base}/identity/accounts/register/finish"),
        &json!({
            "email": EMAIL,
            "kdf": 0,
            "kdfIterations": KDF_ITERATIONS,
            "key": key,
            "masterPasswordHash": base64::engine::general_purpose::STANDARD.encode(password_hash),
            "masterPasswordHint": null,
            "emailVerificationToken": token.trim(),
        }),
    );
    assert_eq!(status, 200, "registration failed");
}

#[test]
#[ignore = "requires Docker and a pinned bw CLI; opt in with --ignored"]
fn vaultwarden_two_cli_states_preserve_fields() {
    let bw = bw_path();
    let container = GenericImage::new("vaultwarden/server", "1.37.5")
        .with_exposed_port(80.tcp())
        .with_wait_for(WaitFor::message_on_either_std("Rocket has launched"))
        .with_startup_timeout(Duration::from_secs(120))
        .with_env_var("SIGNUPS_ALLOWED", "true")
        .with_env_var("I_REALLY_WANT_VOLATILE_STORAGE", "true")
        .with_env_var("WEB_VAULT_ENABLED", "false")
        .start()
        .expect("start the pinned Vaultwarden testcontainer");
    let port = container
        .get_host_port_ipv4(80.tcp())
        .expect("Vaultwarden host port");
    let base = format!("http://127.0.0.1:{port}");
    let agent = agent();

    let mut delay = Duration::from_millis(50);
    while get(&agent, &format!("{base}/alive")) != 200 {
        std::thread::sleep(delay);
        delay = (delay * 2).min(Duration::from_secs(2));
    }

    let directory = std::env::temp_dir().join(format!(
        "nvault-vaultwarden-container-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time")
            .as_nanos()
    ));
    register_account(&agent, &base);

    // Two independent CLI states for the same account. B logs in before the
    // item exists, so its local copy is missing it until a sync.
    let state_a = prepare_profile(&bw, &directory, "a", &base);
    let state_b = prepare_profile(&bw, &directory, "b", &base);
    let client_a = Client::open(&state_a.config).expect("open the first profile");
    let client_b = Client::open(&state_b.config).expect("open the second profile");

    client_a
        .set(Some("vw"), "DB", &Secret::new(b"initial-value".to_vec()))
        .expect("create a login item from the first state");

    // The adapter syncs under the lock, so B must see A's item and update a
    // sibling field instead of creating a second item.
    client_b
        .set(Some("vw"), "DB#username", &Secret::new(b"alice".to_vec()))
        .expect("update a sibling field from the second state");
    let password = client_b
        .get(Some("vw"), "DB#password")
        .expect("read the password from the second state");
    assert_eq!(password.expose(), b"initial-value");
    let username = client_b
        .get(Some("vw"), "DB#username")
        .expect("read the username from the second state");
    assert_eq!(username.expose(), b"alice");

    let synced = run_bw(
        &bw,
        &state_b.appdata,
        &["sync"],
        None,
        Some(&state_b.session),
        None,
    );
    assert!(synced.status.success(), "bw sync failed");
    let listing = run_bw(
        &bw,
        &state_b.appdata,
        &["list", "items"],
        None,
        Some(&state_b.session),
        None,
    );
    assert!(listing.status.success(), "bw list items failed");
    let items: Vec<Value> = serde_json::from_slice(&listing.stdout).expect("item list");
    assert_eq!(
        items.iter().filter(|item| item["name"] == "DB").count(),
        1,
        "the second state created a duplicate item instead of updating the first"
    );

    client_a
        .set(
            Some("vw"),
            "DB#password",
            &Secret::new(b"replacement-value".to_vec()),
        )
        .expect("replace the password from the first state");
    let password = client_a
        .get(Some("vw"), "DB#password")
        .expect("read the replaced password");
    assert_eq!(password.expose(), b"replacement-value");
    let username = client_a
        .get(Some("vw"), "DB#username")
        .expect("read the sibling username");
    assert_eq!(username.expose(), b"alice");

    client_b
        .set(Some("vw"), "DB#api", &Secret::new(b"api-key".to_vec()))
        .expect("add a custom field from the second state");
    let custom = client_b
        .get(Some("vw"), "DB#api")
        .expect("read the custom field");
    assert_eq!(custom.expose(), b"api-key");
    let password = client_b
        .get(Some("vw"), "DB#password")
        .expect("read the password after the second-state write");
    assert_eq!(password.expose(), b"replacement-value");

    let ensured = client_a.ensure(
        Some("vw"),
        "DB",
        &Secret::new(b"must-not-be-written".to_vec()),
    );
    assert!(ensured.is_err(), "Vaultwarden ensure must stay unsupported");

    // External writer: edit through the second CLI state without the adapter.
    let mut item = bw_item(&bw, &state_b, "DB");
    let id = item["id"].as_str().expect("item id").to_owned();
    item["login"]["password"] = Value::String("external-value".to_owned());
    let external = bw_edit_item(&bw, &state_b, &id, &item);
    assert!(external.status.success(), "external edit failed");

    // The adapter syncs before writing, so it sees the external password and
    // preserves it while replacing another field.
    client_a
        .set(Some("vw"), "DB#notes", &Secret::new(b"note-text".to_vec()))
        .expect("update notes after an external edit");
    let password = client_a
        .get(Some("vw"), "DB#password")
        .expect("read the external password");
    assert_eq!(password.expose(), b"external-value");
    let notes = client_a
        .get(Some("vw"), "DB#notes")
        .expect("read the notes");
    assert_eq!(notes.expose(), b"note-text");

    // Residual window: a change between the sync and the edit is rejected by
    // the server's revision check. Capture the first state's current item,
    // let the second state advance the revision, then replay the stale item
    // directly through the CLI.
    let captured = bw_item(&bw, &state_a, &id);
    let synced = run_bw(
        &bw,
        &state_b.appdata,
        &["sync"],
        None,
        Some(&state_b.session),
        None,
    );
    assert!(synced.status.success(), "bw sync failed");
    let mut current = bw_item(&bw, &state_b, &id);
    current["login"]["password"] = Value::String("external-two".to_owned());
    let external = bw_edit_item(&bw, &state_b, &id, &current);
    assert!(external.status.success(), "second external edit failed");
    let stale = bw_edit_item(&bw, &state_a, &id, &captured);
    assert!(
        !stale.status.success(),
        "the server accepted a whole-item write with a stale revision"
    );

    let synced = run_bw(
        &bw,
        &state_a.appdata,
        &["sync"],
        None,
        Some(&state_a.session),
        None,
    );
    assert!(synced.status.success(), "bw sync failed");
    let password = client_a
        .get(Some("vw"), "DB#password")
        .expect("read the external value after the stale write");
    assert_eq!(password.expose(), b"external-two");

    std::fs::remove_dir_all(directory).expect("remove temp dir");
    // `container` is dropped here; testcontainers removes only this container.
}
