//! Opt-in, isolated Vaultwarden integration test.
//!
//! Run explicitly:
//!
//! ```sh
//! NSVAULT_TEST_BW=/path/to/pinned/bw \
//!   cargo test --test container_vaultwarden -- --ignored --nocapture
//! ```
//!
//! It requires a working Docker daemon and a pinned `bw` CLI on `PATH` or at
//! `NSVAULT_TEST_BW`. The image is pinned and the test starts only its own
//! container; testcontainers removes that container on drop. It never touches
//! another container, network, volume, or image.
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
use nsvault::{Client, Secret};
use serde_json::{Value, json};
use sha2::Sha256;
use testcontainers::{
    GenericImage, ImageExt,
    core::{IntoContainerPort, WaitFor},
    runners::SyncRunner,
};

const EMAIL: &str = "nsvault-container-test@example.invalid";
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
    std::env::var_os("NSVAULT_TEST_BW")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("bw"))
}

fn run_bw(
    bw: &Path,
    appdata: &Path,
    arguments: &[&str],
    password: Option<&str>,
) -> std::process::Output {
    let mut command = Command::new(bw);
    command
        .args(arguments)
        .env("BITWARDENCLI_APPDATA_DIR", appdata)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    if let Some(password) = password {
        command.env("BW_PASSWORD", password);
    }
    command.output().expect("run the pinned Bitwarden CLI")
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

fn register_account(agent: &ureq::Agent, base: &str) {
    let (status, token) = post(
        agent,
        &format!("{base}/identity/accounts/register/send-verification-email"),
        &json!({ "email": EMAIL, "name": "nsvault container test" }),
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
fn vaultwarden_reads_and_writes_through_the_cli() {
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
        "nsvault-vaultwarden-container-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time")
            .as_nanos()
    ));
    let appdata = directory.join("bw-state");
    std::fs::create_dir_all(&appdata).expect("Bitwarden state directory");

    register_account(&agent, &base);
    let configured = run_bw(&bw, &appdata, &["config", "server", &base], None);
    assert!(configured.status.success(), "bw config server failed");
    let login = run_bw(
        &bw,
        &appdata,
        &["login", EMAIL, "--passwordenv", "BW_PASSWORD", "--raw"],
        Some(PASSWORD),
    );
    assert!(
        login.status.success(),
        "bw login failed; pin a CLI that accepts a loopback HTTP server at NSVAULT_TEST_BW"
    );
    // `login` can return a session while the CLI still reports the vault as
    // locked. A write needs the user key, so ask for an explicit unlock.
    let unlock = run_bw(
        &bw,
        &appdata,
        &["unlock", "--passwordenv", "BW_PASSWORD", "--raw"],
        Some(PASSWORD),
    );
    assert!(
        unlock.status.success(),
        "bw unlock failed after login; the session is not usable for writes"
    );
    let session = String::from_utf8(unlock.stdout).expect("session is UTF-8");
    let session = session.trim();
    assert!(!session.is_empty(), "bw unlock returned no session");

    let session_file = directory.join("session");
    std::fs::write(&session_file, session).expect("write session file");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&session_file, std::fs::Permissions::from_mode(0o600))
            .expect("chmod session");
    }

    let wrapper = directory.join("bw");
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

    let config = directory.join("config.toml");
    std::fs::write(
        &config,
        format!(
            r#"version = 1
provider = "vw"
[providers.vw]
kind = "vaultwarden"
command = "{}"
session_file = "session"
"#,
            wrapper.display()
        ),
    )
    .expect("write config");

    let client = Client::open(&config).expect("open client");
    client
        .set(Some("vw"), "DB", &Secret::new(b"initial-value".to_vec()))
        .expect("create a login item");
    client
        .set(Some("vw"), "DB#username", &Secret::new(b"alice".to_vec()))
        .expect("set the username");
    client
        .set(
            Some("vw"),
            "DB#password",
            &Secret::new(b"replacement-value".to_vec()),
        )
        .expect("replace the password");
    client
        .set(Some("vw"), "DB#api", &Secret::new(b"api-key".to_vec()))
        .expect("add a custom field");

    let password = client
        .get(Some("vw"), "DB#password")
        .expect("read password");
    assert_eq!(password.expose(), b"replacement-value");
    let username = client
        .get(Some("vw"), "DB#username")
        .expect("read username");
    assert_eq!(username.expose(), b"alice");
    let custom = client.get(Some("vw"), "DB#api").expect("read custom field");
    assert_eq!(custom.expose(), b"api-key");

    let listed = client.list(Some("vw"), "").expect("list items");
    assert!(listed.iter().any(|key| key.key == "DB"));

    let ensured = client.ensure(
        Some("vw"),
        "DB",
        &Secret::new(b"must-not-be-written".to_vec()),
    );
    assert!(ensured.is_err(), "Vaultwarden ensure must stay unsupported");

    std::fs::remove_dir_all(directory).expect("remove temp dir");
    // `container` is dropped here; testcontainers removes only this container.
}
