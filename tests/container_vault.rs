//! Opt-in, isolated Vault integration test.
//!
//! Run explicitly: `cargo test --test container_vault -- --ignored --nocapture`.
//! It requires a working Docker daemon and pulls the pinned image. It starts
//! only its own Vault dev container and lets testcontainers remove that
//! container. It does not touch other containers, networks, volumes, or images.

use std::time::Duration;

use nsvault::{Client, Secret};
use testcontainers::{
    GenericImage, ImageExt,
    core::{IntoContainerPort, WaitFor},
    runners::SyncRunner,
};

#[test]
#[ignore = "requires Docker; opt in with --ignored"]
fn vault_kv_v2_round_trip_preserves_sibling_fields() {
    let token = "nsvault-test-root-token";
    let container = GenericImage::new("hashicorp/vault", "1.21.4")
        .with_exposed_port(8200.tcp())
        .with_wait_for(WaitFor::message_on_stdout("Vault server started!"))
        .with_env_var("VAULT_DEV_ROOT_TOKEN_ID", token)
        .with_cmd(["server", "-dev", "-dev-listen-address=0.0.0.0:8200"])
        .start()
        .expect("start Vault testcontainer");
    let port = container
        .get_host_port_ipv4(8200.tcp())
        .expect("Vault host port");

    let directory = std::env::temp_dir().join(format!(
        "nsvault-vault-container-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time")
            .as_nanos()
    ));
    std::fs::create_dir_all(&directory).expect("temp dir");
    let token_file = directory.join("token");
    std::fs::write(&token_file, token).expect("write token");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&token_file, std::fs::Permissions::from_mode(0o600))
            .expect("chmod token");
    }
    let config = directory.join("config.toml");
    std::fs::write(
        &config,
        format!(
            r#"version = 1
provider = "v"
prefix = "apps/prod"
[providers.v]
kind = "vault"
address = "http://127.0.0.1:{port}"
mount = "secret"
token_file = "token"
allow_http_loopback = true
"#
        ),
    )
    .expect("write config");

    let client = Client::open(&config).expect("open client");
    // Wait until the dev server accepts KV v2 traffic, then verify a replacement
    // write patches `value` rather than deleting a sibling field.
    let mut delay = Duration::from_millis(50);
    loop {
        match client.set(
            Some("v"),
            "apps/prod/db",
            &Secret::new(b"initial-value".to_vec()),
        ) {
            Ok(()) => break,
            Err(_) => {
                std::thread::sleep(delay);
                delay = (delay * 2).min(Duration::from_secs(2));
            }
        }
    }
    client
        .set(
            Some("v"),
            "apps/prod/db#user",
            &Secret::new(b"alice".to_vec()),
        )
        .expect("set sibling");
    client
        .set(
            Some("v"),
            "apps/prod/db",
            &Secret::new(b"replacement-value".to_vec()),
        )
        .expect("replace value");

    let value = client
        .get(Some("v"), "apps/prod/db#value")
        .expect("read value");
    assert_eq!(value.expose(), b"replacement-value");
    let user = client
        .get(Some("v"), "apps/prod/db#user")
        .expect("read sibling");
    assert_eq!(user.expose(), b"alice");

    let created = client
        .ensure(Some("v"), "apps/prod/fresh", &Secret::new(b"once".to_vec()))
        .expect("ensure create");
    assert_eq!(created, nsvault::EnsureStatus::Created);
    let present = client
        .ensure(
            Some("v"),
            "apps/prod/fresh",
            &Secret::new(b"twice".to_vec()),
        )
        .expect("ensure present");
    assert_eq!(present, nsvault::EnsureStatus::Present);
    let fresh = client
        .get(Some("v"), "apps/prod/fresh")
        .expect("read ensured secret");
    assert_eq!(fresh.expose(), b"once");
    let note = client
        .ensure(
            Some("v"),
            "apps/prod/db#note",
            &Secret::new(b"kept".to_vec()),
        )
        .expect("ensure field");
    assert_eq!(note, nsvault::EnsureStatus::Created);
    let user = client
        .get(Some("v"), "apps/prod/db#user")
        .expect("sibling after field ensure");
    assert_eq!(user.expose(), b"alice");

    std::fs::remove_dir_all(directory).expect("remove temp dir");
    // `container` is dropped here; testcontainers removes only this container.
}
