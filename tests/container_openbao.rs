//! Opt-in, isolated OpenBao integration test.
//!
//! Run explicitly: `cargo test --test container_openbao -- --ignored --nocapture`.
//! It requires a working Docker daemon and pulls the pinned image. It starts
//! only its own OpenBao dev container and lets testcontainers remove that
//! container. It does not touch other containers, networks, volumes, or images.

use std::time::Duration;

use nvault::{Client, Secret};
use testcontainers::{
    GenericImage, ImageExt,
    core::{IntoContainerPort, WaitFor},
    runners::SyncRunner,
};

#[test]
#[ignore = "requires Docker; opt in with --ignored"]
fn openbao_kv_v2_round_trip_preserves_sibling_fields() {
    let token = "nopenbao-test-root-token";
    let container = GenericImage::new("openbao/openbao", "2.3.1")
        .with_exposed_port(8200.tcp())
        .with_wait_for(WaitFor::message_on_stdout("OpenBao server started!"))
        .with_env_var("BAO_DEV_ROOT_TOKEN_ID", token)
        .with_cmd(["server", "-dev", "-dev-listen-address=0.0.0.0:8200"])
        .start()
        .expect("start OpenBao testcontainer");
    let port = container
        .get_host_port_ipv4(8200.tcp())
        .expect("OpenBao host port");

    let directory = std::env::temp_dir().join(format!(
        "nopenbao-openbao-container-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time")
            .as_nanos()
    ));
    let mut builder = std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(&directory).expect("temp dir");
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
kind = "openbao"
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
    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    loop {
        match client.set(
            Some("v"),
            "apps/prod/db",
            &Secret::new(b"initial-value".to_vec()),
        ) {
            Ok(()) => break,
            Err(error) => {
                assert!(
                    std::time::Instant::now() < deadline,
                    "OpenBao not ready: {error}"
                );
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
    assert_eq!(created, nvault::EnsureStatus::Created);
    let present = client
        .ensure(
            Some("v"),
            "apps/prod/fresh",
            &Secret::new(b"twice".to_vec()),
        )
        .expect("ensure present");
    assert_eq!(present, nvault::EnsureStatus::Present);
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
    assert_eq!(note, nvault::EnsureStatus::Created);
    // A second ensure of the same field must see the real subkeys response and
    // leave the value alone. This is the assertion that would fail if the
    // adapter treated a missing or misplaced subkeys map as absence.
    let note_again = client
        .ensure(
            Some("v"),
            "apps/prod/db#note",
            &Secret::new(b"replaced".to_vec()),
        )
        .expect("ensure existing field");
    assert_eq!(note_again, nvault::EnsureStatus::Present);
    let note_value = client
        .get(Some("v"), "apps/prod/db#note")
        .expect("read existing field");
    assert_eq!(note_value.expose(), b"kept");
    let user = client
        .get(Some("v"), "apps/prod/db#user")
        .expect("sibling after field ensure");
    assert_eq!(user.expose(), b"alice");

    let keys = client.list(Some("v"), "apps/prod").expect("list keys");
    assert!(keys.iter().any(|entry| entry.key == "apps/prod/db"));
    assert!(keys.iter().any(|entry| entry.key == "apps/prod/fresh"));

    // Verify the server actually rejects both create-only and stale-version
    // writes. These direct requests supplement the adapter's ensure checks;
    // they do not claim to induce a race inside ensure itself.
    let agent = ureq::Agent::config_builder()
        .http_status_as_error(false)
        .timeout_global(Some(Duration::from_secs(10)))
        .build()
        .new_agent();
    let url = format!("http://127.0.0.1:{port}/v1/secret/data/apps/prod/db");
    let create = agent
        .post(&url)
        .header("X-Vault-Token", token)
        .header("Content-Type", "application/json")
        .send(r#"{"options":{"cas":0},"data":{"value":"rejected"}}"#)
        .expect("CAS create request");
    assert_eq!(create.status().as_u16(), 400);
    let stale = agent
        .patch(&url)
        .header("X-Vault-Token", token)
        .header("Content-Type", "application/merge-patch+json")
        .send(r#"{"options":{"cas":1},"data":{"user":"rejected"}}"#)
        .expect("stale CAS patch request");
    assert_eq!(stale.status().as_u16(), 400);
    assert_eq!(
        client.get(Some("v"), "apps/prod/db#user").unwrap().expose(),
        b"alice"
    );

    std::fs::remove_dir_all(directory).expect("remove temp dir");
    // `container` is dropped here; testcontainers removes only this container.
}
