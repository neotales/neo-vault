//! Opt-in integration tests against pinned Floci emulators.
//!
//! Run explicitly:
//! `cargo test --test container_cloud -- --ignored --nocapture`
//!
//! These tests require a working Docker daemon. Each test starts one pinned
//! Emulator container, uses only loopback endpoints and obviously fake
//! credentials, and lets testcontainers remove that container. They never touch
//! another container, network, volume, or image.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use nsvault::{Client, EnsureStatus, Result as NsvaultResult, Secret};
use testcontainers::{
    Container, GenericImage, ImageExt,
    core::{IntoContainerPort, WaitFor},
    runners::SyncRunner,
};

fn temp_dir(label: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "nsvault-cloud-{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time")
            .as_nanos()
    ));
    std::fs::create_dir_all(&path).expect("temp dir");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))
            .expect("private temp dir");
    }
    path
}

fn write_credential(directory: &Path, name: &str, value: &str) {
    let path = directory.join(name);
    std::fs::write(&path, value).expect("write credential fixture");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .expect("credential fixture mode");
    }
}

fn retry<T>(mut operation: impl FnMut() -> NsvaultResult<T>) -> T {
    let start = Instant::now();
    let mut delay = Duration::from_millis(50);
    loop {
        match operation() {
            Ok(value) => return value,
            Err(_) if start.elapsed() < Duration::from_secs(20) => {
                std::thread::sleep(delay);
                delay = (delay * 2).min(Duration::from_secs(1));
            }
            Err(error) => panic!("emulator never became usable: {error}"),
        }
    }
}

/// Starts a pinned Floci image and returns its mapped host port.
fn start_emulator(
    image: &str,
    tag: &str,
    port: u16,
    environment: Option<(&str, &str)>,
) -> (u16, Container<GenericImage>) {
    let image = GenericImage::new(image, tag)
        .with_exposed_port(port.tcp())
        .with_wait_for(WaitFor::seconds(1));
    let container = match environment {
        Some((name, value)) => image.with_env_var(name, value).start(),
        None => image.start(),
    }
    .expect("start Floci emulator");
    let host_port = container
        .get_host_port_ipv4(port.tcp())
        .expect("Floci host port");
    (host_port, container)
}

#[test]
#[ignore = "requires Docker; opt in with --ignored"]
fn aws_secrets_manager_round_trips_through_floci() {
    let (port, _container) = start_emulator("floci/floci", "2.5.0", 4566, None);
    let directory = temp_dir("aws");
    write_credential(&directory, "access-key", "test");
    write_credential(&directory, "secret-key", "test");
    let config = directory.join("config.toml");
    std::fs::write(
        &config,
        format!(
            r#"version = 1
provider = "aws"
[providers.aws]
kind = "aws-secrets-manager"
region = "us-east-1"
endpoint = "http://127.0.0.1:{port}"
access_key_file = "access-key"
secret_key_file = "secret-key"
allow_http_loopback = true
"#
        ),
    )
    .expect("write AWS config");
    let client = Client::open(&config).expect("open AWS client");

    let value = Secret::new(b"not-a-real-secret".to_vec());
    retry(|| client.set(Some("aws"), "nsvault-fixture-aws", &value));
    assert_eq!(
        client
            .get(Some("aws"), "nsvault-fixture-aws")
            .expect("AWS get")
            .expose(),
        value.expose()
    );
    let listed = client
        .list(Some("aws"), "nsvault-fixture")
        .expect("AWS list")
        .into_iter()
        .map(|key| key.key)
        .collect::<Vec<_>>();
    assert!(listed.contains(&"nsvault-fixture-aws".to_owned()));

    let ensured = client
        .ensure(Some("aws"), "nsvault-ensure-aws", &value)
        .expect("AWS ensure create");
    assert_eq!(ensured, EnsureStatus::Created);
    let present = client
        .ensure(
            Some("aws"),
            "nsvault-ensure-aws",
            &Secret::new(b"must-not-win".to_vec()),
        )
        .expect("AWS ensure present");
    assert_eq!(present, EnsureStatus::Present);
    assert_eq!(
        client
            .get(Some("aws"), "nsvault-ensure-aws")
            .expect("AWS ensured get")
            .expose(),
        value.expose()
    );

    std::fs::remove_dir_all(directory).expect("remove AWS temp dir");
}

#[test]
#[ignore = "requires Docker; opt in with --ignored"]
fn gcp_secret_manager_round_trips_through_floci() {
    let (port, _container) = start_emulator("floci/floci-gcp", "0.13.0", 4588, None);
    let directory = temp_dir("gcp");
    let config = directory.join("config.toml");
    std::fs::write(
        &config,
        format!(
            r#"version = 1
provider = "gcp"
[providers.gcp]
kind = "gcp-secret-manager"
project = "floci-local"
endpoint = "http://127.0.0.1:{port}"
allow_anonymous = true
allow_http_loopback = true
"#
        ),
    )
    .expect("write GCP config");
    let client = Client::open(&config).expect("open GCP client");

    let first = Secret::new(b"not-a-real-secret".to_vec());
    retry(|| client.set(Some("gcp"), "nsvault-fixture-gcp", &first));
    assert_eq!(
        client
            .get(Some("gcp"), "nsvault-fixture-gcp")
            .expect("GCP get")
            .expose(),
        first.expose()
    );

    let second = Secret::new(b"not-a-real-secret-either".to_vec());
    client
        .set(Some("gcp"), "nsvault-fixture-gcp", &second)
        .expect("GCP add version");
    assert_eq!(
        client
            .get(Some("gcp"), "nsvault-fixture-gcp")
            .expect("GCP latest get")
            .expose(),
        second.expose()
    );

    let ensured = client
        .ensure(Some("gcp"), "nsvault-ensure-gcp", &first)
        .expect("GCP ensure create");
    assert_eq!(ensured, EnsureStatus::Created);
    let present = client
        .ensure(
            Some("gcp"),
            "nsvault-ensure-gcp",
            &Secret::new(b"must-not-win".to_vec()),
        )
        .expect("GCP ensure present");
    assert_eq!(present, EnsureStatus::Present);
    assert_eq!(
        client
            .get(Some("gcp"), "nsvault-ensure-gcp")
            .expect("GCP ensured get")
            .expose(),
        first.expose()
    );

    let listed = client
        .list(Some("gcp"), "nsvault-fixture")
        .expect("GCP list")
        .into_iter()
        .map(|key| key.key)
        .collect::<Vec<_>>();
    assert!(listed.contains(&"nsvault-fixture-gcp".to_owned()));

    std::fs::remove_dir_all(directory).expect("remove GCP temp dir");
}

#[test]
#[ignore = "requires Docker; opt in with --ignored"]
fn azure_key_vault_round_trips_through_floci() {
    let (port, _container) = start_emulator(
        "floci/floci-az",
        "0.17.0",
        4577,
        Some(("FLOCI_AZ_SERVICES_FUNCTIONS_ENABLED", "false")),
    );
    let directory = temp_dir("azure");
    write_credential(&directory, "token", "floci-fake-token");
    let config = directory.join("config.toml");
    std::fs::write(
        &config,
        format!(
            r#"version = 1
provider = "azure"
[providers.azure]
kind = "azure-key-vault"
vault_url = "http://127.0.0.1:{port}/devstoreaccount1-keyvault"
token_file = "token"
allow_http_loopback = true
"#
        ),
    )
    .expect("write Azure config");
    let client = Client::open(&config).expect("open Azure client");

    let first = Secret::new(b"not-a-real-secret".to_vec());
    retry(|| client.set(Some("azure"), "nsvault-fixture-az", &first));
    assert_eq!(
        client
            .get(Some("azure"), "nsvault-fixture-az")
            .expect("Azure get")
            .expose(),
        first.expose()
    );

    let second = Secret::new(b"not-a-real-secret-either".to_vec());
    client
        .set(Some("azure"), "nsvault-fixture-az", &second)
        .expect("Azure set version");
    assert_eq!(
        client
            .get(Some("azure"), "nsvault-fixture-az")
            .expect("Azure latest get")
            .expose(),
        second.expose()
    );

    let listed = client
        .list(Some("azure"), "nsvault-fixture")
        .expect("Azure list")
        .into_iter()
        .map(|key| key.key)
        .collect::<Vec<_>>();
    assert!(listed.contains(&"nsvault-fixture-az".to_owned()));

    for index in 0..27 {
        let name = format!("nsvault-page-{index:02}");
        client
            .set(
                Some("azure"),
                &name,
                &Secret::new(format!("not-a-real-page-{index}").into_bytes()),
            )
            .expect("Azure paginated set");
    }
    let pages = client
        .list(Some("azure"), "nsvault-page-")
        .expect("Azure paginated list")
        .into_iter()
        .map(|key| key.key)
        .collect::<Vec<_>>();
    assert_eq!(pages.len(), 27, "Azure listing did not follow nextLink");

    let ensure = client.ensure(
        Some("azure"),
        "nsvault-ensure-az",
        &Secret::new(b"must-not-land".to_vec()),
    );
    assert!(ensure.is_err(), "Azure must not claim a race-safe ensure");

    std::fs::remove_dir_all(directory).expect("remove Azure temp dir");
}
