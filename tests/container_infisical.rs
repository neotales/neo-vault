//! Opt-in, isolated Infisical integration test.
//!
//! Run explicitly:
//!
//! ```sh
//! cargo test --test container_infisical -- --ignored --nocapture
//! ```
//!
//! It requires a working Docker daemon and pulls three pinned images. It starts
//! only its own PostgreSQL, Redis, and Infisical containers, using the default
//! bridge and each container's own address; testcontainers removes those
//! containers on drop. It never touches another container, network, volume, or
//! image, and it never performs broad Docker cleanup.
//!
//! The instance is bootstrapped through the documented admin endpoint with
//! obviously fake local credentials. The returned machine token and every
//! secret value exist only inside these throwaway containers and a temporary
//! directory.

use std::time::Duration;

use nsvault::{Client, EnsureStatus, Secret};
use serde_json::{Value, json};
use testcontainers::{
    GenericImage, ImageExt,
    core::{IntoContainerPort, WaitFor},
    runners::SyncRunner,
};

/// Dummy local database password for the fixture containers.
const DB_PASSWORD: &str = "nsvault-test-db-password";
/// Dummy bootstrap password for the fixture administrator.
const ADMIN_PASSWORD: &str = "not-a-real-password";

fn agent() -> ureq::Agent {
    let config = ureq::Agent::config_builder()
        .http_status_as_error(false)
        .max_redirects(0)
        .timeout_global(Some(Duration::from_secs(30)))
        .build();
    ureq::Agent::new_with_config(config)
}

fn post(agent: &ureq::Agent, url: &str, token: Option<&str>, body: &Value) -> (u16, String) {
    let mut request = agent.post(url).header("Content-Type", "application/json");
    if let Some(token) = token {
        request = request.header("Authorization", format!("Bearer {token}"));
    }
    let mut response = request
        .send(body.to_string())
        .expect("request to the local container failed");
    let status = response.status().as_u16();
    let text = response.body_mut().read_to_string().unwrap_or_default();
    (status, text)
}

/// Polls one endpoint, treating a refused or dropped connection as "not ready".
fn status(agent: &ureq::Agent, url: &str) -> Option<u16> {
    agent
        .get(url)
        .call()
        .ok()
        .map(|response| response.status().as_u16())
}

fn wait_for_tcp(address: std::net::SocketAddr, limit: Duration) {
    let started = std::time::Instant::now();
    while std::net::TcpStream::connect_timeout(&address, Duration::from_secs(1)).is_err() {
        assert!(
            started.elapsed() < limit,
            "container did not accept connections in time"
        );
        std::thread::sleep(Duration::from_millis(200));
    }
}

#[test]
#[ignore = "requires Docker; opt in with --ignored"]
fn infisical_reads_writes_and_lists_against_the_pinned_image() {
    let postgres = GenericImage::new("postgres", "17-alpine")
        .with_exposed_port(5432.tcp())
        .with_wait_for(WaitFor::message_on_either_std(
            "database system is ready to accept connections",
        ))
        .with_startup_timeout(Duration::from_secs(120))
        .with_env_var("POSTGRES_USER", "infisical")
        .with_env_var("POSTGRES_PASSWORD", DB_PASSWORD)
        .with_env_var("POSTGRES_DB", "infisical")
        .start()
        .expect("start the pinned PostgreSQL testcontainer");
    let postgres_ip = postgres
        .get_bridge_ip_address()
        .expect("PostgreSQL bridge address");
    wait_for_tcp(
        std::net::SocketAddr::new(postgres_ip, 5432),
        Duration::from_secs(60),
    );

    let redis = GenericImage::new("redis", "7.4-alpine")
        .with_exposed_port(6379.tcp())
        .with_wait_for(WaitFor::message_on_stdout("Ready to accept connections"))
        .with_startup_timeout(Duration::from_secs(120))
        .start()
        .expect("start the pinned Redis testcontainer");
    let redis_ip = redis.get_bridge_ip_address().expect("Redis bridge address");
    wait_for_tcp(
        std::net::SocketAddr::new(redis_ip, 6379),
        Duration::from_secs(60),
    );

    let infisical = GenericImage::new("infisical/infisical", "v0.167.11")
        .with_exposed_port(8080.tcp())
        .with_wait_for(WaitFor::Nothing)
        .with_startup_timeout(Duration::from_secs(600))
        // Fixed dummy values: these must not be reused outside the test.
        .with_env_var("ENCRYPTION_KEY", "00000000000000000000000000000000")
        .with_env_var(
            "AUTH_SECRET",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        )
        .with_env_var(
            "DB_CONNECTION_URI",
            format!(
                "postgres://infisical:{DB_PASSWORD}@{postgres_ip}:5432/infisical?sslmode=disable"
            ),
        )
        .with_env_var("REDIS_URL", format!("redis://{redis_ip}:6379"))
        .with_env_var("SITE_URL", "http://localhost:8080")
        .with_env_var("HOST", "0.0.0.0")
        .with_env_var("NODE_ENV", "production")
        .with_env_var("TELEMETRY_ENABLED", "false")
        .with_env_var("DISABLE_UPDATE_CHECK", "true")
        .start()
        .expect("start the pinned Infisical testcontainer");
    let port = infisical
        .get_host_port_ipv4(8080.tcp())
        .expect("Infisical host port");
    let base = format!("http://127.0.0.1:{port}");
    let http = agent();

    let started = std::time::Instant::now();
    while status(&http, &format!("{base}/api/status")) != Some(200) {
        assert!(
            started.elapsed() < Duration::from_secs(300),
            "Infisical did not become ready in time"
        );
        std::thread::sleep(Duration::from_millis(500));
    }

    let (bootstrap_status, bootstrap_body) = post(
        &http,
        &format!("{base}/api/v1/admin/bootstrap"),
        None,
        &json!({
            "email": "nsvault-container-test@example.invalid",
            "password": ADMIN_PASSWORD,
            "organization": "nsvault container test",
        }),
    );
    assert_eq!(bootstrap_status, 200, "bootstrap failed");
    let bootstrap: Value = serde_json::from_str(&bootstrap_body).expect("bootstrap response shape");
    let token = bootstrap["identity"]["credentials"]["token"]
        .as_str()
        .expect("bootstrap machine token")
        .to_owned();
    let (project_status, project_body) = post(
        &http,
        &format!("{base}/api/v1/projects"),
        Some(&token),
        &json!({
            "projectName": "nsvault container test",
            "projectDescription": "isolated testcontainers fixture",
            "slug": "nsvault-container-test",
            "template": "default",
            "type": "secret-manager",
        }),
    );
    assert_eq!(project_status, 200, "project creation failed");
    let project: Value = serde_json::from_str(&project_body).expect("project response shape");
    let project_id = project["project"]["id"]
        .as_str()
        .expect("project id")
        .to_owned();
    let has_dev = project["project"]["environments"]
        .as_array()
        .is_some_and(|environments| {
            environments
                .iter()
                .any(|environment| environment["slug"] == "dev")
        });
    assert!(has_dev, "the default template has no dev environment");

    let directory = std::env::temp_dir().join(format!(
        "nsvault-infisical-container-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time")
            .as_nanos()
    ));
    std::fs::create_dir_all(&directory).expect("temp dir");
    let token_file = directory.join("token");
    std::fs::write(&token_file, token.as_bytes()).expect("write token file");
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
provider = "i"
[providers.i]
kind = "infisical"
address = "http://127.0.0.1:{port}"
project_id = "{project_id}"
environment = "dev"
path = "/"
token_file = "token"
allow_http_loopback = true
"#
        ),
    )
    .expect("write config");

    let client = Client::open(&config).expect("open client");
    client
        .set(
            Some("i"),
            "NSVAULT_CONTAINER_TEST",
            &Secret::new(b"initial-value".to_vec()),
        )
        .expect("create the secret");
    let initial = client
        .get(Some("i"), "NSVAULT_CONTAINER_TEST")
        .expect("read the secret");
    assert_eq!(initial.expose(), b"initial-value");

    client
        .set(
            Some("i"),
            "NSVAULT_CONTAINER_TEST",
            &Secret::new(b"replacement-value".to_vec()),
        )
        .expect("update the secret");
    let updated = client
        .get(Some("i"), "NSVAULT_CONTAINER_TEST")
        .expect("read the updated secret");
    assert_eq!(updated.expose(), b"replacement-value");

    let listed = client.list(Some("i"), "").expect("list the folder");
    assert!(listed.iter().any(|key| key.key == "NSVAULT_CONTAINER_TEST"));

    // Ensure is an atomic Create request. A sequential duplicate is a 400 and
    // must leave the first value alone.
    let ensured = client
        .ensure(
            Some("i"),
            "NSVAULT_CONTAINER_ENSURE",
            &Secret::new(b"first-ensure-value".to_vec()),
        )
        .expect("ensure creates the secret");
    assert_eq!(ensured, EnsureStatus::Created);
    let ensured_again = client
        .ensure(
            Some("i"),
            "NSVAULT_CONTAINER_ENSURE",
            &Secret::new(b"second-ensure-value".to_vec()),
        )
        .expect("ensure reports the existing secret");
    assert_eq!(ensured_again, EnsureStatus::Present);
    let ensured_value = client
        .get(Some("i"), "NSVAULT_CONTAINER_ENSURE")
        .expect("read the ensured secret");
    assert_eq!(ensured_value.expose(), b"first-ensure-value");

    // Prove the server's Create is an atomic insert rather than an upsert.
    // Run the documented POST concurrently with distinct values: exactly one
    // request may succeed, every loser must fail, and no loser may replace the
    // winner's value.
    let project_query = format!("projectId={project_id}&environment=dev&secretPath=%2F");
    let concurrent_name = "NSVAULT_CONTAINER_CONCURRENT";
    let workers = 8usize;
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(workers));
    let results: Vec<(usize, u16, String)> = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..workers)
            .map(|index| {
                let barrier = std::sync::Arc::clone(&barrier);
                let token = token.clone();
                let project_id = project_id.clone();
                let project_query = project_query.clone();
                let base = base.clone();
                scope.spawn(move || {
                    let thread_agent = agent();
                    barrier.wait();
                    let value = format!("concurrent-value-{index}");
                    let (status, text) = post(
                        &thread_agent,
                        &format!("{base}/api/v4/secrets/{concurrent_name}?{project_query}"),
                        Some(&token),
                        &json!({
                            "projectId": project_id,
                            "environment": "dev",
                            "secretPath": "/",
                            "secretValue": value,
                            "type": "shared",
                            "skipMultilineEncoding": true,
                        }),
                    );
                    (index, status, text)
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|handle| handle.join().expect("concurrent create thread"))
            .collect()
    });
    let statuses: Vec<_> = results
        .iter()
        .map(|(index, status, _)| (index, status))
        .collect();
    println!("concurrent Create statuses: {statuses:?}");
    let mut winners = Vec::new();
    for (index, status, text) in &results {
        if *status == 200 {
            let response: Value =
                serde_json::from_str(text).expect("concurrent create response shape");
            let value = response["secret"]["secretValue"]
                .as_str()
                .expect("concurrent create value")
                .to_owned();
            winners.push((*index, value));
        } else {
            assert!(
                *status >= 400,
                "a losing concurrent create returned {status}"
            );
        }
    }
    assert_eq!(
        winners.len(),
        1,
        "exactly one concurrent Create may succeed: {statuses:?}"
    );
    let (winner_index, winner_value) = &winners[0];
    assert_eq!(*winner_value, format!("concurrent-value-{winner_index}"));
    let concurrent_value = client
        .get(Some("i"), concurrent_name)
        .expect("read the concurrently created secret");
    assert_eq!(
        std::str::from_utf8(concurrent_value.expose()).expect("utf8"),
        winner_value
    );
    let concurrent_listing = client.list(Some("i"), "").expect("list the folder");
    assert_eq!(
        concurrent_listing
            .iter()
            .filter(|key| key.key == concurrent_name)
            .count(),
        1,
        "the unique index must leave exactly one row for the winning create"
    );

    std::fs::remove_dir_all(directory).expect("remove temp dir");
    // The containers are dropped here; testcontainers removes only those.
}
