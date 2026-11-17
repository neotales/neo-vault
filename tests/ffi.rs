//! Rust-side coverage of the C ABI's ownership and error paths.

#![allow(unsafe_code)]

use std::ffi::{CString, c_char};

use nsvault::ffi::{
    NsvaultBytes, nsvault_bytes_free, nsvault_client_close, nsvault_client_open, nsvault_ensure,
    nsvault_get, nsvault_last_error, nsvault_list, nsvault_set,
};

fn temp_config(contents: &str) -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!(
        "nsvault-ffi-{}-{}.toml",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time")
            .as_nanos()
    ));
    std::fs::write(&path, contents).expect("write config");
    path
}

#[test]
fn ffi_reports_errors_without_panicking() {
    let path = temp_config("version = 1\n");
    let path = CString::new(path.to_string_lossy().as_bytes()).expect("path");
    let mut client = std::ptr::null_mut();
    // SAFETY: the path and output pointers satisfy the documented contract.
    let status = unsafe { nsvault_client_open(path.as_ptr(), &mut client) };
    assert_eq!(status, 0);
    assert!(!client.is_null());

    let mut output = NsvaultBytes::default();
    // SAFETY: the client is live and the output pointer is writable.
    let status = unsafe {
        nsvault_get(
            client,
            std::ptr::null(),
            c"missing".as_ptr() as *const c_char,
            &mut output,
        )
    };
    assert_eq!(status, 1);
    // A provider must be selected before a key can be resolved.
    assert!(output.data.is_null());

    // SAFETY: the output pointer is writable.
    let status = unsafe { nsvault_last_error(&mut output) };
    assert_eq!(status, 1);
    assert!(output.len > 0);
    // SAFETY: output was produced by the library and is freed once.
    unsafe { nsvault_bytes_free(output) };

    // SAFETY: the client was opened once and is closed once.
    unsafe { nsvault_client_close(client) };
}

#[cfg(unix)]
#[test]
fn ffi_null_prefix_uses_the_configured_default() {
    use std::os::unix::fs::PermissionsExt;

    let directory = std::env::temp_dir().join(format!(
        "nsvault-ffi-prefix-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time")
            .as_nanos()
    ));
    std::fs::create_dir_all(&directory).expect("temp dir");
    let script = directory.join("keepassxc-cli");
    std::fs::write(
        &script,
        r#"#!/bin/sh
case "$1" in
  ls) printf '%s\n' 'other/key' 'apps/prod/db' ;;
  *) exit 2 ;;
esac
"#,
    )
    .expect("write fixture");
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700))
        .expect("chmod fixture");
    let password = directory.join("password");
    std::fs::write(&password, b"not-a-real-password").expect("write password");
    std::fs::set_permissions(&password, std::fs::Permissions::from_mode(0o600))
        .expect("chmod password");
    let config = directory.join("config.toml");
    std::fs::write(
        &config,
        format!(
            r#"version = 1
provider = "k"
prefix = "apps/prod"
[providers.k]
kind = "keepass"
database = "test.kdbx"
command = "{}"
password_file = "password"
"#,
            script.display()
        ),
    )
    .expect("write config");

    let config = CString::new(config.to_string_lossy().as_bytes()).expect("config path");
    let mut client = std::ptr::null_mut();
    // SAFETY: the path and output pointers satisfy the documented contract.
    assert_eq!(
        unsafe { nsvault_client_open(config.as_ptr(), &mut client) },
        0
    );

    let mut output = NsvaultBytes::default();
    // SAFETY: the client is live; null prefix means the configured default.
    let status = unsafe { nsvault_list(client, std::ptr::null(), std::ptr::null(), &mut output) };
    assert_eq!(status, 0);
    // SAFETY: the library produced this buffer and the lengths are valid.
    let keys = unsafe { std::slice::from_raw_parts(output.data, output.len) };
    assert_eq!(keys, b"apps/prod/db\n");
    // SAFETY: output is freed exactly once.
    unsafe { nsvault_bytes_free(output) };

    let explicit = CString::new("other").expect("prefix");
    let mut output = NsvaultBytes::default();
    // SAFETY: the client is live and the explicit prefix is NUL-terminated.
    let status = unsafe { nsvault_list(client, std::ptr::null(), explicit.as_ptr(), &mut output) };
    assert_eq!(status, 0);
    // SAFETY: the library produced this buffer and the lengths are valid.
    let keys = unsafe { std::slice::from_raw_parts(output.data, output.len) };
    assert_eq!(keys, b"other/key\n");
    // SAFETY: output is freed exactly once.
    unsafe { nsvault_bytes_free(output) };

    // SAFETY: the client was opened once and is closed once.
    unsafe { nsvault_client_close(client) };
    std::fs::remove_dir_all(directory).expect("remove temp dir");
}
#[cfg(unix)]
#[test]
fn ffi_writes_fail_closed_when_the_lock_directory_is_not_private() {
    use std::os::unix::fs::PermissionsExt;

    let directory = std::env::temp_dir().join(format!(
        "nsvault-ffi-lock-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time")
            .as_nanos()
    ));
    std::fs::create_dir_all(&directory).expect("temp dir");
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))
        .expect("private temp dir");
    for (name, value) in [("access-key", "test"), ("secret-key", "test")] {
        let path = directory.join(name);
        std::fs::write(&path, value).expect("credential fixture");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .expect("credential mode");
    }
    let config = directory.join("config.toml");
    std::fs::write(
        &config,
        r#"version = 1
provider = "aws"
[providers.aws]
kind = "aws-secrets-manager"
region = "us-east-1"
endpoint = "http://127.0.0.1:9"
access_key_file = "access-key"
secret_key_file = "secret-key"
allow_http_loopback = true
"#,
    )
    .expect("write config");

    let lock_dir = directory.join("locks");
    std::fs::create_dir(&lock_dir).expect("lock dir");
    std::fs::set_permissions(&lock_dir, std::fs::Permissions::from_mode(0o755))
        .expect("non-private lock dir");
    // SAFETY: this test binary has no other test that resolves a write lock,
    // so the process-wide override cannot race a concurrent write.
    unsafe { std::env::set_var("NSVAULT_LOCK_DIR", &lock_dir) };

    let config = CString::new(config.to_string_lossy().as_bytes()).expect("config path");
    let mut client = std::ptr::null_mut();
    // SAFETY: the path and output pointers satisfy the documented contract.
    assert_eq!(
        unsafe { nsvault_client_open(config.as_ptr(), &mut client) },
        0
    );

    let key = CString::new("nsvault-ffi-lock").expect("key");
    let value = b"must-not-land";
    // SAFETY: the client is live and the value points at readable bytes.
    let status = unsafe {
        nsvault_set(
            client,
            std::ptr::null(),
            key.as_ptr(),
            value.as_ptr(),
            value.len(),
        )
    };
    assert_eq!(status, 1);
    let mut output = NsvaultBytes::default();
    // SAFETY: the output pointer is writable.
    assert_eq!(unsafe { nsvault_last_error(&mut output) }, 1);
    // SAFETY: the library produced this buffer and the lengths are valid.
    let message = unsafe { std::slice::from_raw_parts(output.data, output.len) };
    assert!(
        String::from_utf8_lossy(message).contains("not private"),
        "{}",
        String::from_utf8_lossy(message)
    );
    assert!(!String::from_utf8_lossy(message).contains("must-not-land"));
    // SAFETY: output was produced by the library and is freed once.
    unsafe { nsvault_bytes_free(output) };

    let mut created = 7;
    // SAFETY: the client is live and `created` is writable.
    let status = unsafe {
        nsvault_ensure(
            client,
            std::ptr::null(),
            key.as_ptr(),
            value.as_ptr(),
            value.len(),
            &mut created,
        )
    };
    assert_eq!(status, 1);
    assert_eq!(created, 7, "a failed ensure must not report created");

    // SAFETY: the client was opened once and is closed once.
    unsafe { nsvault_client_close(client) };
    // SAFETY: this test set the variable above and no other test reads it.
    unsafe { std::env::remove_var("NSVAULT_LOCK_DIR") };
    std::fs::remove_dir_all(directory).expect("remove temp dir");
}

#[test]
fn ffi_refuses_an_empty_value() {
    let path = temp_config("version = 1\n");
    let path = CString::new(path.to_string_lossy().as_bytes()).expect("path");
    let mut client = std::ptr::null_mut();
    // SAFETY: the path and output pointers satisfy the documented contract.
    assert_eq!(
        unsafe { nsvault_client_open(path.as_ptr(), &mut client) },
        0
    );
    let key = CString::new("KEY").expect("key");
    // SAFETY: the client is live; the value pointer is null with len 0.
    let status =
        unsafe { nsvault_set(client, std::ptr::null(), key.as_ptr(), std::ptr::null(), 0) };
    assert_eq!(status, 1);
    let mut created = 7;
    // SAFETY: the client is live; the value pointer is null with len 0.
    let status = unsafe {
        nsvault_ensure(
            client,
            std::ptr::null(),
            key.as_ptr(),
            std::ptr::null(),
            0,
            &mut created,
        )
    };
    assert_eq!(status, 1);
    assert_eq!(created, 7);
    // SAFETY: the client was opened once and is closed once.
    unsafe { nsvault_client_close(client) };
}
