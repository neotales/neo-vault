/*
 * nvault C ABI
 *
 * The library is conservative by design:
 *
 *   - nvault_client_open allocates an opaque handle. Close it exactly once.
 *   - Every NsvaultBytes filled by this library is caller-owned. Release it
 *     with nvault_bytes_free exactly once. Secret buffers are zeroed first.
 *   - Strings are NUL-terminated UTF-8. Optional string parameters may be NULL.
 *   - No panic crosses the ABI. A non-zero return is an error; call
 *     nvault_last_error to copy a redacted message for the current thread.
 *   - The last error is consumed by nvault_last_error and is valid until the
 *     next FFI call on that thread.
 *   - A client may be used concurrently for reads/list/set/ensure, but
 *     nvault_client_close must not race with another call on the same handle.
 *   - set and ensure take a per-machine, same-user advisory lock keyed by the
 *     provider's canonical origin and non-secret scope. This is the same lock
 *     the CLI and the Rust API use, so writes to one provider scope serialize
 *     across threads, processes, and entry points for one OS user. A call can
 *     block until the other nvault writer exits. Lock failures are returned
 *     as errors (status 1); there is no unlocked fallback and no timeout. The
 *     lock does not exclude writers that are not nvault, another host, or
 *     another OS user. Coordination requires the same lock directory on every
 *     writer: the same NVAULT_LOCK_DIR, or the same XDG_STATE_HOME/HOME when
 *     it is unset. Different values are different locks, and no component of
 *     that path may be a symbolic link. The path must be absolute; a relative
 *     NVAULT_LOCK_DIR or XDG_STATE_HOME is rejected. Every ancestor must be
 *     owned by root or this user (an owner can rename entries even without
 *     write permission), and an ancestor writable by group or others must also
 *     be sticky.
 *   - The lock is advisory. Do not remove, rename, or replace the lock
 *     directory or its lock files while a write may be in progress: a new
 *     inode or directory is a different lock. A hostile same-user process or
 *     root can break cooperation that way; this lock is not a boundary
 *     against them.
 *
 * Status: 0 = success, 1 = error (or, for nvault_last_error, 1 = message).
 * Build:  cargo build --release --lib
 *         -> target/release/libnvault.so  (cdylib)
 *         -> target/release/libnvault.a   (staticlib)
 */

#ifndef NVAULT_H
#define NVAULT_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct NsvaultClient NsvaultClient;

typedef struct {
    uint8_t *data;      /* NULL when len == 0 */
    size_t   len;       /* number of initialized bytes */
    size_t   capacity;  /* allocation capacity; do not modify */
} NsvaultBytes;

/* Opens a TOML or YAML configuration file. */
int nvault_client_open(const char *path, NsvaultClient **out);

/* Closes a handle. Passing NULL is a no-op. */
void nvault_client_close(NsvaultClient *client);

/*
 * Lists key names under prefix, one per line (a trailing newline is present
 * when the result is non-empty). provider may be NULL to use the configured
 * default. prefix may be NULL for the configured default prefix.
 */
int nvault_list(const NsvaultClient *client,
                 const char *provider,
                 const char *prefix,
                 NsvaultBytes *out);

/*
 * Reads one secret. provider may be NULL. key is required. The returned bytes
 * are the exact value and are not NUL-terminated.
 */
int nvault_get(const NsvaultClient *client,
                const char *provider,
                const char *key,
                NsvaultBytes *out);

/*
 * Writes one secret. The value is passed as bytes so it never needs to appear
 * in argv or in a NUL-terminated string. Empty values are refused.
 */
int nvault_set(const NsvaultClient *client,
                const char *provider,
                const char *key,
                const uint8_t *value,
                size_t value_len);

/*
 * Creates a secret only when the provider confirms it is absent. Does not
 * replace an existing secret and does not delete. On success, if created is
 * non-NULL, *created is 1 when this call created the secret and 0 when it was
 * already present. The value is never copied to an output buffer.
 */
int nvault_ensure(const NsvaultClient *client,
                   const char *provider,
                   const char *key,
                   const uint8_t *value,
                   size_t value_len,
                   int *created);

/* Copies the current thread's last redacted error, if any. */
int nvault_last_error(NsvaultBytes *out);

/* Releases a buffer returned by this library and zeroes its allocation. */
void nvault_bytes_free(NsvaultBytes bytes);

#ifdef __cplusplus
}
#endif

#endif /* NVAULT_H */
