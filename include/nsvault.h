/*
 * nsvault C ABI
 *
 * The library is conservative by design:
 *
 *   - nsvault_client_open allocates an opaque handle. Close it exactly once.
 *   - Every NsvaultBytes filled by this library is caller-owned. Release it
 *     with nsvault_bytes_free exactly once. Secret buffers are zeroed first.
 *   - Strings are NUL-terminated UTF-8. Optional string parameters may be NULL.
 *   - No panic crosses the ABI. A non-zero return is an error; call
 *     nsvault_last_error to copy a redacted message for the current thread.
 *   - The last error is consumed by nsvault_last_error and is valid until the
 *     next FFI call on that thread.
 *   - A client may be used concurrently for reads/list/set/ensure, but
 *     nsvault_client_close must not race with another call on the same handle.
 *   - set and ensure take a per-machine, same-user advisory lock keyed by the
 *     provider's canonical origin and non-secret scope. This is the same lock
 *     the CLI and the Rust API use, so writes to one provider scope serialize
 *     across threads, processes, and entry points for one OS user. A call can
 *     block until the other nsvault writer exits. Lock failures are returned
 *     as errors (status 1); there is no unlocked fallback and no timeout. The
 *     lock does not exclude writers that are not nsvault, another host, or
 *     another OS user. Coordination requires the same lock directory on every
 *     writer: the same NSVAULT_LOCK_DIR, or the same XDG_STATE_HOME/HOME when
 *     it is unset. Different values are different locks.
 *
 * Status: 0 = success, 1 = error (or, for nsvault_last_error, 1 = message).
 * Build:  cargo build --release --lib
 *         -> target/release/libnsvault.so  (cdylib)
 *         -> target/release/libnsvault.a   (staticlib)
 */

#ifndef NSVAULT_H
#define NSVAULT_H

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
int nsvault_client_open(const char *path, NsvaultClient **out);

/* Closes a handle. Passing NULL is a no-op. */
void nsvault_client_close(NsvaultClient *client);

/*
 * Lists key names under prefix, one per line (a trailing newline is present
 * when the result is non-empty). provider may be NULL to use the configured
 * default. prefix may be NULL for the configured default prefix.
 */
int nsvault_list(const NsvaultClient *client,
                 const char *provider,
                 const char *prefix,
                 NsvaultBytes *out);

/*
 * Reads one secret. provider may be NULL. key is required. The returned bytes
 * are the exact value and are not NUL-terminated.
 */
int nsvault_get(const NsvaultClient *client,
                const char *provider,
                const char *key,
                NsvaultBytes *out);

/*
 * Writes one secret. The value is passed as bytes so it never needs to appear
 * in argv or in a NUL-terminated string. Empty values are refused.
 */
int nsvault_set(const NsvaultClient *client,
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
int nsvault_ensure(const NsvaultClient *client,
                   const char *provider,
                   const char *key,
                   const uint8_t *value,
                   size_t value_len,
                   int *created);

/* Copies the current thread's last redacted error, if any. */
int nsvault_last_error(NsvaultBytes *out);

/* Releases a buffer returned by this library and zeroes its allocation. */
void nsvault_bytes_free(NsvaultBytes bytes);

#ifdef __cplusplus
}
#endif

#endif /* NSVAULT_H */
