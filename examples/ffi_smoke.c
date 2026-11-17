/*
 * Minimal ABI smoke test. It does not contact a provider.
 *
 *   cargo build --release --lib
 *   cc examples/ffi_smoke.c -Iinclude -Ltarget/release -lnsvault \
 *      -Wl,-rpath,'$ORIGIN/../target/release' -o /tmp/nsvault-ffi-smoke
 *   /tmp/nsvault-ffi-smoke
 */

#include "nsvault.h"

#include <stdio.h>
#include <string.h>

int main(void) {
    NsvaultClient *client = NULL;
    int status = nsvault_client_open("/nonexistent/nsvault.toml", &client);
    if (status == 0 || client != NULL) {
        fprintf(stderr, "expected open to fail\n");
        return 1;
    }

    NsvaultBytes error = {0};
    if (nsvault_last_error(&error) != 1 || error.len == 0) {
        fprintf(stderr, "expected a redacted error\n");
        return 1;
    }
    printf("redacted error received (%zu bytes)\n", error.len);
    nsvault_bytes_free(error);

    int created = 99;
    status = nsvault_ensure(NULL, NULL, "key", (const uint8_t *)"x", 1, &created);
    if (status == 0 || created != 99) {
        fprintf(stderr, "expected ensure on a null client to fail without writing status\n");
        return 1;
    }
    nsvault_bytes_free((NsvaultBytes){0});
    if (nsvault_last_error(&error) != 1) {
        fprintf(stderr, "expected an ensure error\n");
        return 1;
    }
    nsvault_bytes_free(error);

    nsvault_client_close(NULL);
    return 0;
}
