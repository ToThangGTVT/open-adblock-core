/*
 * Open AdBlock core — C ABI.
 *
 * For native hosts: Swift (macOS/iOS Network Extension), C#/C++ (Windows, Wintun), C/C++ (Linux).
 * Link libopenadblock (static: libopenadblock.a / openadblock.lib, shared: .dylib/.so/.dll).
 * JVM hosts use the Java API in bindings/java instead.
 *
 * Conventions
 *  - Input strings: NUL-terminated UTF-8, borrowed for the call. NULL means "".
 *  - Output strings: owned by the caller, free with oab_string_free().
 *  - Output byte buffers: owned by the caller, free with oab_bytes_free().
 *  - Callback structs are copied. `context` is passed back to every callback; `release`
 *    (optional) runs exactly once when the engine no longer needs the context, also when the
 *    call that received it fails. Callbacks run on engine threads and must be thread-safe.
 *  - JSON configuration schemas: docs/API.md.
 */
#ifndef OPENADBLOCK_H
#define OPENADBLOCK_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Binding contract implemented by this header. Compare with oab_api_version() at runtime. */
#define OAB_API_VERSION 1u

/* Number of values oab_counters() reports today; new counters are only appended. */
#define OAB_COUNTER_COUNT 8u
enum {
    OAB_COUNTER_PACKETS_IN = 0,
    OAB_COUNTER_PACKETS_OUT = 1,
    OAB_COUNTER_TCP_OPENED = 2,
    OAB_COUNTER_UDP_OPENED = 3,
    OAB_COUNTER_PROTECT_DENIED = 4,
    OAB_COUNTER_TCP_BYTES_UP = 5,
    OAB_COUNTER_TCP_BYTES_DOWN = 6,
    OAB_COUNTER_NETWORK_RESETS = 7,
};

/* Excludes engine sockets from the tunnel. `fd` is a file descriptor (POSIX) or SOCKET
 * (Windows). Return true when the socket bypasses the tunnel; false closes it (fail closed).
 * connection_owner (optional) returns the app id owning a tunnelled flow, or -1. */
typedef struct OabSocketProtector {
    void *context;
    bool (*protect)(void *context, int64_t fd);
    int64_t (*connection_owner)(void *context, uint8_t protocol, const char *source,
                                uint16_t source_port, const char *destination,
                                uint16_t destination_port);
    void (*release)(void *context);
} OabSocketProtector;

/* Batched query-log/statistics JSON; `json` is valid only during the call. */
typedef struct OabEventListener {
    void *context;
    void (*on_events)(void *context, const char *json);
    void (*release)(void *context);
} OabEventListener;

/* One IP packet from the engine toward apps (packet mode); valid only during the call. */
typedef struct OabPacketSink {
    void *context;
    void (*on_packet)(void *context, const uint8_t *data, size_t length);
    void (*release)(void *context);
} OabPacketSink;

/* Signs with the host-held root CA key: ECDSA P-256, SHA-256, DER signature. Write at most
 * `capacity` (128) bytes to `signature` and return the length, or 0 to refuse. */
typedef struct OabCertificateSigner {
    void *context;
    size_t (*sign)(void *context, const uint8_t *data, size_t length, uint8_t *signature,
                   size_t capacity);
    void (*release)(void *context);
} OabCertificateSigner;

/* --- Library ------------------------------------------------------------------------------ */
const char *oab_version(void); /* static string, do not free */
uint32_t oab_api_version(void);
void oab_string_free(char *value);
void oab_bytes_free(uint8_t *data, size_t length);

/* --- Tunnel (one per process) ------------------------------------------------------------- */
/* POSIX: the engine owns `fd` from entry, also on failure. Returns false on Windows. */
bool oab_start_fd(int32_t fd, const OabSocketProtector *protector, const char *dns);
/* Host-driven packet I/O: push app packets with oab_send_packet, receive replies in `sink`. */
bool oab_start_packets(const OabSocketProtector *protector, const char *dns,
                       const OabPacketSink *sink);
/* False when not in packet mode or the queue is full (the packet is dropped). */
bool oab_send_packet(const uint8_t *data, size_t length);
/* Loopback listener for TCP streams the host intercepts per app (docs/API.md#app-proxy).
 * Writes the port and the NUL-terminated token; false when the tunnel is not running. */
#define OAB_APP_PROXY_TOKEN_LENGTH 32u
bool oab_open_app_proxy(uint16_t *port, char *token, size_t token_capacity);
void oab_stop(void);
bool oab_update_network(const char *dns);
bool oab_is_running(void);
/* Copies min(capacity, count) counters to `values` (may be NULL); returns the count. */
size_t oab_counters(int64_t *values, size_t capacity);

/* --- Configuration (JSON, valid any time; false keeps the previous value) ------------------ */
bool oab_configure_policy(const char *json);
bool oab_configure_dns(const char *json);
bool oab_configure_https(const char *json);

/* --- Filters ------------------------------------------------------------------------------ */
/* Returns a JSON report; free with oab_string_free. `apply` false only validates. */
char *oab_replace_rules(const char *dns_rules, const char *browser_rules,
                        const char *custom_rules, bool apply);
char *oab_set_resources(const char *scriptlets, const char *redirects);

/* --- Events ------------------------------------------------------------------------------- */
/* NULL detaches the current listener. */
void oab_set_event_listener(const OabEventListener *listener);
void oab_flush_events(void);
void oab_set_request_capture(int32_t app, int64_t session, int32_t minutes);

/* --- HTTPS root CA (private key stays in the host's secure store) ------------------------- */
/* `public_point`: uncompressed P-256 point, 65 bytes starting with 0x04. On success
 * *certificate receives a DER buffer to free with oab_bytes_free. */
bool oab_generate_root_ca(const OabCertificateSigner *signer, const uint8_t *public_point,
                          size_t public_length, uint8_t **certificate,
                          size_t *certificate_length);
/* NULL signer removes the root CA (HTTPS filtering off). */
bool oab_set_root_ca(const OabCertificateSigner *signer, const uint8_t *public_point,
                     size_t public_length, const uint8_t *certificate,
                     size_t certificate_length);

#ifdef __cplusplus
}
#endif
#endif /* OPENADBLOCK_H */
