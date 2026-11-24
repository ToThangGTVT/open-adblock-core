/* C ABI smoke test: header compiles, lifecycle and ownership rules hold. scripts/test-c.sh */
#include "openadblock.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int released;
static bool protect(void *context, int64_t fd) { (void)context; (void)fd; return true; }
static void release(void *context) { (void)context; released++; }
static void on_packet(void *context, const uint8_t *data, size_t length) {
    (void)context; (void)data; (void)length;
}

#define CHECK(condition) do { if (!(condition)) { \
    fprintf(stderr, "%s:%d: CHECK failed: %s\n", __FILE__, __LINE__, #condition); exit(1); } } while (0)

int main(void) {
    CHECK(oab_api_version() == OAB_API_VERSION);
    CHECK(strlen(oab_version()) > 0);

    char *report = oab_replace_rules("||ads.example^\n", NULL, "", false);
    CHECK(report != NULL && strstr(report, "\"loaded\":1") != NULL);
    oab_string_free(report);
    CHECK(oab_configure_dns("{}"));
    CHECK(!oab_configure_dns("not json"));

    int64_t counters[OAB_COUNTER_COUNT];
    CHECK(oab_counters(counters, OAB_COUNTER_COUNT) == OAB_COUNTER_COUNT);
    CHECK(counters[OAB_COUNTER_PACKETS_IN] == 0);

    OabSocketProtector protector = {NULL, protect, NULL, release};
    OabPacketSink sink = {NULL, on_packet, release};
    CHECK(oab_start_packets(&protector, "", &sink));
    CHECK(oab_is_running());
    CHECK(!oab_start_packets(&protector, "", &sink)); /* already running: both released */
    CHECK(released == 2);
    uint8_t junk[20] = {0x45};
    CHECK(oab_send_packet(junk, sizeof junk));
    oab_stop();
    CHECK(!oab_is_running());
    CHECK(released == 4);
    CHECK(!oab_send_packet(junk, sizeof junk));

    OabSocketProtector missing = {NULL, NULL, NULL, release};
    CHECK(!oab_start_packets(&missing, NULL, &sink));
    CHECK(released == 6);
    CHECK(oab_set_root_ca(NULL, NULL, 0, NULL, 0));
    puts("C ABI smoke test passed");
    return 0;
}
