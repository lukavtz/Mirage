/*
 * test_vpn.c — VPN: init_vpn_table, VPN name matching, has_ext
 * Build: gcc -Wall -Wextra -O2 -Iinclude -std=c11 -o tests/test_vpn tests/test_vpn.c
 */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>

/* ── Inline VPN table and helpers from vpn.c ──────────────── */

#define VPN_MAX_CLIENTS 18

typedef struct {
    const char *name;
    const char *subdir;
    const char *ext;
    int         use_local;
} VpnEntry;

static VpnEntry vpn_table[VPN_MAX_CLIENTS];
static int vpn_table_init = 0;

static void init_vpn_table(void) {
    if (vpn_table_init) return;
    static const char *names[] = {
        "NordVPN", "OpenVPN", "WireGuard", "Surfshark", "ExpressVPN",
        "CyberGhost", "PIA", "Mullvad", "Windscribe", "TunnelBear",
        "Hotspot Shield", "VyprVPN", "Hamachi", "Hide My Name",
        "IPVanish", "Radmin VPN", "SoftEther", "ProtonVPN"
    };
    static const char *subdirs[] = {
        "NordVPN", "OpenVPN Connect\\profiles", "WireGuard\\Configurations",
        "Surfshark", "ExpressVPN", "CyberGhost", "Private Internet Access",
        "Mullvad VPN", "Windscribe", "TunnelBear", "Hotspot Shield",
        "VyprVPN", "Hamachi", "Hide My Name", "IPVanish", "Radmin VPN",
        "SoftEther VPN Client", "ProtonVPN"
    };
    static const char *exts[] = {
        NULL, "ovpn", "conf", NULL, NULL, NULL, "json", "json",
        "cfg", NULL, "cfg", "dat", "conf", "xml", "dat", "xml", "config", NULL
    };
    static const int locals[] = { 0,0,0,1,0,0,0,0,0,1,1,0,0,0,0,0,0,1 };
    for (int i = 0; i < 18; i++) {
        vpn_table[i].name = names[i];
        vpn_table[i].subdir = subdirs[i];
        vpn_table[i].ext = exts[i];
        vpn_table[i].use_local = locals[i];
    }
    vpn_table_init = 1;
}

static int has_ext(const char *filename, const char *ext) {
    if (!ext) return 1;
    const char *dot = strrchr(filename, '.');
    if (!dot) return 0;
    return strcasecmp(dot + 1, ext) == 0;
}

/* ═══════════════════════ TESTS ═══════════════════════════ */

static void test_vpn_table_count(void) {
    init_vpn_table();
    int count = 0;
    for (int i = 0; i < VPN_MAX_CLIENTS; i++)
        if (vpn_table[i].name) count++;
    assert(count == 18);
}

static void test_vpn_table_init_idempotent(void) {
    vpn_table_init = 0;
    init_vpn_table();
    assert(vpn_table_init == 1);
    init_vpn_table(); /* second call should be no-op */
    assert(vpn_table_init == 1);
    assert(strcmp(vpn_table[0].name, "NordVPN") == 0);
}

static void test_vpn_table_no_nulls(void) {
    init_vpn_table();
    for (int i = 0; i < VPN_MAX_CLIENTS; i++) {
        assert(vpn_table[i].name != NULL);
        assert(vpn_table[i].subdir != NULL);
        assert(strlen(vpn_table[i].name) > 0);
        assert(strlen(vpn_table[i].subdir) > 0);
    }
}

static void test_vpn_table_known_entries(void) {
    init_vpn_table();
    assert(strcmp(vpn_table[0].name, "NordVPN") == 0);
    assert(strcmp(vpn_table[0].subdir, "NordVPN") == 0);
    assert(vpn_table[0].ext == NULL);
    assert(vpn_table[0].use_local == 0);

    assert(strcmp(vpn_table[1].name, "OpenVPN") == 0);
    assert(strcmp(vpn_table[1].ext, "ovpn") == 0);
    assert(strcmp(vpn_table[1].subdir, "OpenVPN Connect\\profiles") == 0);

    assert(strcmp(vpn_table[17].name, "ProtonVPN") == 0);
    assert(vpn_table[17].use_local == 1);
}

static void test_vpn_table_local_flag(void) {
    init_vpn_table();
    /* Surfshark, TunnelBear, Hotspot Shield, ProtonVPN use LOCAL */
    assert(vpn_table[3].use_local == 1);
    assert(vpn_table[9].use_local == 1);
    assert(vpn_table[10].use_local == 1);
    assert(vpn_table[17].use_local == 1);
    /* Rest use roaming */
    assert(vpn_table[0].use_local == 0);
    assert(vpn_table[1].use_local == 0);
    assert(vpn_table[2].use_local == 0);
    assert(vpn_table[4].use_local == 0);
}

static void test_has_ext_null_matches_all(void) {
    assert(has_ext("file.txt", NULL) == 1);
    assert(has_ext("noext", NULL) == 1);
    assert(has_ext("", NULL) == 1);
}

static void test_has_ext_match(void) {
    assert(has_ext("config.ovpn", "ovpn") == 1);
    assert(has_ext("server.conf", "conf") == 1);
    assert(has_ext("settings.json", "json") == 1);
    assert(has_ext("data.dat", "dat") == 1);
    assert(has_ext("profile.xml", "xml") == 1);
    assert(has_ext("tunnel.cfg", "cfg") == 1);
    assert(has_ext("client.config", "config") == 1);
}

static void test_has_ext_case_insensitive(void) {
    assert(has_ext("file.OVPN", "ovpn") == 1);
    assert(has_ext("file.Json", "json") == 1);
    assert(has_ext("file.CFG", "cfg") == 1);
}

static void test_has_ext_no_match(void) {
    assert(has_ext("file.txt", "ovpn") == 0);
    assert(has_ext("file.json", "conf") == 0);
}

static void test_has_ext_no_extension(void) {
    assert(has_ext("noext", "json") == 0);
}

int main(void) {
    test_vpn_table_count();
    test_vpn_table_init_idempotent();
    test_vpn_table_no_nulls();
    test_vpn_table_known_entries();
    test_vpn_table_local_flag();
    test_has_ext_null_matches_all();
    test_has_ext_match();
    test_has_ext_case_insensitive();
    test_has_ext_no_match();
    test_has_ext_no_extension();
    printf("test_vpn: ALL PASSED\n");
    return 0;
}
