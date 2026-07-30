#include <stdio.h>
#include <assert.h>
#include "hash.h"
#include "peb.h"
#include "config.h"

// Test hash computation
void test_hash(void) {
    printf("[TEST] hash module...\n");
    
    // Test that hash produces consistent results
    const uint8_t test_str[] = "test";
    uint32_t h1 = mirage_hash_string(test_str, 4, 28);
    uint32_t h2 = mirage_hash_string(test_str, 4, 28);
    assert(h1 == h2);
    
    // Test that different strings produce different hashes
    const uint8_t diff_str[] = "different";
    uint32_t h3 = mirage_hash_string(diff_str, 9, 28);
    assert(h1 != h3);
    
    // Test encrypted hash
    uint32_t eh1 = mirage_encrypted_hash_module("kernel32.dll");
    uint32_t eh2 = mirage_encrypted_hash_module("kernel32.dll");
    assert(eh1 == eh2);
    
    printf("[PASS] hash tests\n");
}

// Test config
void test_config(void) {
    printf("[TEST] config...\n");
    assert(MIRAGE_SEED == 0x61472f96);
    assert(MIRAGE_SSN_XOR_KEY == 0xA3B5C7D9);
    printf("[PASS] config tests\n");
}

int main(void) {
    printf("=== zialfi Unit Tests ===\n");
    test_hash();
    test_config();
    printf("=== All tests passed ===\n");
    return 0;
}
