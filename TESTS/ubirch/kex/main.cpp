#include <unity/unity.h>
#include <ubirch/ubirch_protocol.h>
#include <armnacl.h>
#include <platform/mbed_mem_trace.h>
#include <ubirch_protocol_kex.h>
#include <object.h>

#include "utest/utest.h"
#include "greentea-client/test_env.h"

static const unsigned char UUID[16] = {'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p'};

using namespace utest::v1;

static unsigned char private_key[crypto_sign_SECRETKEYBYTES] = {
        0x69, 0x09, 0xcb, 0x3d, 0xff, 0x94, 0x43, 0x26, 0xed, 0x98, 0x72, 0x60,
        0x1e, 0xb3, 0x3c, 0xb2, 0x2d, 0x9e, 0x20, 0xdb, 0xbb, 0xe8, 0x17, 0x34,
        0x1c, 0x81, 0x33, 0x53, 0xda, 0xc9, 0xef, 0xbb, 0x7c, 0x76, 0xc4, 0x7c,
        0x51, 0x61, 0xd0, 0xa0, 0x3e, 0x7a, 0xe9, 0x87, 0x01, 0x0f, 0x32, 0x4b,
        0x87, 0x5c, 0x23, 0xda, 0x81, 0x31, 0x32, 0xcf, 0x8f, 0xfd, 0xaa, 0x55,
        0x93, 0xe6, 0x3e, 0x6a
};
static unsigned char public_key[crypto_sign_PUBLICKEYBYTES] = {
        0x7c, 0x76, 0xc4, 0x7c, 0x51, 0x61, 0xd0, 0xa0, 0x3e, 0x7a, 0xe9, 0x87,
        0x01, 0x0f, 0x32, 0x4b, 0x87, 0x5c, 0x23, 0xda, 0x81, 0x31, 0x32, 0xcf,
        0x8f, 0xfd, 0xaa, 0x55, 0x93, 0xe6, 0x3e, 0x6a
};
static unsigned char prev_public_key[crypto_sign_PUBLICKEYBYTES] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};
static const unsigned char *public_key_id = reinterpret_cast<const unsigned char *>("foobar");

int ed25519_sign(const char *buf, size_t len, unsigned char signature[crypto_sign_BYTES]) {
    crypto_uint16 signedLength;
    unsigned char *signedMessage = new unsigned char[crypto_sign_BYTES + len];
    crypto_sign(signedMessage, &signedLength, (const unsigned char *) buf, (crypto_uint16) len, private_key);
    memcpy(signature, signedMessage, crypto_sign_BYTES);
    delete[] signedMessage;
    return 0;
}


void dump(void *buf, size_t len) {
    for (unsigned int i = 0; i < len; i++) {
        printf("%02x", ((unsigned char *) buf)[i]);
    }
    printf("\r\n");
}

static inline bool isKey(const char *key, msgpack_object *o) {
    return o->via.raw.size == strlen(key) && memcmp(key, o, o->via.raw.size);
}

void TestProtocolInit() {
    msgpack_sbuffer sbuf = {};
    msgpack_sbuffer_init(&sbuf);
    msgpack_packer *pk = msgpack_packer_new(&sbuf, msgpack_sbuffer_write);

    ubirch_key_info info = {};
    info.algorithm = const_cast<char *>(UBIRCH_KEX_ALG_ECC_ED25519);
    info.created = static_cast<long>(MBED_BUILD_TIMESTAMP);
    memcpy(info.hwDeviceId, UUID, sizeof(UUID));
    memcpy(info.pubKey, public_key, sizeof(public_key));
    info.validNotAfter = static_cast<long>(MBED_BUILD_TIMESTAMP + 60000);
    info.validNotBefore = static_cast<long>(MBED_BUILD_TIMESTAMP);

    msgpack_pack_key_register(pk, &info);

    msgpack_zone mempool = {};
    msgpack_object deserialized = {};
    msgpack_zone_init(&mempool, 2048);
    msgpack_unpack(sbuf.data, sbuf.size, NULL, &mempool, &deserialized);

    TEST_ASSERT_EQUAL_INT_MESSAGE(MSGPACK_OBJECT_MAP, deserialized.type, "kex msg not a map");
    TEST_ASSERT_EQUAL_INT_MESSAGE(6, deserialized.via.map.size, "kex msg length wrong");

    msgpack_object_map map = deserialized.via.map;
    msgpack_object_kv *e = map.ptr;
    for (; e < map.ptr + map.size; e++) {
        TEST_ASSERT_EQUAL_INT(MSGPACK_OBJECT_RAW, e->key.type);
        //printf("%.*s\r\n", (int) e->key.via.raw.size, e->key.via.raw.ptr);
        if (isKey(UBIRCH_KEX_ALGORITHM, &e->key)) {
            TEST_ASSERT_EQUAL_HEX8_ARRAY(UBIRCH_KEX_ALG_ECC_ED25519, e->val.via.raw.ptr, e->val.via.raw.size);
        } else if (isKey(UBIRCH_KEX_CREATED, &e->key)) {
            TEST_ASSERT_EQUAL_UINT(MBED_BUILD_TIMESTAMP, e->val.via.u64);
        } else if (isKey(UBIRCH_KEX_UUID, &e->key)) {
            TEST_ASSERT_EQUAL_HEX8_ARRAY(UUID, e->val.via.raw.ptr, e->val.via.raw.size);
        } else if (isKey(UBIRCH_KEX_PREV_PUBKEY_ID, &e->key)) {
            TEST_ASSERT_EQUAL_HEX8_ARRAY(prev_public_key, e->val.via.raw.ptr, e->val.via.raw.size);
        } else if (isKey(UBIRCH_KEX_PUBKEY, &e->key)) {
            TEST_ASSERT_EQUAL_HEX8_ARRAY(public_key, e->val.via.raw.ptr, e->val.via.raw.size);
        } else if (isKey(UBIRCH_KEX_PUBKEY_ID, &e->key)) {
            TEST_ASSERT_EQUAL_HEX8_ARRAY(public_key_id, e->val.via.raw.ptr, e->val.via.raw.size);
        } else if (isKey(UBIRCH_KEX_VALID_NOT_AFTER, &e->key)) {
            TEST_ASSERT_EQUAL_UINT(MBED_BUILD_TIMESTAMP + 60000, e->val.via.u64);
        } else if (isKey(UBIRCH_KEX_VALID_NOT_BEFORE, &e->key)) {
            TEST_ASSERT_EQUAL_UINT(MBED_BUILD_TIMESTAMP, e->val.via.u64);
        }

    }


//    for (unsigned int i = 0; i < sbuf.size; i++) printf("%02x", sbuf.data[i]);
//    printf("\r\n");
}

utest::v1::status_t greentea_test_setup(const size_t number_of_cases) {
    GREENTEA_SETUP(600, "ProtocolTests");
    return greentea_test_setup_handler(number_of_cases);
}


int main() {
    mbed_mem_trace_set_callback(mbed_mem_trace_default_callback);

    Case cases[] = {
            Case("ubirch protocol [kex] init",
                 TestProtocolInit, greentea_case_failure_abort_handler),
    };

    Specification specification(greentea_test_setup, cases, greentea_test_teardown_handler);
    Harness::run(specification);
}