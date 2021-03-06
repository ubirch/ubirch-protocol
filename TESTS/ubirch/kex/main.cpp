#include <unity/unity.h>
#include "ubirch/ubirch_protocol.h"
#include "ubirch_protocol_kex.h"
#include <ubirch/ubirch_ed25519.h>
#include <mbedtls/base64.h>

#include "utest/utest.h"
#include "greentea-client/test_env.h"

static const unsigned char UUID[16] = {'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p'};

using namespace utest::v1;

 unsigned char ed25519_secret_key[crypto_sign_SECRETKEYBYTES] = {
        0x69, 0x09, 0xcb, 0x3d, 0xff, 0x94, 0x43, 0x26, 0xed, 0x98, 0x72, 0x60,
        0x1e, 0xb3, 0x3c, 0xb2, 0x2d, 0x9e, 0x20, 0xdb, 0xbb, 0xe8, 0x17, 0x34,
        0x1c, 0x81, 0x33, 0x53, 0xda, 0xc9, 0xef, 0xbb, 0x7c, 0x76, 0xc4, 0x7c,
        0x51, 0x61, 0xd0, 0xa0, 0x3e, 0x7a, 0xe9, 0x87, 0x01, 0x0f, 0x32, 0x4b,
        0x87, 0x5c, 0x23, 0xda, 0x81, 0x31, 0x32, 0xcf, 0x8f, 0xfd, 0xaa, 0x55,
        0x93, 0xe6, 0x3e, 0x6a
};
 unsigned char ed25519_public_key[crypto_sign_PUBLICKEYBYTES] = {
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
static const time_t timestamp = 1518783656;


static inline bool isKey(const char *key, msgpack_object *o) {
    return o->via.str.size == strlen(key) && memcmp(key, o, o->via.str.size) == 0;
}

void TestPackKeyReg() {
    msgpack_sbuffer sbuf = {};
    msgpack_sbuffer_init(&sbuf);
    msgpack_packer pk;
    msgpack_packer_init(&pk, &sbuf, msgpack_sbuffer_write);

    ubirch_key_info info = {};
    info.algorithm = const_cast<char *>(UBIRCH_KEX_ALG_ECC_ED25519);
    info.created = static_cast<long>(timestamp);
    memcpy(info.hwDeviceId, UUID, sizeof(UUID));
    memcpy(info.pubKey, ed25519_public_key, sizeof(ed25519_public_key));
    info.validNotAfter = static_cast<long>(timestamp + 60000);
    info.validNotBefore = static_cast<long>(timestamp);

    msgpack_pack_key_register(&pk, &info);

    const char binaryMessage[] = {
            0x86, 0xa9, 0x61, 0x6c, 0x67, 0x6f, 0x72, 0x69, 0x74, 0x68, 0x6d, 0xab, 0x45, 0x43, 0x43, 0x5f, 0x45, 0x44,
            0x32, 0x35, 0x35, 0x31, 0x39, 0xa7, 0x63, 0x72, 0x65, 0x61, 0x74, 0x65, 0x64, 0xce, 0x5a, 0x86, 0xcc, 0xa8,
            0xaa, 0x68, 0x77, 0x44, 0x65, 0x76, 0x69, 0x63, 0x65, 0x49, 0x64, 0xc4, 0x10, 0x61, 0x62, 0x63, 0x64, 0x65,
            0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0xa6, 0x70, 0x75, 0x62, 0x4b, 0x65, 0x79,
            0xc4, 0x20, 0x7c, 0x76, 0xc4, 0x7c, 0x51, 0x61, 0xd0, 0xa0, 0x3e, 0x7a, 0xe9, 0x87, 0x01, 0x0f, 0x32, 0x4b,
            0x87, 0x5c, 0x23, 0xda, 0x81, 0x31, 0x32, 0xcf, 0x8f, 0xfd, 0xaa, 0x55, 0x93, 0xe6, 0x3e, 0x6a, 0xad, 0x76,
            0x61, 0x6c, 0x69, 0x64, 0x4e, 0x6f, 0x74, 0x41, 0x66, 0x74, 0x65, 0x72, 0xce, 0x5a, 0x87, 0xb7, 0x08, 0xae,
            0x76, 0x61, 0x6c, 0x69, 0x64, 0x4e, 0x6f, 0x74, 0x42, 0x65, 0x66, 0x6f, 0x72, 0x65, 0xce, 0x5a, 0x86, 0xcc,
            0xa8,
    };
    TEST_ASSERT_EQUAL_HEX8_ARRAY(binaryMessage, sbuf.data, sbuf.size);

    msgpack_zone mempool = {};
    msgpack_object deserialized = {};
    msgpack_zone_init(&mempool, 2048);
    msgpack_unpack(sbuf.data, sbuf.size, NULL, &mempool, &deserialized);

    TEST_ASSERT_EQUAL_INT_MESSAGE(MSGPACK_OBJECT_MAP, deserialized.type, "kex msg not a map");
    TEST_ASSERT_EQUAL_INT_MESSAGE(6, deserialized.via.map.size, "kex msg length wrong");

    msgpack_object_map map = deserialized.via.map;
    msgpack_object_kv *e = map.ptr;
    for (; e < map.ptr + map.size; e++) {
        TEST_ASSERT_EQUAL_INT(MSGPACK_OBJECT_STR, e->key.type);
        if (isKey(UBIRCH_KEX_ALGORITHM, &e->key)) {
            TEST_ASSERT_EQUAL_HEX8_ARRAY(UBIRCH_KEX_ALG_ECC_ED25519, e->val.via.str.ptr, e->val.via.str.size);
        } else if (isKey(UBIRCH_KEX_CREATED, &e->key)) {
            TEST_ASSERT_EQUAL_UINT(MBED_BUILD_TIMESTAMP, e->val.via.u64);
        } else if (isKey(UBIRCH_KEX_UUID, &e->key)) {
            TEST_ASSERT_EQUAL_HEX8_ARRAY(UUID, e->val.via.bin.ptr, e->val.via.bin.size);
        } else if (isKey(UBIRCH_KEX_PREV_PUBKEY_ID, &e->key)) {
            TEST_ASSERT_EQUAL_HEX8_ARRAY(prev_public_key, e->val.via.bin.ptr, e->val.via.bin.size);
        } else if (isKey(UBIRCH_KEX_PUBKEY, &e->key)) {
            TEST_ASSERT_EQUAL_HEX8_ARRAY(ed25519_public_key, e->val.via.bin.ptr, e->val.via.bin.size);
        } else if (isKey(UBIRCH_KEX_PUBKEY_ID, &e->key)) {
            TEST_ASSERT_EQUAL_HEX8_ARRAY(public_key_id, e->val.via.bin.ptr, e->val.via.bin.size);
        } else if (isKey(UBIRCH_KEX_VALID_NOT_AFTER, &e->key)) {
            TEST_ASSERT_EQUAL_UINT(MBED_BUILD_TIMESTAMP + 60000, e->val.via.u64);
        } else if (isKey(UBIRCH_KEX_VALID_NOT_BEFORE, &e->key)) {
            TEST_ASSERT_EQUAL_UINT(MBED_BUILD_TIMESTAMP, e->val.via.u64);
        }
    }

    msgpack_zone_destroy(&mempool);
}

void TestSignKeyRegisterMessage() {
    ubirch_key_info info = {};
    info.algorithm = const_cast<char *>(UBIRCH_KEX_ALG_ECC_ED25519);
    info.created = static_cast<long>(timestamp);
    memcpy(info.hwDeviceId, UUID, sizeof(UUID));
    memcpy(info.pubKey, ed25519_public_key, sizeof(ed25519_public_key));
    info.validNotAfter = static_cast<long>(timestamp + 60000);
    info.validNotBefore = static_cast<long>(timestamp);

    ubirch_protocol *upp = ubirch_protocol_new(UUID, ed25519_sign);
    TEST_ASSERT_NOT_NULL_MESSAGE(upp, "creating UPP context failed");

    int8_t ret = ubirch_protocol_message(upp, proto_signed, UBIRCH_PROTOCOL_TYPE_REG,
                                         reinterpret_cast<const char *> (&info), sizeof(info));
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, ret, "packing UPP failed");

    const char expectedMessage[] = {
            0x95, 0x22, 0xc4, 0x10, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e,
            0x6f, 0x70, 0x01, 0x86, 0xa9, 0x61, 0x6c, 0x67, 0x6f, 0x72, 0x69, 0x74, 0x68, 0x6d, 0xab, 0x45, 0x43, 0x43,
            0x5f, 0x45, 0x44, 0x32, 0x35, 0x35, 0x31, 0x39, 0xa7, 0x63, 0x72, 0x65, 0x61, 0x74, 0x65, 0x64, 0xce, 0x5a,
            0x86, 0xcc, 0xa8, 0xaa, 0x68, 0x77, 0x44, 0x65, 0x76, 0x69, 0x63, 0x65, 0x49, 0x64, 0xc4, 0x10, 0x61, 0x62,
            0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0xa6, 0x70, 0x75, 0x62,
            0x4b, 0x65, 0x79, 0xc4, 0x20, 0x7c, 0x76, 0xc4, 0x7c, 0x51, 0x61, 0xd0, 0xa0, 0x3e, 0x7a, 0xe9, 0x87, 0x01,
            0x0f, 0x32, 0x4b, 0x87, 0x5c, 0x23, 0xda, 0x81, 0x31, 0x32, 0xcf, 0x8f, 0xfd, 0xaa, 0x55, 0x93, 0xe6, 0x3e,
            0x6a, 0xad, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x4e, 0x6f, 0x74, 0x41, 0x66, 0x74, 0x65, 0x72, 0xce, 0x5a, 0x87,
            0xb7, 0x08, 0xae, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x4e, 0x6f, 0x74, 0x42, 0x65, 0x66, 0x6f, 0x72, 0x65, 0xce,
            0x5a, 0x86, 0xcc, 0xa8, 0xc4, 0x40, 0x31, 0x4d, 0xa3, 0x93, 0x67, 0x6d, 0x87, 0x9e, 0x3c, 0xc0, 0x30, 0x89,
            0x6e, 0x16, 0x18, 0x39, 0xca, 0x47, 0x7c, 0x8b, 0x0a, 0x00, 0x64, 0x43, 0xd0, 0x23, 0x44, 0x9d, 0x59, 0xa2,
            0x6f, 0x1f, 0x88, 0xb2, 0x6a, 0x68, 0x49, 0x95, 0x60, 0x2b, 0x78, 0x58, 0x8e, 0x35, 0x8f, 0x80, 0x4e, 0x6d,
            0xdb, 0x9f, 0x32, 0xf9, 0x2c, 0x92, 0x37, 0x95, 0xa8, 0xcc, 0x3b, 0xd1, 0xee, 0x52, 0x80, 0x07,
    };
    TEST_ASSERT_EQUAL_INT_MESSAGE(sizeof(expectedMessage), upp->size, "message length wrong");
    TEST_ASSERT_EQUAL_HEX8_ARRAY_MESSAGE(expectedMessage, upp->data, upp->size, "message serialization failed");

    ubirch_protocol_free(upp);
}

void TestKeyVerify() {
    ubirch_key_info info = {};
    info.algorithm = const_cast<char *>(UBIRCH_KEX_ALG_ECC_ED25519);
    info.created = static_cast<long>(timestamp);
    memcpy(info.hwDeviceId, UUID, sizeof(UUID));
    memcpy(info.pubKey, ed25519_public_key, sizeof(ed25519_public_key));
    info.validNotAfter = static_cast<long>(timestamp + 60000);
    info.validNotBefore = static_cast<long>(timestamp);

    // create ubirch key registration message
    ubirch_protocol *upp = ubirch_protocol_new(UUID, ed25519_sign);
    TEST_ASSERT_NOT_NULL_MESSAGE(upp, "creating UPP context failed");

    int8_t ret = ubirch_protocol_message(upp, proto_signed, UBIRCH_PROTOCOL_TYPE_REG,
                                         reinterpret_cast<const char *> (&info), sizeof(info));
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, ret, "packing UPP failed");

    // verify message
    ret = ubirch_protocol_verify(upp->data, upp->size, ed25519_verify);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, ret, "message verification failed");

    ubirch_protocol_free(upp);
}

void TestHostKeyRegMessage() {
    ubirch_key_info info = {};
    info.algorithm = const_cast<char *>(UBIRCH_KEX_ALG_ECC_ED25519);
    info.created = static_cast<long>(timestamp);
    memcpy(info.hwDeviceId, UUID, sizeof(UUID));
    memcpy(info.pubKey, ed25519_public_key, sizeof(ed25519_public_key));
    info.validNotAfter = static_cast<long>(timestamp + 60000);
    info.validNotBefore = static_cast<long>(timestamp);

    char _key[20], _value[500];
    size_t encoded_size;

    // create ubirch key registration message
    ubirch_protocol *upp = ubirch_protocol_new(UUID, ed25519_sign);
    TEST_ASSERT_NOT_NULL_MESSAGE(upp, "creating UPP context failed");

    int8_t ret = ubirch_protocol_message(upp, proto_signed, UBIRCH_PROTOCOL_TYPE_REG,
                                         reinterpret_cast<const char *> (&info), sizeof(info));
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, ret, "packing UPP failed");

    // encode and send message to host
    memset(_value, 0, sizeof(_value));
    int encode_error = mbedtls_base64_encode((unsigned char *) _value, sizeof(_value), &encoded_size,
                                             (unsigned char *) upp->data, upp->size);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, encode_error, "mbedtls_base64_encode returned error");
    greentea_send_kv("checkMessage", _value, encoded_size);

    ubirch_protocol_free(upp);

    greentea_parse_kv(_key, _value, sizeof(_key), sizeof(_value));
    TEST_ASSERT_EQUAL_STRING_MESSAGE("variant", _key, "message verification failed");
    TEST_ASSERT_EQUAL_STRING_MESSAGE("2", _value, "protocol variant check failed");

    greentea_parse_kv(_key, _value, sizeof(_key), sizeof(_value));
    TEST_ASSERT_EQUAL_STRING_MESSAGE("uuid", _key, "unexpected key");
    TEST_ASSERT_EQUAL_HEX8_ARRAY_MESSAGE(UUID, _value, UBIRCH_PROTOCOL_UUID_SIZE, "UUID check failed");
}

utest::v1::status_t greentea_test_setup(const size_t number_of_cases) {
    GREENTEA_SETUP(600, "ProtocolTests");
    return greentea_test_setup_handler(number_of_cases);
}


int main() {
    Case cases[] = {
            Case("ubirch protocol [kex] pack key register info",
                 TestPackKeyReg, greentea_case_failure_abort_handler),
            Case("ubirch protocol [kex] signed key register message",
                 TestSignKeyRegisterMessage, greentea_case_failure_abort_handler),
            Case("ubirch protocol [kex] verify signed key register message",
                 TestKeyVerify, greentea_case_failure_abort_handler),
            Case("ubirch protocol [kex] verify key register message with host",
                 TestHostKeyRegMessage, greentea_case_failure_abort_handler),
    };

    Specification specification(greentea_test_setup, cases, greentea_test_teardown_handler);
    Harness::run(specification);
}