#include <unity/unity.h>
#include "ubirch/ubirch_protocol.h"
#include <ubirch/ubirch_ed25519.h>
#include <mbedtls/base64.h>
#include <msgpack.h>

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

void TestProtocolNewSigned() {
    const unsigned char allZeros[UBIRCH_PROTOCOL_SIGN_SIZE] = {0};

    ubirch_protocol *upp = ubirch_protocol_new(UUID, ed25519_sign);

    TEST_ASSERT_NOT_NULL_MESSAGE(upp, "creating UPP context failed");
    TEST_ASSERT_NOT_NULL_MESSAGE(upp->data, "creating UPP data buffer failed");
    TEST_ASSERT_EQUAL_INT(UPP_BUFFER_INIT_SIZE, upp->alloc);
    TEST_ASSERT_EQUAL_PTR_MESSAGE(upp, upp->packer.data, "packer data not initialized");
    TEST_ASSERT_EQUAL_PTR_MESSAGE(ubirch_protocol_write, upp->packer.callback, "packer callback not initialized");
    TEST_ASSERT_EQUAL_PTR_MESSAGE(ed25519_sign, upp->sign, "sign callback not initialized");
    TEST_ASSERT_EQUAL_UINT8_ARRAY(upp->uuid, UUID, UBIRCH_PROTOCOL_UUID_SIZE);
    TEST_ASSERT_EQUAL_UINT8_ARRAY_MESSAGE(allZeros, upp->signature, UBIRCH_PROTOCOL_SIGN_SIZE,
                                          "last signature should be 0");

    ubirch_protocol_free(upp);
}

void TestProtocolMessageSigned() {
    const char msg[] = {0x24, 0x98, 0x3f, 0xff, 0xf3, 0x89, 0x42};
    const char expected_message[] = {
            0x95, 0x22, 0xc4, 0x10, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e,
            0x6f, 0x70, 0x00, 0xc4, 0x07, 0x24, 0x98, 0x3f, 0xff, 0xf3, 0x89, 0x42, 0xc4, 0x40, 0x92, 0x7b, 0xd0, 0x65,
            0x12, 0x97, 0x94, 0x2a, 0x92, 0x6a, 0x54, 0x63, 0xe0, 0xfc, 0x1a, 0x78, 0xa3, 0x5a, 0x61, 0x13, 0x31, 0xcb,
            0x62, 0x4c, 0xde, 0x6d, 0x28, 0xcf, 0xe1, 0xfa, 0x76, 0xf9, 0x64, 0xda, 0xbb, 0xb4, 0x54, 0xda, 0x5a, 0x1e,
            0x3c, 0x8d, 0x0c, 0x98, 0xe2, 0x09, 0x1e, 0xff, 0x5e, 0xfc, 0x54, 0x04, 0xf1, 0xc3, 0x83, 0x41, 0x1b, 0x5c,
            0x23, 0xc1, 0x22, 0x63, 0xf5, 0x01,
    };

    ubirch_protocol *upp = ubirch_protocol_new(UUID, ed25519_sign);
    TEST_ASSERT_NOT_NULL_MESSAGE(upp, "creating UPP context failed");

    int8_t ret = ubirch_protocol_message(upp, proto_signed, UBIRCH_PROTOCOL_TYPE_BIN, msg, sizeof(msg));
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, ret, "packing UPP failed");
    TEST_ASSERT_EQUAL_INT_MESSAGE(sizeof(expected_message), upp->size, "message length wrong");
    TEST_ASSERT_EQUAL_HEX8_ARRAY_MESSAGE(expected_message, upp->data, upp->size, "message serialization failed");

    ubirch_protocol_free(upp);
}

void TestProtocolVerifySigned() {
    const char msg[] = {0x24, 0x98, 0x3f, 0xff, 0xf3, 0x89, 0x42};

    ubirch_protocol *upp = ubirch_protocol_new(UUID, ed25519_sign);
    TEST_ASSERT_NOT_NULL_MESSAGE(upp, "creating UPP context failed");

    int8_t ret = ubirch_protocol_message(upp, proto_signed, UBIRCH_PROTOCOL_TYPE_BIN, msg, sizeof(msg));
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, ret, "packing UPP failed");

    // verify message
    ret = ubirch_protocol_verify(upp->data, upp->size, ed25519_verify);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, ret, "message verification failed");

    ubirch_protocol_free(upp);
}

void TestSimpleMessageSigned() {
    char _key[20], _value[300];
    size_t encoded_size;
    const char *msg = "simple message";

    // create UPP
    ubirch_protocol *upp = ubirch_protocol_new(UUID, ed25519_sign);
    TEST_ASSERT_NOT_NULL_MESSAGE(upp, "creating UPP context failed");

    int8_t ret = ubirch_protocol_message(upp, proto_signed, UBIRCH_PROTOCOL_TYPE_BIN, msg, strlen(msg));
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, ret, "packing UPP failed");

    // register public key with host
    memset(_value, 0, sizeof(_value));
    mbedtls_base64_encode((unsigned char *) _value, sizeof(_value), &encoded_size, ed25519_public_key,
                          crypto_sign_PUBLICKEYBYTES);
    greentea_send_kv("publicKey", _value);

    // send message to host
    memset(_value, 0, sizeof(_value));
    int encode_error = mbedtls_base64_encode((unsigned char *) _value, sizeof(_value), &encoded_size,
                                             (unsigned char *) upp->data, upp->size);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, encode_error, "mbedtls_base64_encode returned error");;
    greentea_send_kv("checkMessage", _value, encoded_size);

    ubirch_protocol_free(upp);

    // check if host could verify signature and was able to unpack UPP correctly
    greentea_parse_kv(_key, _value, sizeof(_key), sizeof(_value));
    TEST_ASSERT_EQUAL_STRING_MESSAGE("variant", _key, "message verification failed");
    TEST_ASSERT_EQUAL_STRING_MESSAGE("2", _value, "protocol variant check failed");

    greentea_parse_kv(_key, _value, sizeof(_key), sizeof(_value));
    TEST_ASSERT_EQUAL_STRING_MESSAGE("uuid", _key, "unexpected key");
    TEST_ASSERT_EQUAL_HEX8_ARRAY_MESSAGE(UUID, _value, UBIRCH_PROTOCOL_UUID_SIZE, "UUID check failed");

    greentea_parse_kv(_key, _value, sizeof(_key), sizeof(_value));
    TEST_ASSERT_EQUAL_STRING_MESSAGE("payload", _key, "unexpected key");
    TEST_ASSERT_EQUAL_STRING_MESSAGE(msg, _value, "payload check failed");
}

void TestProtocolLongMessageSigned() {
    /* this message is 259 bytes long */
    const char *msg = "Libero enim sed faucibus turpis in eu. Aliquet risus feugiat in ante metus dictum at tempor "
                      "commodo. Sit amet facilisis magna etiam tempor orci eu lobortis elementum. Cras tincidunt "
                      "lobortis feugiat vivamus. Eu scelerisque felis imperdiet proin fermentum leo.";

    ubirch_protocol *upp = ubirch_protocol_new(UUID, ed25519_sign);
    TEST_ASSERT_NOT_NULL_MESSAGE(upp, "creating UPP context failed");

    int8_t ret = ubirch_protocol_message(upp, proto_signed, UBIRCH_PROTOCOL_TYPE_BIN, msg, strlen(msg));
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, ret, "packing UPP failed");

    const char expected_message[] = {
            0x95, 0x22, 0xc4, 0x10, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e,
            0x6f, 0x70, 0x00, 0xc5, 0x01, 0x03, 0x4c, 0x69, 0x62, 0x65, 0x72, 0x6f, 0x20, 0x65, 0x6e, 0x69, 0x6d, 0x20,
            0x73, 0x65, 0x64, 0x20, 0x66, 0x61, 0x75, 0x63, 0x69, 0x62, 0x75, 0x73, 0x20, 0x74, 0x75, 0x72, 0x70, 0x69,
            0x73, 0x20, 0x69, 0x6e, 0x20, 0x65, 0x75, 0x2e, 0x20, 0x41, 0x6c, 0x69, 0x71, 0x75, 0x65, 0x74, 0x20, 0x72,
            0x69, 0x73, 0x75, 0x73, 0x20, 0x66, 0x65, 0x75, 0x67, 0x69, 0x61, 0x74, 0x20, 0x69, 0x6e, 0x20, 0x61, 0x6e,
            0x74, 0x65, 0x20, 0x6d, 0x65, 0x74, 0x75, 0x73, 0x20, 0x64, 0x69, 0x63, 0x74, 0x75, 0x6d, 0x20, 0x61, 0x74,
            0x20, 0x74, 0x65, 0x6d, 0x70, 0x6f, 0x72, 0x20, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x64, 0x6f, 0x2e, 0x20, 0x53,
            0x69, 0x74, 0x20, 0x61, 0x6d, 0x65, 0x74, 0x20, 0x66, 0x61, 0x63, 0x69, 0x6c, 0x69, 0x73, 0x69, 0x73, 0x20,
            0x6d, 0x61, 0x67, 0x6e, 0x61, 0x20, 0x65, 0x74, 0x69, 0x61, 0x6d, 0x20, 0x74, 0x65, 0x6d, 0x70, 0x6f, 0x72,
            0x20, 0x6f, 0x72, 0x63, 0x69, 0x20, 0x65, 0x75, 0x20, 0x6c, 0x6f, 0x62, 0x6f, 0x72, 0x74, 0x69, 0x73, 0x20,
            0x65, 0x6c, 0x65, 0x6d, 0x65, 0x6e, 0x74, 0x75, 0x6d, 0x2e, 0x20, 0x43, 0x72, 0x61, 0x73, 0x20, 0x74, 0x69,
            0x6e, 0x63, 0x69, 0x64, 0x75, 0x6e, 0x74, 0x20, 0x6c, 0x6f, 0x62, 0x6f, 0x72, 0x74, 0x69, 0x73, 0x20, 0x66,
            0x65, 0x75, 0x67, 0x69, 0x61, 0x74, 0x20, 0x76, 0x69, 0x76, 0x61, 0x6d, 0x75, 0x73, 0x2e, 0x20, 0x45, 0x75,
            0x20, 0x73, 0x63, 0x65, 0x6c, 0x65, 0x72, 0x69, 0x73, 0x71, 0x75, 0x65, 0x20, 0x66, 0x65, 0x6c, 0x69, 0x73,
            0x20, 0x69, 0x6d, 0x70, 0x65, 0x72, 0x64, 0x69, 0x65, 0x74, 0x20, 0x70, 0x72, 0x6f, 0x69, 0x6e, 0x20, 0x66,
            0x65, 0x72, 0x6d, 0x65, 0x6e, 0x74, 0x75, 0x6d, 0x20, 0x6c, 0x65, 0x6f, 0x2e, 0xc4, 0x40, 0x1c, 0x16, 0xef,
            0x7c, 0x23, 0x7f, 0x05, 0x89, 0x0f, 0xa5, 0xbe, 0x06, 0x92, 0x1b, 0xf6, 0x0c, 0x4c, 0x90, 0xb7, 0x84, 0x1b,
            0x74, 0x7c, 0x87, 0x38, 0xb0, 0x5b, 0x41, 0xe0, 0x94, 0x50, 0x31, 0xc4, 0x66, 0xe8, 0x39, 0x3b, 0xbd, 0xc0,
            0xd9, 0x36, 0x28, 0x03, 0x6c, 0x0b, 0x8c, 0xaf, 0x80, 0x48, 0xd6, 0xc4, 0x3f, 0xf5, 0x15, 0xd2, 0x32, 0x73,
            0x7c, 0xde, 0x33, 0x35, 0xff, 0x9e, 0x0d,
    };
    TEST_ASSERT_EQUAL_INT_MESSAGE(sizeof(expected_message), upp->size, "message length wrong");
    TEST_ASSERT_EQUAL_HEX8_ARRAY_MESSAGE(expected_message, upp->data, upp->size, "message serialization failed");

    // verify message
    ret = ubirch_protocol_verify(upp->data, upp->size, ed25519_verify);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, ret, "message verification failed");

    ubirch_protocol_free(upp);
}

void TestMsgpackMessageSigned() {
    char _key[20], _value[300];
    size_t encoded_size;
    static const time_t timestamp = 1568392345;

    // create a ubirch protocol context
    ubirch_protocol *upp = ubirch_protocol_new(UUID, ed25519_sign);
    TEST_ASSERT_NOT_NULL_MESSAGE(upp, "creating UPP context failed");

    //create a msgpack object
    msgpack_sbuffer sbuf; /* buffer */
    msgpack_packer pk;    /* packer */

    msgpack_sbuffer_init(&sbuf); /* initialize buffer */
    msgpack_packer_init(&pk, &sbuf, msgpack_sbuffer_write); /* initialize packer */

    //dummy map with 3 key-value-pairs
    msgpack_pack_map(&pk, 3);

    // 1 - UUID
    msgpack_pack_str(&pk, strlen("uuid"));
    msgpack_pack_str_body(&pk, "uuid", strlen("uuid"));
    msgpack_pack_bin(&pk, UBIRCH_PROTOCOL_UUID_SIZE);
    msgpack_pack_bin_body(&pk, UUID, UBIRCH_PROTOCOL_UUID_SIZE);

    // 2 - timestamp
    msgpack_pack_str(&pk, strlen("time"));
    msgpack_pack_str_body(&pk, "time", strlen("time"));
    msgpack_pack_uint32(&pk, timestamp);

    // 3 - dummy data array
    msgpack_pack_str(&pk, strlen("data"));
    msgpack_pack_str_body(&pk, "data", strlen("data"));
    msgpack_pack_array(&pk, 3);
    msgpack_pack_uint8(&pk, 42);
    msgpack_pack_int16(&pk, -21);
    msgpack_pack_float(&pk, 84.125);

    // pack message
    int8_t ret = ubirch_protocol_message(upp, proto_signed, UBIRCH_PROTOCOL_TYPE_MSGPACK, sbuf.data, sbuf.size);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, ret, "packing UPP failed");

    // verify message
    ret = ubirch_protocol_verify(upp->data, upp->size, ed25519_verify);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, ret, "message verification failed");

    // send message to host
    memset(_value, 0, sizeof(_value));
    int encode_error = mbedtls_base64_encode((unsigned char *) _value, sizeof(_value), &encoded_size,
                                             (unsigned char *) upp->data, upp->size);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, encode_error, "mbedtls_base64_encode returned error");;
    greentea_send_kv("checkMessage", _value, encoded_size);

    ubirch_protocol_free(upp);

    // check if host could verify signature and was able to unpack UPP correctly
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
            Case("ubirch protocol [signed] new upp context",
                 TestProtocolNewSigned, greentea_case_failure_abort_handler),
            Case("ubirch protocol [signed] pack message",
                 TestProtocolMessageSigned, greentea_case_failure_abort_handler),
            Case("ubirch protocol [signed] verify",
                 TestProtocolVerifySigned, greentea_case_failure_abort_handler),
            Case("ubirch protocol [signed] simple message",
                 TestSimpleMessageSigned, greentea_case_failure_abort_handler),
            Case("ubirch protocol [signed] long message",
                 TestProtocolLongMessageSigned, greentea_case_failure_abort_handler),
            Case("ubirch protocol [signed] msgpack message",
                 TestMsgpackMessageSigned, greentea_case_failure_abort_handler),
    };

    Specification specification(greentea_test_setup, cases, greentea_test_teardown_handler);
    Harness::run(specification);
}