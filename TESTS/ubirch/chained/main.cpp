#include <unity/unity.h>
#include "ubirch/ubirch_protocol_api.h"
#include <armnacl.h>
#include <mbedtls/base64.h>
#include <ubirch_ed25519.h>

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

void TestProtocolSimpleAPIMessageFinish() {

    ubirch_protocol *upp = ubirch_protocol_new(ed25519_sign);
    TEST_ASSERT_NOT_NULL_MESSAGE(upp, "creating UPP failed");

    const unsigned char msg[] = {0x09, 0xC2};
    int8_t ret = ubirch_protocol_message(upp, proto_chained, UUID, UBIRCH_PROTOCOL_TYPE_BIN, msg, sizeof(msg));
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, ret, "packing failed");

    const unsigned char expected_message[] = {
            0x96, 0x23, 0xc4, 0x10, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e,
            0x6f, 0x70, 0xc4, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc4, 0x02, 0x09,
            0xc2, 0xc4, 0x40, 0x0b, 0xac, 0x97, 0xb9, 0x00, 0xe8, 0x97, 0x2a, 0xc3, 0x5b, 0x4d, 0xde, 0x59, 0x5b, 0xd3,
            0x6d, 0x37, 0x32, 0x23, 0x1e, 0xbe, 0x79, 0x5d, 0x8a, 0x94, 0x34, 0xc5, 0xba, 0xe7, 0x5d, 0x19, 0xea, 0x86,
            0xba, 0xed, 0x3f, 0x33, 0x8a, 0xe1, 0x6e, 0x6c, 0x6c, 0xd9, 0xb9, 0x70, 0x44, 0xae, 0x81, 0x33, 0x25, 0x25,
            0xc6, 0x9c, 0xde, 0x96, 0x48, 0x2c, 0xa9, 0x75, 0x9a, 0x31, 0x31, 0x93, 0x02,

    };
    TEST_ASSERT_EQUAL_INT_MESSAGE(sizeof(expected_message), upp->size, "message length wrong");
    TEST_ASSERT_EQUAL_HEX8_ARRAY_MESSAGE(expected_message, upp->data, upp->size, "message serialization failed");

    ubirch_protocol_free(upp);
}

void TestSimpleAPISimpleMessage() {
    char _key[20], _value[300];
    size_t encoded_size;

    memset(_value, 0, sizeof(_value));
    mbedtls_base64_encode((unsigned char *) _value, sizeof(_value), &encoded_size,
                          ed25519_public_key, crypto_sign_PUBLICKEYBYTES);
    greentea_send_kv("publicKey", _value);

    ubirch_protocol *upp = ubirch_protocol_new(ed25519_sign);
    TEST_ASSERT_NOT_NULL_MESSAGE(upp, "creating UPP failed");

    const unsigned char msg[] = {0x09, 0xC2};
    int8_t ret = ubirch_protocol_message(upp, proto_chained, UUID, UBIRCH_PROTOCOL_TYPE_BIN, msg, sizeof(msg));
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, ret, "packing failed");

    memset(_value, 0, sizeof(_value));
    mbedtls_base64_encode((unsigned char *) _value, sizeof(_value), &encoded_size,
                          (unsigned char *) upp->data, upp->size);
    greentea_send_kv("checkMessage", _value, encoded_size);

    ubirch_protocol_free(upp);

    greentea_parse_kv(_key, _value, sizeof(_key), sizeof(_value));
    TEST_ASSERT_EQUAL_STRING_MESSAGE("verify", _key, "signature verification failed");
    TEST_ASSERT_EQUAL_STRING_MESSAGE("3", _value, "chained protocol variant failed");
}

void TestSimpleAPIChainedMessage() {
    char _key[20], _value[300], _value_in[300];
    size_t encoded_size;
    int8_t ret = 0;

    memset(_value, 0, sizeof(_value));
    mbedtls_base64_encode((unsigned char *) _value, sizeof(_value), &encoded_size,
                          ed25519_public_key, crypto_sign_PUBLICKEYBYTES);
    greentea_send_kv("publicKey", _value);

    ubirch_protocol *upp = ubirch_protocol_new(ed25519_sign);
    TEST_ASSERT_NOT_NULL_MESSAGE(upp, "creating UPP failed");

    const char *message1 = "message 1";
    ret = ubirch_protocol_message(upp, proto_chained, UUID, UBIRCH_PROTOCOL_TYPE_BIN,
                                  reinterpret_cast<const unsigned char *> (message1), strlen(message1));
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, ret, "packing failed");

    memset(_value, 0, sizeof(_value));
    mbedtls_base64_encode((unsigned char *) _value, sizeof(_value), &encoded_size,
                          (unsigned char *) upp->data, upp->size);
    greentea_send_kv("checkMessage", _value, encoded_size);

    greentea_parse_kv(_key, _value_in, sizeof(_key), sizeof(_value_in));
    TEST_ASSERT_EQUAL_STRING_MESSAGE("verify", _key, "signature verification failed");
    TEST_ASSERT_EQUAL_STRING_MESSAGE("3", _value_in, "chained protocol variant failed");

    greentea_send_kv("checkPayload", _value, encoded_size);

    greentea_parse_kv(_key, _value_in, sizeof(_key), sizeof(_value_in));
    TEST_ASSERT_EQUAL_STRING_MESSAGE(message1, _value_in, "payload comparison failed");


    const char *message2 = "message 2 (is a bit longer)";
    ret = ubirch_protocol_message(upp, proto_chained, UUID, UBIRCH_PROTOCOL_TYPE_BIN,
                                  reinterpret_cast<const unsigned char *> (message2), strlen(message2));
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, ret, "packing failed");

    memset(_value, 0, sizeof(_value));
    mbedtls_base64_encode((unsigned char *) _value, sizeof(_value), &encoded_size,
                          (unsigned char *) upp->data, upp->size);
    greentea_send_kv("checkMessage", _value, encoded_size);

    greentea_parse_kv(_key, _value_in, sizeof(_key), sizeof(_value_in));
    TEST_ASSERT_EQUAL_STRING_MESSAGE("verify", _key, "signature verification failed");
    TEST_ASSERT_EQUAL_STRING_MESSAGE("3", _value_in, "chained protocol variant failed");

    greentea_send_kv("checkPayload", _value, encoded_size);

    greentea_parse_kv(_key, _value_in, sizeof(_key), sizeof(_value_in));
    TEST_ASSERT_EQUAL_STRING_MESSAGE(message2, _value_in, "payload comparison failed");


    const char *message3 = "msg3";
    ret = ubirch_protocol_message(upp, proto_chained, UUID, UBIRCH_PROTOCOL_TYPE_BIN,
                                  reinterpret_cast<const unsigned char *> (message3), strlen(message3));
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, ret, "packing failed");

    memset(_value, 0, sizeof(_value));
    mbedtls_base64_encode((unsigned char *) _value, sizeof(_value), &encoded_size,
                          (unsigned char *) upp->data, upp->size);
    greentea_send_kv("checkMessage", _value, encoded_size);

    greentea_parse_kv(_key, _value_in, sizeof(_key), sizeof(_value_in));
    TEST_ASSERT_EQUAL_STRING_MESSAGE("verify", _key, "signature verification failed");
    TEST_ASSERT_EQUAL_STRING_MESSAGE("3", _value_in, "chained protocol variant failed");

    greentea_send_kv("checkPayload", _value, encoded_size);

    greentea_parse_kv(_key, _value_in, sizeof(_key), sizeof(_value_in));
    TEST_ASSERT_EQUAL_STRING_MESSAGE(message3, _value_in, "payload comparison failed");

    ubirch_protocol_free(upp);
}

void TestSimpleAPIChainedStaticMessage() {
    char _key[20], _value[300], _value_in[300];
    size_t encoded_size;
    int8_t ret = 0;
    const char *staticValue = "STATIC";

    memset(_value, 0, sizeof(_value));
    mbedtls_base64_encode((unsigned char *) _value, sizeof(_value), &encoded_size,
                          ed25519_public_key, crypto_sign_PUBLICKEYBYTES);
    greentea_send_kv("publicKey", _value);

    ubirch_protocol *upp = ubirch_protocol_new(ed25519_sign);
    TEST_ASSERT_NOT_NULL_MESSAGE(upp, "creating UPP failed");

    for (int i = 0; i < 5; i++) {
        ret = ubirch_protocol_message(upp, proto_chained, UUID, UBIRCH_PROTOCOL_TYPE_BIN,
                                      reinterpret_cast<const unsigned char *> (staticValue), strlen(staticValue));
        TEST_ASSERT_EQUAL_INT_MESSAGE(0, ret, "packing failed");

        // verify message
        TEST_ASSERT_EQUAL_INT_MESSAGE(0, ubirch_protocol_verify(upp->data, upp->size, ed25519_verify),
                                      "message verification failed");

        memset(_value, 0, sizeof(_value));
        mbedtls_base64_encode((unsigned char *) _value, sizeof(_value), &encoded_size,
                              (unsigned char *) upp->data, upp->size);
        greentea_send_kv("checkMessage", _value, encoded_size);

        greentea_parse_kv(_key, _value_in, sizeof(_key), sizeof(_value_in));
        TEST_ASSERT_EQUAL_STRING_MESSAGE("verify", _key, "signature verification failed");
        TEST_ASSERT_EQUAL_STRING_MESSAGE("3", _value_in, "chained protocol variant failed");

        greentea_send_kv("checkPayload", _value, encoded_size);

        greentea_parse_kv(_key, _value_in, sizeof(_key), sizeof(_value_in));
        TEST_ASSERT_EQUAL_STRING_MESSAGE(staticValue, _value_in, "payload comparison failed");
    }

    ubirch_protocol_free(upp);
}


utest::v1::status_t greentea_test_setup(const size_t number_of_cases) {
    GREENTEA_SETUP(600, "ProtocolTests");
    return greentea_test_setup_handler(number_of_cases);
}


int main() {
    Case cases[] = {
            Case("ubirch protocol simple API [chained] message finish",
                 TestProtocolSimpleAPIMessageFinish, greentea_case_failure_abort_handler),
            Case("ubirch protocol simple API [chained] message simple",
                 TestSimpleAPISimpleMessage, greentea_case_failure_abort_handler),
            Case("ubirch protocol simple API [chained] message chained",
                 TestSimpleAPIChainedMessage, greentea_case_failure_abort_handler),
            Case("ubirch protocol simple API [chained] message chained static",
                 TestSimpleAPIChainedStaticMessage, greentea_case_failure_abort_handler),
    };

    Specification specification(greentea_test_setup, cases, greentea_test_teardown_handler);
    Harness::run(specification);
}