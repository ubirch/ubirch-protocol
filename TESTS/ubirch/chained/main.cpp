#include <unity/unity.h>
#include "ubirch/ubirch_protocol.h"
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

void TestProtocolMessageChained() {
    const char msg[] = {0x24, 0x98, 0x3f, 0xff, 0xf3, 0x89, 0x42};
    const char expected_message[] = {
            0x96, 0x23, 0xc4, 0x10, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e,
            0x6f, 0x70, 0xc4, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc4, 0x07, 0x24,
            0x98, 0x3f, 0xff, 0xf3, 0x89, 0x42, 0xc4, 0x40, 0xde, 0x3f, 0x28, 0x00, 0x7a, 0xbb, 0xc9, 0x0a, 0x53, 0xbf,
            0xb3, 0x29, 0x9c, 0x6e, 0x81, 0xa6, 0xd0, 0x6a, 0xe2, 0x99, 0x63, 0x8f, 0x0c, 0xe1, 0xe7, 0x8b, 0x9e, 0x7f,
            0x62, 0xce, 0x07, 0x6d, 0xdc, 0xaf, 0x3b, 0xd4, 0xd2, 0x32, 0xc7, 0x49, 0x63, 0xdf, 0xe2, 0x15, 0xd5, 0x0f,
            0x2a, 0xe0, 0x6f, 0x11, 0x54, 0x70, 0x9c, 0xd5, 0x44, 0x1b, 0xf2, 0x3b, 0x63, 0x42, 0x7e, 0x2b, 0x52, 0x0b,
    };

    ubirch_protocol *upp = ubirch_protocol_new(UUID, ed25519_sign);
    TEST_ASSERT_NOT_NULL_MESSAGE(upp, "creating UPP context failed");

    int8_t ret = ubirch_protocol_message(upp, proto_chained, UBIRCH_PROTOCOL_TYPE_BIN, msg, sizeof(msg));
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, ret, "packing UPP failed");
    TEST_ASSERT_EQUAL_INT_MESSAGE(sizeof(expected_message), upp->size, "message length wrong");
    TEST_ASSERT_EQUAL_HEX8_ARRAY_MESSAGE(expected_message, upp->data, upp->size, "message serialization failed");

    ubirch_protocol_free(upp);
}

void TestProtocolVerifyChained() {
    const char msg[] = {0x24, 0x98, 0x3f, 0xff, 0xf3, 0x89, 0x42};

    ubirch_protocol *upp = ubirch_protocol_new(UUID, ed25519_sign);
    TEST_ASSERT_NOT_NULL_MESSAGE(upp, "creating UPP context failed");

    int8_t ret = ubirch_protocol_message(upp, proto_chained, UBIRCH_PROTOCOL_TYPE_BIN, msg, sizeof(msg));
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, ret, "packing UPP failed");

    // verify message
    ret = ubirch_protocol_verify(upp->data, upp->size, ed25519_verify);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, ret, "message verification failed");

    ubirch_protocol_free(upp);
}

void TestSimpleMessageChained() {
    char _key[20], _value[300];
    size_t encoded_size;
    const char *msg = "simple message";

    // create UPP
    ubirch_protocol *upp = ubirch_protocol_new(UUID, ed25519_sign);
    TEST_ASSERT_NOT_NULL_MESSAGE(upp, "creating UPP context failed");

    int8_t ret = ubirch_protocol_message(upp, proto_chained, UBIRCH_PROTOCOL_TYPE_BIN, msg, strlen(msg));
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
    TEST_ASSERT_EQUAL_STRING_MESSAGE("3", _value, "protocol variant check failed");

    greentea_parse_kv(_key, _value, sizeof(_key), sizeof(_value));
    TEST_ASSERT_EQUAL_STRING_MESSAGE("uuid", _key, "unexpected key");
    TEST_ASSERT_EQUAL_HEX8_ARRAY_MESSAGE(UUID, _value, UBIRCH_PROTOCOL_UUID_SIZE, "UUID check failed");

    greentea_parse_kv(_key, _value, sizeof(_key), sizeof(_value));
    TEST_ASSERT_EQUAL_STRING_MESSAGE("payload", _key, "unexpected key");
    TEST_ASSERT_EQUAL_STRING_MESSAGE(msg, _value, "payload check failed");
}

void TestChainedMessages() {
    char _key[20], _value[300];
    size_t encoded_size;
    int8_t ret = 0;
    int encode_error = 0;
    unsigned char last_signature[UBIRCH_PROTOCOL_SIGN_SIZE] = {0};

    // register public key with host
    memset(_value, 0, sizeof(_value));
    mbedtls_base64_encode((unsigned char *) _value, sizeof(_value), &encoded_size, ed25519_public_key,
                          crypto_sign_PUBLICKEYBYTES);
    greentea_send_kv("publicKey", _value);

    // create UPP
    ubirch_protocol *upp = ubirch_protocol_new(UUID, ed25519_sign);
    TEST_ASSERT_NOT_NULL_MESSAGE(upp, "creating UPP context failed");

    const char *message1 = "message 1";
    ret = ubirch_protocol_message(upp, proto_chained, UBIRCH_PROTOCOL_TYPE_BIN, message1, strlen(message1));
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, ret, "packing UPP failed");

    // check last signature
    TEST_ASSERT_EQUAL_HEX8_ARRAY_MESSAGE(last_signature, upp->data + 22, UBIRCH_PROTOCOL_SIGN_SIZE,
                                         "last signature check failed");

    // send message to host
    memset(_value, 0, sizeof(_value));
    encode_error = mbedtls_base64_encode((unsigned char *) _value, sizeof(_value), &encoded_size,
                                         (unsigned char *) upp->data, upp->size);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, encode_error, "mbedtls_base64_encode returned error");;
    greentea_send_kv("checkMessage", _value, encoded_size);

    // check if host could verify signature and was able to unpack UPP correctly
    greentea_parse_kv(_key, _value, sizeof(_key), sizeof(_value));
    TEST_ASSERT_EQUAL_STRING_MESSAGE("variant", _key, "message verification failed");
    TEST_ASSERT_EQUAL_STRING_MESSAGE("3", _value, "protocol variant check failed");

    greentea_parse_kv(_key, _value, sizeof(_key), sizeof(_value));
    TEST_ASSERT_EQUAL_STRING_MESSAGE("uuid", _key, "unexpected key");
    TEST_ASSERT_EQUAL_HEX8_ARRAY_MESSAGE(UUID, _value, UBIRCH_PROTOCOL_UUID_SIZE, "UUID check failed");

    greentea_parse_kv(_key, _value, sizeof(_key), sizeof(_value));
    TEST_ASSERT_EQUAL_STRING_MESSAGE("payload", _key, "unexpected key");
    TEST_ASSERT_EQUAL_STRING_MESSAGE(message1, _value, "payload check failed");

    // store signature of last UPP
    memcpy(last_signature, upp->signature, UBIRCH_PROTOCOL_SIGN_SIZE);

    // pack new UPP
    const char *message2 = "message 2 (is a little bit longer)";
    ret = ubirch_protocol_message(upp, proto_chained, UBIRCH_PROTOCOL_TYPE_BIN, message2, strlen(message2));
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, ret, "packing UPP failed");

    // check last signature
    TEST_ASSERT_EQUAL_HEX8_ARRAY_MESSAGE(last_signature, upp->data + 22, UBIRCH_PROTOCOL_SIGN_SIZE,
                                         "last signature check failed");

    // send message to host
    memset(_value, 0, sizeof(_value));
    encode_error = mbedtls_base64_encode((unsigned char *) _value, sizeof(_value), &encoded_size,
                                         (unsigned char *) upp->data, upp->size);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, encode_error, "mbedtls_base64_encode returned error");;
    greentea_send_kv("checkMessage", _value, encoded_size);

    // check if host could verify signature and was able to unpack UPP correctly
    greentea_parse_kv(_key, _value, sizeof(_key), sizeof(_value));
    TEST_ASSERT_EQUAL_STRING_MESSAGE("variant", _key, "message verification failed");
    TEST_ASSERT_EQUAL_STRING_MESSAGE("3", _value, "protocol variant check failed");

    greentea_parse_kv(_key, _value, sizeof(_key), sizeof(_value));
    TEST_ASSERT_EQUAL_STRING_MESSAGE("uuid", _key, "unexpected key");
    TEST_ASSERT_EQUAL_HEX8_ARRAY_MESSAGE(UUID, _value, UBIRCH_PROTOCOL_UUID_SIZE, "UUID check failed");

    greentea_parse_kv(_key, _value, sizeof(_key), sizeof(_value));
    TEST_ASSERT_EQUAL_STRING_MESSAGE("payload", _key, "unexpected key");
    TEST_ASSERT_EQUAL_STRING_MESSAGE(message2, _value, "payload check failed");

    // store signature of last UPP
    memcpy(last_signature, upp->signature, UBIRCH_PROTOCOL_SIGN_SIZE);

    // pack new UPP
    const char *message3 = "msg3";
    ret = ubirch_protocol_message(upp, proto_chained, UBIRCH_PROTOCOL_TYPE_BIN, message3, strlen(message3));
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, ret, "packing UPP failed");

    // check last signature
    TEST_ASSERT_EQUAL_HEX8_ARRAY_MESSAGE(last_signature, upp->data + 22, UBIRCH_PROTOCOL_SIGN_SIZE,
                                         "last signature check failed");

    // send message to host
    memset(_value, 0, sizeof(_value));
    encode_error = mbedtls_base64_encode((unsigned char *) _value, sizeof(_value), &encoded_size,
                                         (unsigned char *) upp->data, upp->size);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, encode_error, "mbedtls_base64_encode returned error");;
    greentea_send_kv("checkMessage", _value, encoded_size);

    // check if host could verify signature and was able to unpack UPP correctly
    greentea_parse_kv(_key, _value, sizeof(_key), sizeof(_value));
    TEST_ASSERT_EQUAL_STRING_MESSAGE("variant", _key, "message verification failed");
    TEST_ASSERT_EQUAL_STRING_MESSAGE("3", _value, "protocol variant check failed");

    greentea_parse_kv(_key, _value, sizeof(_key), sizeof(_value));
    TEST_ASSERT_EQUAL_STRING_MESSAGE("uuid", _key, "unexpected key");
    TEST_ASSERT_EQUAL_HEX8_ARRAY_MESSAGE(UUID, _value, UBIRCH_PROTOCOL_UUID_SIZE, "UUID check failed");

    greentea_parse_kv(_key, _value, sizeof(_key), sizeof(_value));
    TEST_ASSERT_EQUAL_STRING_MESSAGE("payload", _key, "unexpected key");
    TEST_ASSERT_EQUAL_STRING_MESSAGE(message3, _value, "payload check failed");

    ubirch_protocol_free(upp);
}

void TestChainedMessagesStatic() {
    char _key[20], _value[300];
    size_t encoded_size;
    int8_t ret = 0;
    int encode_error = 0;
    const char *staticValue = "STATIC";
    unsigned char last_signature[UBIRCH_PROTOCOL_SIGN_SIZE] = {0};

    // register public key with host
    memset(_value, 0, sizeof(_value));
    mbedtls_base64_encode((unsigned char *) _value, sizeof(_value), &encoded_size,
                          ed25519_public_key, crypto_sign_PUBLICKEYBYTES);
    greentea_send_kv("publicKey", _value);

    // create UPP
    ubirch_protocol *upp = ubirch_protocol_new(UUID, ed25519_sign);
    TEST_ASSERT_NOT_NULL_MESSAGE(upp, "creating UPP context failed");

    for (int i = 0; i < 5; i++) {
        ret = ubirch_protocol_message(upp, proto_chained, UBIRCH_PROTOCOL_TYPE_BIN,
                                      staticValue, strlen(staticValue));
        TEST_ASSERT_EQUAL_INT_MESSAGE(0, ret, "packing UPP failed");

        // verify message
        TEST_ASSERT_EQUAL_INT_MESSAGE(0, ubirch_protocol_verify(upp->data, upp->size, ed25519_verify),
                                      "message verification failed");

        // check last signature
        TEST_ASSERT_EQUAL_HEX8_ARRAY_MESSAGE(last_signature, upp->data + 22, UBIRCH_PROTOCOL_SIGN_SIZE,
                                             "last signature check failed");

        // send message to host
        memset(_value, 0, sizeof(_value));
        encode_error = mbedtls_base64_encode((unsigned char *) _value, sizeof(_value), &encoded_size,
                                             (unsigned char *) upp->data, upp->size);
        TEST_ASSERT_EQUAL_INT_MESSAGE(0, encode_error, "mbedtls_base64_encode returned error");;
        greentea_send_kv("checkMessage", _value, encoded_size);

        // check if host could verify signature and was able to unpack UPP correctly
        greentea_parse_kv(_key, _value, sizeof(_key), sizeof(_value));
        TEST_ASSERT_EQUAL_STRING_MESSAGE("variant", _key, "message verification failed");
        TEST_ASSERT_EQUAL_STRING_MESSAGE("3", _value, "protocol variant check failed");

        greentea_parse_kv(_key, _value, sizeof(_key), sizeof(_value));
        TEST_ASSERT_EQUAL_STRING_MESSAGE("uuid", _key, "unexpected key");
        TEST_ASSERT_EQUAL_HEX8_ARRAY_MESSAGE(UUID, _value, UBIRCH_PROTOCOL_UUID_SIZE, "UUID check failed");

        greentea_parse_kv(_key, _value, sizeof(_key), sizeof(_value));
        TEST_ASSERT_EQUAL_STRING_MESSAGE("payload", _key, "unexpected key");
        TEST_ASSERT_EQUAL_STRING_MESSAGE(staticValue, _value, "payload check failed");

        // store signature of last UPP
        memcpy(last_signature, upp->signature, UBIRCH_PROTOCOL_SIGN_SIZE);
    }

    ubirch_protocol_free(upp);
}


utest::v1::status_t greentea_test_setup(const size_t number_of_cases) {
    GREENTEA_SETUP(600, "ProtocolTests");
    return greentea_test_setup_handler(number_of_cases);
}


int main() {
    Case cases[] = {
            Case("ubirch protocol [chained] pack message",
                 TestProtocolMessageChained, greentea_case_failure_abort_handler),
            Case("ubirch protocol [chained] verify",
                 TestProtocolVerifyChained, greentea_case_failure_abort_handler),
            Case("ubirch protocol [chained] simple message",
                 TestSimpleMessageChained, greentea_case_failure_abort_handler),
            Case("ubirch protocol [chained] chained messages",
                 TestChainedMessages, greentea_case_failure_abort_handler),
            Case("ubirch protocol [chained] chained static messages",
                 TestChainedMessagesStatic, greentea_case_failure_abort_handler),
    };

    Specification specification(greentea_test_setup, cases, greentea_test_teardown_handler);
    Harness::run(specification);
}