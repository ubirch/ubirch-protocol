#include <unity/unity.h>
#include "ubirch/ubirch_protocol_api.h"
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

void TestSimpleAPIVerifyMessage() {
    // create a new message a sign it
    const unsigned char msg[] = {99};

    ubirch_protocol *upp = ubirch_protocol_new(ed25519_sign);
    TEST_ASSERT_NOT_NULL_MESSAGE(upp, "creating UPP failed");

    int8_t ret = ubirch_protocol_message(upp, proto_signed, UUID, UBIRCH_PROTOCOL_TYPE_BIN, msg, sizeof(msg));
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, ret, "packing failed");

    // verify message
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, ubirch_protocol_verify(upp->data, upp->size, ed25519_verify),
                                  "message verification failed");

    ubirch_protocol_free(upp);
}

void TestSimpleAPISimpleMessage() {
    char _key[20], _value[300];
    size_t encoded_size;

    memset(_value, 0, sizeof(_value));
    mbedtls_base64_encode((unsigned char *) _value, sizeof(_value), &encoded_size, ed25519_public_key,
                          crypto_sign_PUBLICKEYBYTES);
    greentea_send_kv("publicKey", _value);

    const unsigned char msg[] = {0x09, 0xC2};

    ubirch_protocol *upp = ubirch_protocol_new(ed25519_sign);
    TEST_ASSERT_NOT_NULL_MESSAGE(upp, "creating UPP failed");

    int8_t ret = ubirch_protocol_message(upp, proto_signed, UUID, UBIRCH_PROTOCOL_TYPE_BIN, msg, sizeof(msg));
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, ret, "packing failed");

    memset(_value, 0, sizeof(_value));
    mbedtls_base64_encode((unsigned char *) _value, sizeof(_value), &encoded_size,
                          (unsigned char *) upp->data, upp->size);
    greentea_send_kv("checkMessage", _value, encoded_size);

    greentea_parse_kv(_key, _value, sizeof(_key), sizeof(_value));
    TEST_ASSERT_EQUAL_STRING_MESSAGE("verify", _key, "signature verification failed");
    TEST_ASSERT_EQUAL_STRING_MESSAGE("2", _value, "signed protocol variant failed");

    // verify message
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, ubirch_protocol_verify(upp->data, upp->size, ed25519_verify),
                                  "message verification failed");

    ubirch_protocol_free(upp);
}

void TestProtocolSimpleAPIMessageFinish() {
    const unsigned char msg[] = {0x09, 0xC2};

    ubirch_protocol *upp = ubirch_protocol_new(ed25519_sign);
    TEST_ASSERT_NOT_NULL_MESSAGE(upp, "creating UPP failed");

    int8_t ret = ubirch_protocol_message(upp, proto_signed, UUID, UBIRCH_PROTOCOL_TYPE_BIN, msg, sizeof(msg));
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, ret, "packing failed");

    const unsigned char expected_message[] = {
            0x95, 0x22, 0xc4, 0x10, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e,
            0x6f, 0x70, 0x00, 0xc4, 0x02, 0x09, 0xc2, 0xc4, 0x40, 0x1f, 0x89, 0xd7, 0x0c, 0x9f, 0xa1, 0xc5, 0x7c, 0x80,
            0x22, 0x7b, 0x85, 0x18, 0xde, 0x06, 0x37, 0x03, 0x9b, 0xe4, 0xa5, 0x38, 0xb7, 0x47, 0xbf, 0xb8, 0xec, 0x96,
            0xd8, 0xc5, 0x45, 0xad, 0x2c, 0xae, 0x07, 0xc1, 0xfb, 0x88, 0xc6, 0x92, 0x97, 0x49, 0x0c, 0x72, 0xf9, 0x0a,
            0x25, 0x2c, 0x6c, 0xb6, 0x2c, 0x64, 0x53, 0xa2, 0xd1, 0x83, 0x54, 0x83, 0x5f, 0x38, 0xef, 0x1d, 0xfb, 0x45,
            0x0e,
    };

    TEST_ASSERT_EQUAL_INT_MESSAGE(sizeof(expected_message), upp->size, "message length wrong");
    TEST_ASSERT_EQUAL_HEX8_ARRAY_MESSAGE(expected_message, upp->data, upp->size, "message serialization failed");

    // verify message
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, ubirch_protocol_verify(upp->data, upp->size, ed25519_verify),
                                  "message verification failed");

    ubirch_protocol_free(upp);
}

utest::v1::status_t greentea_test_setup(const size_t number_of_cases) {
    GREENTEA_SETUP(600, "ProtocolTests");
    return greentea_test_setup_handler(number_of_cases);
}


int main() {
    Case cases[] = {
            Case("ubirch protocol simple API [signed] message signed",
                 TestSimpleAPISimpleMessage, greentea_case_failure_abort_handler),
            Case("ubirch protocol simple API [signed] message verify",
                 TestSimpleAPIVerifyMessage, greentea_case_failure_abort_handler),
            Case("ubirch protocol simple API [signed] message finish",
                 TestProtocolSimpleAPIMessageFinish, greentea_case_failure_abort_handler),
    };

    Specification specification(greentea_test_setup, cases, greentea_test_teardown_handler);
    Harness::run(specification);
}