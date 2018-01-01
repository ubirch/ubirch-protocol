#include <unity/unity.h>
#include <ubirch/ubirch_protocol.h>
#include <ubirch-mbed-crypto/source/Base64.h>

#include "utest/utest.h"
#include "greentea-client/test_env.h"

static const char UUID[16] = {'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p'};
static const char *const TEST_PAYLOAD = "0123456789";

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

void ed25519_sign(const char *buf, size_t len, unsigned char signature[crypto_sign_BYTES]) {
    crypto_uint16 signedLength;
    unsigned char *signedMessage = new unsigned char[crypto_sign_BYTES + 32];
    crypto_sign(signedMessage, &signedLength, (const unsigned char *) buf, (crypto_uint16) len, private_key);
    memcpy(signature, signedMessage, crypto_sign_BYTES);
    free(signedMessage);
}


void TestSimpleMessage() {
    char _key[20], _value[100];
    Base64 base64;
    size_t encoded_size;

    const char *encoded_pubkey = base64.Encode((const char *) public_key, crypto_sign_PUBLICKEYBYTES, &encoded_size);
    greentea_send_kv("publicKey", encoded_pubkey);

    msgpack_sbuffer *sbuf = msgpack_sbuffer_new();
    ubirch_protocol *proto = ubirch_protocol_new(sbuf, msgpack_sbuffer_write, ed25519_sign,
                                                 (const unsigned char *) UUID);
    msgpack_packer *pk = msgpack_packer_new(proto, ubirch_protocol_write);

    ubirch_protocol_start(proto, pk);
    msgpack_pack_raw(pk, strlen(TEST_PAYLOAD));
    msgpack_pack_raw_body(pk, TEST_PAYLOAD, strlen(TEST_PAYLOAD));
    ubirch_protocol_finish(proto, pk);

    const char *encoded = base64.Encode(sbuf->data, sbuf->size, &encoded_size);
    greentea_send_kv("checkMessage", encoded, encoded_size);

    msgpack_packer_free(pk);
    ubirch_protocol_free(proto);

    greentea_parse_kv(_key, _value, sizeof(_key), sizeof(_value));
    TEST_ASSERT_EQUAL_STRING_MESSAGE("verify", _key, "signature verification failed");
}

void TestChainedMessage() {
    char _key[20], _value[100];
    Base64 base64;
    size_t encoded_size;

    const char *encoded_pubkey = base64.Encode((const char *) public_key, crypto_sign_PUBLICKEYBYTES, &encoded_size);
    greentea_send_kv("publicKey", encoded_pubkey);

    msgpack_sbuffer *sbuf = msgpack_sbuffer_new();
    ubirch_protocol *proto = ubirch_protocol_new(sbuf, msgpack_sbuffer_write, ed25519_sign,
                                                 (const unsigned char *) UUID);
    msgpack_packer *pk = msgpack_packer_new(proto, ubirch_protocol_write);

    ubirch_protocol_start(proto, pk);
    msgpack_pack_raw(pk, strlen(TEST_PAYLOAD));
    msgpack_pack_raw_body(pk, TEST_PAYLOAD, strlen(TEST_PAYLOAD));
    ubirch_protocol_finish(proto, pk);

    char *encoded = base64.Encode(sbuf->data, sbuf->size, &encoded_size);
    greentea_send_kv("checkMessage", encoded, encoded_size);

    greentea_parse_kv(_key, _value, sizeof(_key), sizeof(_value));
    TEST_ASSERT_EQUAL_STRING_MESSAGE("verify", _key, "signature verification failed");

    // clear buffer for next message
    msgpack_sbuffer_clear(sbuf);

    ubirch_protocol_start(proto, pk);
    msgpack_pack_raw(pk, strlen("CHAINED"));
    msgpack_pack_raw_body(pk, "CHAINED", strlen("CHAINED"));
    ubirch_protocol_finish(proto, pk);

    encoded = base64.Encode(sbuf->data, sbuf->size, &encoded_size);
    greentea_send_kv("checkMessage", encoded, encoded_size);

    greentea_parse_kv(_key, _value, sizeof(_key), sizeof(_value));
    TEST_ASSERT_EQUAL_STRING_MESSAGE("verify", _key, "chained signature verification failed");

    msgpack_packer_free(pk);
    ubirch_protocol_free(proto);
}

utest::v1::status_t greentea_test_setup(const size_t number_of_cases) {
    GREENTEA_SETUP(600, "ProtocolTests");
    return greentea_test_setup_handler(number_of_cases);
}


int main() {
    Case cases[] = {
            Case("ubirch protocol simple message", TestSimpleMessage, greentea_case_failure_abort_handler),
            Case("ubirch protocol chained message", TestChainedMessage, greentea_case_failure_abort_handler),
    };

    Specification specification(greentea_test_setup, cases, greentea_test_teardown_handler);
    Harness::run(specification);
}