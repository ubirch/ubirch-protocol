#include <unity/unity.h>
#include <ubirch/ubirch_protocol.h>
#include <armnacl.h>
#include <mbedtls/base64.h>
#include <mbedtls/sha256.h>

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

int ed25519_sign(const char *buf, size_t len, unsigned char signature[crypto_sign_BYTES]) {
    crypto_uint16 signedLength;
    unsigned char *signedMessage = new unsigned char[crypto_sign_BYTES + 32];
    crypto_sign(signedMessage, &signedLength, (const unsigned char *) buf, (crypto_uint16) len, private_key);
    memcpy(signature, signedMessage, crypto_sign_BYTES);
    free(signedMessage);
    return 0;
}

void TestProtocolInit() {
    char dummybuffer[10];
    ubirch_protocol proto = {};
    ubirch_protocol_init(&proto, proto_chained, dummybuffer, msgpack_sbuffer_write, ed25519_sign, UUID);

    TEST_ASSERT_EQUAL_PTR(dummybuffer, proto.packer.data);
    TEST_ASSERT_EQUAL_PTR(msgpack_sbuffer_write, proto.packer.callback);
    TEST_ASSERT_EQUAL_HEX16(proto_chained, proto.version);
    TEST_ASSERT_EQUAL_PTR(ed25519_sign, proto.sign);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(UUID, proto.uuid, 16);
}

void TestProtocolNew() {
    char dummybuffer[10];
    ubirch_protocol *proto = ubirch_protocol_new(proto_chained, dummybuffer, msgpack_sbuffer_write, ed25519_sign, UUID);

    TEST_ASSERT_EQUAL_PTR(dummybuffer, proto->packer.data);
    TEST_ASSERT_EQUAL_PTR(msgpack_sbuffer_write, proto->packer.callback);
    TEST_ASSERT_EQUAL_HEX16(proto_chained, proto->version);
    TEST_ASSERT_EQUAL_PTR(ed25519_sign, proto->sign);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(proto->uuid, UUID, 16);

    ubirch_protocol_free(proto);
}

void TestProtocolWrite() {
    msgpack_sbuffer *sbuf = msgpack_sbuffer_new();
    ubirch_protocol *proto = ubirch_protocol_new(proto_chained, sbuf, msgpack_sbuffer_write, ed25519_sign, UUID);
    msgpack_packer *pk = msgpack_packer_new(proto, ubirch_protocol_write);

    // intialize the protocol hash manually
    mbedtls_sha256_init(&proto->hash);
    mbedtls_sha256_starts(&proto->hash, 0);

    // pack a random (sort of) number
    msgpack_pack_int(pk, 2489);

    unsigned char expected_data[] = {0xcd, 0x09, 0xb9};
    TEST_ASSERT_EQUAL_INT_MESSAGE(sizeof(expected_data), sbuf->size, "written data does not match");
    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected_data, sbuf->data, sizeof(expected_data));

    unsigned char sha256sum[32];
    mbedtls_sha256_finish(&proto->hash, sha256sum);
    unsigned char expected_hash[32] = {
            0x98, 0x72, 0x2d, 0x21, 0x12, 0x3d, 0xf3, 0xc2,
            0xd2, 0xfb, 0x68, 0xf3, 0xc8, 0xd2, 0x3d, 0xec,
            0xfe, 0x5f, 0x8b, 0x94, 0x19, 0x9f, 0x48, 0x6f,
            0x63, 0x76, 0x6a, 0x17, 0x3d, 0x55, 0x4e, 0x93,
    };
    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected_hash, sha256sum, sizeof(sha256sum));

    msgpack_packer_free(pk);
    ubirch_protocol_free(proto);
}

void TestProtocolMessageStart() {
    msgpack_sbuffer *sbuf = msgpack_sbuffer_new();
    ubirch_protocol *proto = ubirch_protocol_new(proto_chained, sbuf, msgpack_sbuffer_write, ed25519_sign, UUID);
    msgpack_packer *pk = msgpack_packer_new(proto, ubirch_protocol_write);

    ubirch_protocol_start(proto, pk);

    TEST_ASSERT_EQUAL_INT_MESSAGE(0, proto->hash.is224, "SHA256 initialization failed");
    TEST_ASSERT_EQUAL_INT_MESSAGE(88, sbuf->size, "header size wrong");
    TEST_ASSERT_EQUAL_HEX_MESSAGE(0x95, sbuf->data[0], "msgpack format wrong (expected 5-array)");

    const unsigned char expected_version[3] = {
            0xcd, 0, UBIRCH_PROTOCOL_VERSION << 4 | UBIRCH_PROTOCOL_CHAINED
    };
    TEST_ASSERT_EQUAL_HEX8_ARRAY_MESSAGE(expected_version, sbuf->data + 1, 3, "protocol version wrong");
    const unsigned char expected_uuid[16] = {
            0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68,
            0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70,
    };
    TEST_ASSERT_EQUAL_HEX_MESSAGE(0xb0, sbuf->data[4], "message uuid marker wrong");
    TEST_ASSERT_EQUAL_HEX8_ARRAY_MESSAGE(expected_uuid, sbuf->data + 5, 16, "message uuid wrong");
    const unsigned char expected_prev_sig_marker[3] = {0xda, 0x00, 0x40};
    TEST_ASSERT_EQUAL_HEX8_ARRAY_MESSAGE(expected_prev_sig_marker, sbuf->data + 21, 3, "prev signature marker wrong");
    const unsigned char expected_prev_signature[64] = {};
    memset((void *) expected_prev_signature, 0, 64);
    TEST_ASSERT_EQUAL_HEX8_ARRAY_MESSAGE(expected_prev_signature, sbuf->data + 24, 64, "prev signature not 0");

    unsigned char sha256sum[32];
    mbedtls_sha256_finish(&proto->hash, sha256sum);
    unsigned char expected_hash[32] = {
            0x2f, 0xe5, 0x92, 0x3e, 0xca, 0xb7, 0x26, 0xd0,
            0x34, 0x4e, 0x80, 0xec, 0xb7, 0x49, 0x99, 0x74,
            0xac, 0x88, 0xb0, 0xfe, 0x27, 0x8c, 0x51, 0x98,
            0xaa, 0x38, 0x05, 0x83, 0x69, 0x4d, 0x54, 0x7d,
    };
    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected_hash, sha256sum, sizeof(sha256sum));

    msgpack_packer_free(pk);
    ubirch_protocol_free(proto);
}

void TestProtocolMessageFinishWithoutStart() {
    msgpack_sbuffer *sbuf = msgpack_sbuffer_new();
    ubirch_protocol *proto = ubirch_protocol_new(proto_chained, sbuf, msgpack_sbuffer_write, ed25519_sign, UUID);
    msgpack_packer *pk = msgpack_packer_new(proto, ubirch_protocol_write);

    // add some dummy data without start
    msgpack_pack_int(pk, 2498);

    int finish_ok = ubirch_protocol_finish(proto, pk);
    TEST_ASSERT_EQUAL_INT_MESSAGE(-2, finish_ok, "message finish without start must fail");

    msgpack_packer_free(pk);
    ubirch_protocol_free(proto);
}

void TestProtocolMessageFinish() {
    msgpack_sbuffer *sbuf = msgpack_sbuffer_new();
    ubirch_protocol *proto = ubirch_protocol_new(proto_chained, sbuf, msgpack_sbuffer_write, ed25519_sign, UUID);
    msgpack_packer *pk = msgpack_packer_new(proto, ubirch_protocol_write);

    ubirch_protocol_start(proto, pk);
    msgpack_pack_int(pk, 2498);
    int finish_ok = ubirch_protocol_finish(proto, pk);

    TEST_ASSERT_EQUAL_INT_MESSAGE(0, finish_ok, "message finish failed");
    TEST_ASSERT_EQUAL_INT_MESSAGE(158, sbuf->size, "message length wrong");

    const unsigned char expected_message[158] = {
            0x95, 0xcd, 0x00, 0x13, 0xb0, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d,
            0x6e, 0x6f, 0x70, 0xda, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xcd, 0x09,
            0xc2, 0xda, 0x00, 0x40, 0x71, 0xb6, 0x18, 0xed, 0x6b, 0x28, 0x9f, 0x0b, 0x42, 0x6c, 0x19, 0xaa, 0xb2, 0xf4,
            0x53, 0x01, 0x99, 0xf4, 0x86, 0x2d, 0xee, 0xc2, 0xb2, 0xcf, 0xa0, 0x86, 0x31, 0xdd, 0x59, 0xa4, 0xff, 0x78,
            0x4f, 0x89, 0x11, 0xb0, 0xeb, 0x8e, 0x10, 0x1d, 0xcd, 0xe8, 0xc5, 0x82, 0x4a, 0x17, 0x97, 0x10, 0x1a, 0x6e,
            0x9b, 0xdf, 0x5a, 0x8b, 0x3a, 0x24, 0x74, 0x25, 0x80, 0x94, 0x00, 0x95, 0x02, 0x04,
    };

    TEST_ASSERT_EQUAL_HEX8_ARRAY_MESSAGE(expected_message, sbuf->data, sbuf->size, "message serialization failed");

    msgpack_packer_free(pk);
    ubirch_protocol_free(proto);
}

void TestSimpleMessage() {
    char _key[20], _value[300];
    size_t encoded_size;

    memset(_value, 0, sizeof(_value));
    mbedtls_base64_encode((unsigned char *) _value, sizeof(_value), &encoded_size, public_key,
                          crypto_sign_PUBLICKEYBYTES);
    greentea_send_kv("publicKey", _value);

    msgpack_sbuffer *sbuf = msgpack_sbuffer_new();
    ubirch_protocol *proto = ubirch_protocol_new(proto_chained, sbuf, msgpack_sbuffer_write, ed25519_sign, UUID);
    msgpack_packer *pk = msgpack_packer_new(proto, ubirch_protocol_write);

    ubirch_protocol_start(proto, pk);
    msgpack_pack_int(pk, 99);
    ubirch_protocol_finish(proto, pk);

    memset(_value, 0, sizeof(_value));
    mbedtls_base64_encode((unsigned char *) _value, sizeof(_value), &encoded_size,
                          (unsigned char *) sbuf->data, sbuf->size);
    greentea_send_kv("checkMessage", _value, encoded_size);

    msgpack_packer_free(pk);
    ubirch_protocol_free(proto);

    greentea_parse_kv(_key, _value, sizeof(_key), sizeof(_value));
    TEST_ASSERT_EQUAL_STRING_MESSAGE("verify", _key, "signature verification failed");
}

void TestChainedMessage() {
    char _key[20], _value[300];
    size_t encoded_size;

    memset(_value, 0, sizeof(_value));
    mbedtls_base64_encode((unsigned char *) _value, sizeof(_value), &encoded_size, public_key,
                          crypto_sign_PUBLICKEYBYTES);
    greentea_send_kv("publicKey", _value);

    msgpack_sbuffer *sbuf = msgpack_sbuffer_new();
    ubirch_protocol *proto = ubirch_protocol_new(proto_chained, sbuf, msgpack_sbuffer_write, ed25519_sign, UUID);
    msgpack_packer *pk = msgpack_packer_new(proto, ubirch_protocol_write);

    const char *message1 = "message 1";
    ubirch_protocol_start(proto, pk);
    msgpack_pack_raw(pk, strlen(message1));
    msgpack_pack_raw_body(pk, message1, strlen(message1));
    ubirch_protocol_finish(proto, pk);

    memset(_value, 0, sizeof(_value));
    mbedtls_base64_encode((unsigned char *) _value, sizeof(_value), &encoded_size,
                          (unsigned char *) sbuf->data, sbuf->size);
    greentea_send_kv("checkMessage", _value, encoded_size);

    greentea_parse_kv(_key, _value, sizeof(_key), sizeof(_value));
    TEST_ASSERT_EQUAL_STRING_MESSAGE("verify", _key, "signature verification failed");

    // clear buffer for next message
    msgpack_sbuffer_clear(sbuf);

    const char *message2 = "message 2";
    ubirch_protocol_start(proto, pk);
    msgpack_pack_raw(pk, strlen(message2));
    msgpack_pack_raw_body(pk, message2, strlen(message2));
    ubirch_protocol_finish(proto, pk);

    memset(_value, 0, sizeof(_value));
    mbedtls_base64_encode((unsigned char *) _value, sizeof(_value), &encoded_size,
                          (unsigned char *) sbuf->data, sbuf->size);
    greentea_send_kv("checkMessage", _value, encoded_size);

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
            Case("ubirch protocol init", TestProtocolInit, greentea_case_failure_abort_handler),
            Case("ubirch protocol new", TestProtocolNew, greentea_case_failure_abort_handler),
            Case("ubirch protocol write", TestProtocolWrite, greentea_case_failure_abort_handler),
            Case("ubirch protocol message simple", TestSimpleMessage, greentea_case_failure_abort_handler),
            Case("ubirch protocol message chained", TestChainedMessage, greentea_case_failure_abort_handler),
            Case("ubirch protocol message start", TestProtocolMessageStart, greentea_case_failure_abort_handler),
            Case("ubirch protocol message finish (fails)", TestProtocolMessageFinishWithoutStart,
                 greentea_case_failure_abort_handler),
            Case("ubirch protocol message finish", TestProtocolMessageFinish, greentea_case_failure_abort_handler),
    };

    Specification specification(greentea_test_setup, cases, greentea_test_teardown_handler);
    Harness::run(specification);
}