#include <unity/unity.h>
#include <ubirch/ubirch_protocol.h>
#include <armnacl.h>
#include <mbedtls/base64.h>

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
    unsigned char *signedMessage = new unsigned char[crypto_sign_BYTES + len];
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
    mbedtls_sha512_init(&proto->hash);
    mbedtls_sha512_starts(&proto->hash, 0);

    // pack a random (sort of) number
    msgpack_pack_int(pk, 2489);

    unsigned char expected_data[] = {0xcd, 0x09, 0xb9};
    TEST_ASSERT_EQUAL_INT_MESSAGE(sizeof(expected_data), sbuf->size, "written data does not match");
    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected_data, sbuf->data, sizeof(expected_data));

    unsigned char sha512sum[UBIRCH_PROTOCOL_HASH_SIZE];
    mbedtls_sha512_finish(&proto->hash, sha512sum);
    unsigned char expected_hash[UBIRCH_PROTOCOL_HASH_SIZE] = {
            0x69, 0x70, 0x5a, 0x70, 0x90, 0xd4, 0xbd, 0x2b, 0x17, 0xeb, 0xe3, 0xe5, 0xaa, 0x29, 0x8a, 0x1f, 0x00, 0x64,
            0xc7, 0xee, 0x70, 0xae, 0x22, 0x1a, 0xee, 0x0a, 0x9a, 0xaa, 0xa9, 0x56, 0x28, 0xa8, 0x64, 0x36, 0xc8, 0x59,
            0x20, 0xc6, 0x74, 0x33, 0x24, 0x41, 0x37, 0x3b, 0xba, 0xc7, 0x4a, 0xa3, 0xd7, 0x3e, 0xa6, 0x1c, 0x8c, 0xc4,
            0x11, 0xc9, 0x82, 0x2e, 0x94, 0x03, 0x17, 0x12, 0x3a, 0x4e
    };
    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected_hash, sha512sum, sizeof(sha512sum));

    msgpack_packer_free(pk);
    ubirch_protocol_free(proto);
}

void TestProtocolMessageStart() {
    msgpack_sbuffer *sbuf = msgpack_sbuffer_new();
    ubirch_protocol *proto = ubirch_protocol_new(proto_chained, sbuf, msgpack_sbuffer_write, ed25519_sign, UUID);
    msgpack_packer *pk = msgpack_packer_new(proto, ubirch_protocol_write);

    ubirch_protocol_start(proto, pk);

    TEST_ASSERT_EQUAL_INT_MESSAGE(0, proto->hash.is384, "sha512 initialization failed");
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

    unsigned char sha512sum[UBIRCH_PROTOCOL_HASH_SIZE];
    mbedtls_sha512_finish(&proto->hash, sha512sum);
    unsigned char expected_hash[UBIRCH_PROTOCOL_HASH_SIZE] = {
            0x81, 0xda, 0x9b, 0x5d, 0x1b, 0x90, 0x13, 0x76, 0x80, 0xb2, 0x86, 0x3f, 0xbf, 0xe8, 0xb1, 0x2f, 0xa0, 0xfd,
            0xd9, 0x45, 0x6d, 0x10, 0x7a, 0x14, 0xaf, 0x8f, 0x0b, 0x6a, 0xd8, 0x80, 0x6c, 0x5d, 0xd8, 0x2c, 0x32, 0x8b,
            0xee, 0xe1, 0x17, 0x20, 0x90, 0x5a, 0x1f, 0x14, 0x58, 0x28, 0xa4, 0x3e, 0x27, 0x1f, 0x52, 0xe0, 0x28, 0x9d,
            0x38, 0x35, 0x2e, 0xe1, 0xd6, 0x60, 0x00, 0x96, 0x21, 0xa7
    };
    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected_hash, sha512sum, sizeof(sha512sum));

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
            0xc2, 0xda, 0x00, 0x40, 0x16, 0x71, 0x4e, 0x35, 0x4f, 0x5b, 0x83, 0xd1, 0xd7, 0x33, 0x14, 0xe6, 0x5e, 0x4a,
            0xd2, 0x7e, 0x62, 0x4d, 0xc0, 0xdd, 0x5e, 0xc0, 0xdf, 0x5d, 0x63, 0x5c, 0xbf, 0x2a, 0xc8, 0x26, 0xbd, 0xad,
            0x5a, 0x34, 0xb5, 0x9d, 0x93, 0x41, 0xa3, 0x2b, 0xc1, 0x44, 0xa7, 0x6c, 0xeb, 0x31, 0x58, 0x4c, 0x72, 0xce,
            0x0d, 0x96, 0x26, 0x01, 0xea, 0x82, 0x38, 0x1a, 0x6e, 0x31, 0xe3, 0xe1, 0x8b, 0x0e
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
    TEST_ASSERT_EQUAL_STRING_MESSAGE("3", _value, "chained protocol variant failed");

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
    TEST_ASSERT_EQUAL_STRING_MESSAGE("3", _value, "chained protocol variant failed");

    msgpack_packer_free(pk);
    ubirch_protocol_free(proto);
}

void TestChainedStaticMessage() {
    char _key[20], _value[300];
    size_t encoded_size;

    memset(_value, 0, sizeof(_value));
    mbedtls_base64_encode((unsigned char *) _value, sizeof(_value), &encoded_size, public_key,
                          crypto_sign_PUBLICKEYBYTES);
    greentea_send_kv("publicKey", _value);

    msgpack_sbuffer *sbuf = msgpack_sbuffer_new();
    ubirch_protocol *proto = ubirch_protocol_new(proto_chained, sbuf, msgpack_sbuffer_write, ed25519_sign, UUID);
    msgpack_packer *pk = msgpack_packer_new(proto, ubirch_protocol_write);

    for (int i = 0; i < 5; i++) {
        const char *staticValue = "STATIC";
        ubirch_protocol_start(proto, pk);
        msgpack_pack_raw(pk, strlen(staticValue));
        msgpack_pack_raw_body(pk, staticValue, strlen(staticValue));
        ubirch_protocol_finish(proto, pk);

        memset(_value, 0, sizeof(_value));
        mbedtls_base64_encode((unsigned char *) _value, sizeof(_value), &encoded_size,
                              (unsigned char *) sbuf->data, sbuf->size);
        greentea_send_kv("checkMessage", _value, encoded_size);

        greentea_parse_kv(_key, _value, sizeof(_key), sizeof(_value));
        TEST_ASSERT_EQUAL_STRING_MESSAGE("verify", _key, "chained signature verification failed");
        TEST_ASSERT_EQUAL_STRING_MESSAGE("3", _value, "chained protocol variant failed");

        // clear buffer for next message
        msgpack_sbuffer_clear(sbuf);
    }

    msgpack_packer_free(pk);
    ubirch_protocol_free(proto);

}

utest::v1::status_t greentea_test_setup(const size_t number_of_cases) {
    GREENTEA_SETUP(600, "ProtocolTests");
    return greentea_test_setup_handler(number_of_cases);
}


int main() {
    Case cases[] = {
            Case("ubirch protocol [chained] init",
                 TestProtocolInit, greentea_case_failure_abort_handler),
            Case("ubirch protocol [chained] new",
                 TestProtocolNew, greentea_case_failure_abort_handler),
            Case("ubirch protocol [chained] write",
                 TestProtocolWrite, greentea_case_failure_abort_handler),
            Case("ubirch protocol [chained] message simple",
                 TestSimpleMessage, greentea_case_failure_abort_handler),
            Case("ubirch protocol [chained] message chained",
                 TestChainedMessage, greentea_case_failure_abort_handler),
            Case("ubirch protocol [chained] message start",
                 TestProtocolMessageStart, greentea_case_failure_abort_handler),
            Case("ubirch protocol [chained] message finish (fails)",
                 TestProtocolMessageFinishWithoutStart, greentea_case_failure_abort_handler),
            Case("ubirch protocol [chained] message finish",
                 TestProtocolMessageFinish, greentea_case_failure_abort_handler),
            Case("ubirch protocol [chained] static message",
                 TestChainedStaticMessage, greentea_case_failure_abort_handler),
    };

    Specification specification(greentea_test_setup, cases, greentea_test_teardown_handler);
    Harness::run(specification);
}