#include <unity/unity.h>
#include <ubirch/ubirch_protocol.h>
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

void dump(void *buf, size_t len) {
//    for (unsigned int i = 0; i < len; i++) {
//        printf("%02x", ((unsigned char *) buf)[i]);
//    }
//    printf("\r\n");
}

void TestProtocolInit() {
    char dummybuffer[10];
    ubirch_protocol proto = {};
    ubirch_protocol_init(&proto, proto_chained, UBIRCH_PROTOCOL_TYPE_BIN,
                         dummybuffer, msgpack_sbuffer_write, ed25519_sign, UUID);

    TEST_ASSERT_EQUAL_PTR(dummybuffer, proto.packer.data);
    TEST_ASSERT_EQUAL_PTR(msgpack_sbuffer_write, proto.packer.callback);
    TEST_ASSERT_EQUAL_HEX16(proto_chained, proto.version);
    TEST_ASSERT_EQUAL_PTR(ed25519_sign, proto.sign);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(UUID, proto.uuid, 16);
}

void TestProtocolNew() {
    char dummybuffer[10];
    ubirch_protocol *proto = ubirch_protocol_new(proto_chained, UBIRCH_PROTOCOL_TYPE_BIN,
                                                 dummybuffer, msgpack_sbuffer_write, ed25519_sign, UUID);

    TEST_ASSERT_EQUAL_PTR(dummybuffer, proto->packer.data);
    TEST_ASSERT_EQUAL_PTR(msgpack_sbuffer_write, proto->packer.callback);
    TEST_ASSERT_EQUAL_HEX16(proto_chained, proto->version);
    TEST_ASSERT_EQUAL_PTR(ed25519_sign, proto->sign);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(proto->uuid, UUID, 16);

    ubirch_protocol_free(proto);
}

void TestProtocolWrite() {
    msgpack_sbuffer *sbuf = msgpack_sbuffer_new();
    ubirch_protocol *proto = ubirch_protocol_new(proto_chained, UBIRCH_PROTOCOL_TYPE_BIN,
                                                 sbuf, msgpack_sbuffer_write, ed25519_sign, UUID);
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
    msgpack_sbuffer_free(sbuf);
}

void TestProtocolMessageStart() {
    msgpack_sbuffer *sbuf = msgpack_sbuffer_new();
    ubirch_protocol *proto = ubirch_protocol_new(proto_chained, UBIRCH_PROTOCOL_TYPE_BIN,
                                                 sbuf, msgpack_sbuffer_write, ed25519_sign, UUID);
    msgpack_packer *pk = msgpack_packer_new(proto, ubirch_protocol_write);

    ubirch_protocol_start(proto, pk);

    TEST_ASSERT_EQUAL_INT_MESSAGE(0, proto->hash.is384, "sha512 initialization failed");
    TEST_ASSERT_EQUAL_INT_MESSAGE(87, sbuf->size, "header size wrong");
    TEST_ASSERT_EQUAL_HEX_MESSAGE(0x96, sbuf->data[0], "msgpack format wrong (expected 6-array)");

    dump(sbuf->data, sbuf->size);

    const int expected_version = UBIRCH_PROTOCOL_VERSION << 4 | UBIRCH_PROTOCOL_CHAINED;
    TEST_ASSERT_EQUAL_HEX8_ARRAY_MESSAGE(&expected_version, sbuf->data + 1, 1, "protocol version wrong");
    const unsigned char expected_uuid[16] = {
            0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68,
            0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70,
    };
    TEST_ASSERT_EQUAL_HEX_MESSAGE(0xc4, sbuf->data[2], "message uuid marker wrong");
    TEST_ASSERT_EQUAL_HEX8_ARRAY_MESSAGE(expected_uuid, sbuf->data + 4, 16, "message uuid wrong");
    const unsigned char expected_prev_sig_marker[2] = {0xc4, 0x40};
    TEST_ASSERT_EQUAL_HEX8_ARRAY_MESSAGE(expected_prev_sig_marker, sbuf->data + 20, 2, "prev signature marker wrong");
    const unsigned char expected_prev_signature[64] = {};
    memset((void *) expected_prev_signature, 0, 64);
    TEST_ASSERT_EQUAL_HEX8_ARRAY_MESSAGE(expected_prev_signature, sbuf->data + 22, 64, "prev signature not 0");

    unsigned char sha512sum[UBIRCH_PROTOCOL_HASH_SIZE];
    mbedtls_sha512_finish(&proto->hash, sha512sum);

    dump(sha512sum, sizeof(sha512sum));

    unsigned char expected_hash[UBIRCH_PROTOCOL_HASH_SIZE] = {
            0x93, 0x1b, 0xab, 0xe8, 0x15, 0x83, 0xde, 0x4d, 0x9c, 0x49, 0x1f, 0xc7, 0x0d, 0xa6, 0x9d, 0x90, 0x74, 0x32,
            0x38, 0x36, 0x10, 0x0e, 0x00, 0xa1, 0x96, 0xf4, 0x04, 0xb1, 0xd4, 0x80, 0x92, 0x98, 0xce, 0xf7, 0xe5, 0xf6,
            0x5c, 0x6d, 0xe7, 0x96, 0x6c, 0x3c, 0xd6, 0xb2, 0xe5, 0x26, 0xf0, 0x7f, 0xc7, 0x4f, 0x7d, 0x10, 0x78, 0x33,
            0x4c, 0x25, 0xcd, 0x57, 0xd3, 0xc7, 0xbb, 0xfb, 0x19, 0xfc,
    };
    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected_hash, sha512sum, sizeof(sha512sum));

    msgpack_packer_free(pk);
    ubirch_protocol_free(proto);
    msgpack_sbuffer_free(sbuf);
}

void TestProtocolMessageFinishWithoutStart() {
    msgpack_sbuffer *sbuf = msgpack_sbuffer_new();
    ubirch_protocol *proto = ubirch_protocol_new(proto_chained, UBIRCH_PROTOCOL_TYPE_BIN,
                                                 sbuf, msgpack_sbuffer_write, ed25519_sign, UUID);
    msgpack_packer *pk = msgpack_packer_new(proto, ubirch_protocol_write);

    // add some dummy data without start
    msgpack_pack_int(pk, 2498);

    int finish_ok = ubirch_protocol_finish(proto, pk);
    TEST_ASSERT_EQUAL_INT_MESSAGE(-2, finish_ok, "message finish without start must fail");

    msgpack_packer_free(pk);
    ubirch_protocol_free(proto);
    msgpack_sbuffer_free(sbuf);
}

void TestProtocolMessageFinish() {
    msgpack_sbuffer *sbuf = msgpack_sbuffer_new();
    ubirch_protocol *proto = ubirch_protocol_new(proto_chained, UBIRCH_PROTOCOL_TYPE_BIN,
                                                 sbuf, msgpack_sbuffer_write, ed25519_sign, UUID);
    msgpack_packer *pk = msgpack_packer_new(proto, ubirch_protocol_write);

    ubirch_protocol_start(proto, pk);
    msgpack_pack_int(pk, 2498);
    int finish_ok = ubirch_protocol_finish(proto, pk);

    TEST_ASSERT_EQUAL_INT_MESSAGE(0, finish_ok, "message finish failed");
    TEST_ASSERT_EQUAL_INT_MESSAGE(156, sbuf->size, "message length wrong");

    dump(sbuf->data, sbuf->size);

    const unsigned char expected_message[156] = {
            0x96, 0x23, 0xc4, 0x10, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e,
            0x6f, 0x70, 0xc4, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xcd, 0x09, 0xc2,
            0xc4, 0x40, 0x3f, 0xe0, 0xd2, 0x7b, 0x1f, 0xb0, 0x5d, 0xa6, 0x3b, 0x4b, 0x25, 0x5e, 0xf9, 0x2e, 0x82, 0xe9,
            0x99, 0x6a, 0xd0, 0x25, 0x52, 0x5d, 0x7d, 0x79, 0x79, 0x55, 0x56, 0xce, 0xed, 0x2d, 0x18, 0x78, 0x42, 0x30,
            0xe2, 0x8d, 0xc6, 0xd5, 0x5b, 0x85, 0xb0, 0xe4, 0x57, 0xf7, 0x5e, 0x58, 0x19, 0x5f, 0xff, 0x84, 0x9b, 0xbd,
            0x66, 0xf6, 0xe6, 0xf2, 0xd4, 0xf2, 0x36, 0x10, 0x81, 0x0b, 0x83, 0x0c,
    };
    TEST_ASSERT_EQUAL_HEX8_ARRAY_MESSAGE(expected_message, sbuf->data, sbuf->size, "message serialization failed");

    msgpack_packer_free(pk);
    ubirch_protocol_free(proto);
    msgpack_sbuffer_free(sbuf);
}

void TestSimpleMessage() {
    char _key[20], _value[300];
    size_t encoded_size;

    memset(_value, 0, sizeof(_value));
    mbedtls_base64_encode((unsigned char *) _value, sizeof(_value), &encoded_size,
                          ed25519_public_key, crypto_sign_PUBLICKEYBYTES);
    greentea_send_kv("publicKey", _value);

    msgpack_sbuffer *sbuf = msgpack_sbuffer_new();
    ubirch_protocol *proto = ubirch_protocol_new(proto_chained, UBIRCH_PROTOCOL_TYPE_BIN,
                                                 sbuf, msgpack_sbuffer_write, ed25519_sign, UUID);
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
    msgpack_sbuffer_free(sbuf);

    greentea_parse_kv(_key, _value, sizeof(_key), sizeof(_value));
    TEST_ASSERT_EQUAL_STRING_MESSAGE("verify", _key, "signature verification failed");
}

void TestChainedMessage() {
    char _key[20], _value[300];
    size_t encoded_size;

    memset(_value, 0, sizeof(_value));
    mbedtls_base64_encode((unsigned char *) _value, sizeof(_value), &encoded_size,
                          ed25519_public_key, crypto_sign_PUBLICKEYBYTES);
    greentea_send_kv("publicKey", _value);

    msgpack_sbuffer *sbuf = msgpack_sbuffer_new();
    ubirch_protocol *proto = ubirch_protocol_new(proto_chained, UBIRCH_PROTOCOL_TYPE_BIN,
                                                 sbuf, msgpack_sbuffer_write, ed25519_sign, UUID);
    msgpack_packer *pk = msgpack_packer_new(proto, ubirch_protocol_write);

    const char *message1 = "message 1";
    ubirch_protocol_start(proto, pk);
    msgpack_pack_str(pk, strlen(message1));
    msgpack_pack_str_body(pk, message1, strlen(message1));
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
    msgpack_pack_str(pk, strlen(message2));
    msgpack_pack_str_body(pk, message2, strlen(message2));
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
    msgpack_sbuffer_free(sbuf);
}

void TestChainedStaticMessage() {
    char _key[20], _value[300];
    size_t encoded_size;

    memset(_value, 0, sizeof(_value));
    mbedtls_base64_encode((unsigned char *) _value, sizeof(_value), &encoded_size,
                          ed25519_public_key, crypto_sign_PUBLICKEYBYTES);
    greentea_send_kv("publicKey", _value);

    msgpack_sbuffer *sbuf = msgpack_sbuffer_new();
    ubirch_protocol *proto = ubirch_protocol_new(proto_chained, UBIRCH_PROTOCOL_TYPE_BIN,
                                                 sbuf, msgpack_sbuffer_write, ed25519_sign, UUID);
    msgpack_packer *pk = msgpack_packer_new(proto, ubirch_protocol_write);

    for (int i = 0; i < 5; i++) {
        const char *staticValue = "STATIC";
        ubirch_protocol_start(proto, pk);
        msgpack_pack_str(pk, strlen(staticValue));
        msgpack_pack_str_body(pk, staticValue, strlen(staticValue));
        ubirch_protocol_finish(proto, pk);

        // unpack and verify
        msgpack_unpacker *unpacker = msgpack_unpacker_new(16);
        if (msgpack_unpacker_buffer_capacity(unpacker) < sbuf->size) {
            msgpack_unpacker_reserve_buffer(unpacker, sbuf->size);
        }
        memcpy(msgpack_unpacker_buffer(unpacker), sbuf->data, sbuf->size);
        msgpack_unpacker_buffer_consumed(unpacker, sbuf->size);
        TEST_ASSERT_EQUAL_INT_MESSAGE(0, ubirch_protocol_verify(unpacker, ed25519_verify),
                                      "message verification failed");
        msgpack_unpacker_free(unpacker);

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
    msgpack_sbuffer_free(sbuf);
}

void TestVerifyMessage() {
    // create a new message a sign it
    msgpack_sbuffer *sbuf = msgpack_sbuffer_new();
    ubirch_protocol *proto = ubirch_protocol_new(proto_signed, UBIRCH_PROTOCOL_TYPE_BIN,
                                                 sbuf, msgpack_sbuffer_write, ed25519_sign, UUID);
    msgpack_packer *pk = msgpack_packer_new(proto, ubirch_protocol_write);

    ubirch_protocol_start(proto, pk);
    msgpack_pack_int(pk, 99);
    ubirch_protocol_finish(proto, pk);

    msgpack_packer_free(pk);
    ubirch_protocol_free(proto);

    // unpack and verify
    msgpack_unpacker *unpacker = msgpack_unpacker_new(16);
    if (msgpack_unpacker_buffer_capacity(unpacker) < sbuf->size) {
        msgpack_unpacker_reserve_buffer(unpacker, sbuf->size);
    }
    memcpy(msgpack_unpacker_buffer(unpacker), sbuf->data, sbuf->size);
    msgpack_unpacker_buffer_consumed(unpacker, sbuf->size);

    TEST_ASSERT_EQUAL_INT_MESSAGE(0, ubirch_protocol_verify(unpacker, ed25519_verify), "message verification failed");

    msgpack_unpacker_free(unpacker);
    msgpack_sbuffer_free(sbuf);
    msgpack_sbuffer_free(sbuf);
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