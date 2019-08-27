#include <unity/unity.h>
#include <ubirch/ubirch_protocol.h>
#include "ubirch_protocol_api.h"
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

void TestProtocolInit() {
    char dummybuffer[10];
    ubirch_protocol proto = {};
    ubirch_protocol_init(&proto, proto_signed, UBIRCH_PROTOCOL_TYPE_BIN,
                         dummybuffer, msgpack_sbuffer_write, ed25519_sign, UUID);

    TEST_ASSERT_EQUAL_PTR(dummybuffer, proto.packer.data);
    TEST_ASSERT_EQUAL_PTR(msgpack_sbuffer_write, proto.packer.callback);
    TEST_ASSERT_EQUAL_HEX16(proto_signed, proto.version);
    TEST_ASSERT_EQUAL_PTR(ed25519_sign, proto.sign);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(UUID, proto.uuid, 16);
}

void TestProtocolNew() {
    char dummybuffer[10];
    ubirch_protocol *proto = ubirch_protocol_new(proto_signed, UBIRCH_PROTOCOL_TYPE_BIN,
                                                 dummybuffer, msgpack_sbuffer_write, ed25519_sign, UUID);

    TEST_ASSERT_EQUAL_PTR(dummybuffer, proto->packer.data);
    TEST_ASSERT_EQUAL_PTR(msgpack_sbuffer_write, proto->packer.callback);
    TEST_ASSERT_EQUAL_HEX16(proto_signed, proto->version);
    TEST_ASSERT_EQUAL_PTR(ed25519_sign, proto->sign);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(proto->uuid, UUID, 16);

    ubirch_protocol_free(proto);
}

void TestProtocolWrite() {
    msgpack_sbuffer *sbuf = msgpack_sbuffer_new();
    ubirch_protocol *proto = ubirch_protocol_new(proto_signed, UBIRCH_PROTOCOL_TYPE_BIN,
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
    ubirch_protocol *proto = ubirch_protocol_new(proto_signed, UBIRCH_PROTOCOL_TYPE_BIN,
                                                 sbuf, msgpack_sbuffer_write, ed25519_sign, UUID);
    msgpack_packer *pk = msgpack_packer_new(proto, ubirch_protocol_write);

    TEST_ASSERT_NOT_NULL_MESSAGE(sbuf, "sbuf NULL");
    TEST_ASSERT_NOT_NULL_MESSAGE(proto, "protocol NULL");
    TEST_ASSERT_NOT_NULL_MESSAGE(pk, "packer NULL");

    TEST_ASSERT_EQUAL_INT(0, ubirch_protocol_start(proto, pk));

    TEST_ASSERT_EQUAL_INT_MESSAGE(0, proto->hash.is384, "sha512 initialization failed");
    TEST_ASSERT_EQUAL_INT_MESSAGE(21, sbuf->size, "header size wrong");
    TEST_ASSERT_EQUAL_HEX_MESSAGE(0x95, sbuf->data[0], "msgpack format wrong (expected 5-array)");

    const int expected_version = UBIRCH_PROTOCOL_VERSION << 4 | UBIRCH_PROTOCOL_SIGNED;
    TEST_ASSERT_EQUAL_HEX8_ARRAY_MESSAGE(&expected_version, sbuf->data + 1, 1, "protocol version wrong");
    TEST_ASSERT_EQUAL_HEX8_MESSAGE(0xc4, sbuf->data[2], "message uuid marker wrong");
    TEST_ASSERT_EQUAL_HEX8_ARRAY_MESSAGE(UUID, sbuf->data + 4, 16, "message uuid wrong");

    unsigned char sha512sum[UBIRCH_PROTOCOL_HASH_SIZE];
    mbedtls_sha512_finish(&proto->hash, sha512sum);

    unsigned char expected_hash[UBIRCH_PROTOCOL_HASH_SIZE] = {
            0xee, 0x0a, 0x2f, 0x85, 0xde, 0x07, 0x0a, 0xfa, 0xcf, 0x14, 0x5f, 0xb8, 0xee, 0x60, 0xa2, 0x77, 0x72, 0xce,
            0x12, 0xe3, 0x71, 0xf1, 0xe1, 0x1f, 0x68, 0x98, 0xf0, 0x6f, 0x6c, 0x06, 0xee, 0x12, 0xb8, 0x96, 0x13, 0x3b,
            0x4e, 0x33, 0xb3, 0x30, 0xc2, 0x68, 0xb2, 0xe9, 0x01, 0x08, 0x2d, 0x01, 0x20, 0x59, 0x3a, 0x48, 0x70, 0xcb,
            0x44, 0x6b, 0xa0, 0x7b, 0xbf, 0xde, 0x6a, 0xa3, 0x20, 0xd7
    };
    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected_hash, sha512sum, sizeof(sha512sum));

    msgpack_packer_free(pk);
    ubirch_protocol_free(proto);
    msgpack_sbuffer_free(sbuf);
}

void TestProtocolMessageFinishWithoutStart() {
    msgpack_sbuffer *sbuf = msgpack_sbuffer_new();
    ubirch_protocol *proto = ubirch_protocol_new(proto_signed, UBIRCH_PROTOCOL_TYPE_BIN,
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
    ubirch_protocol *proto = ubirch_protocol_new(proto_signed, UBIRCH_PROTOCOL_TYPE_BIN,
                                                 sbuf, msgpack_sbuffer_write, ed25519_sign, UUID);
    msgpack_packer *pk = msgpack_packer_new(proto, ubirch_protocol_write);

    ubirch_protocol_start(proto, pk);
    msgpack_pack_int(pk, 2498);
    int finish_ok = ubirch_protocol_finish(proto, pk);

    TEST_ASSERT_EQUAL_INT_MESSAGE(0, finish_ok, "message finish failed");
    TEST_ASSERT_EQUAL_INT_MESSAGE(90, sbuf->size, "message length wrong");

    const unsigned char expected_message[90] = {
            0x95, 0x22, 0xc4, 0x10, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e,
            0x6f, 0x70, 0x00, 0xcd, 0x09, 0xc2, 0xc4, 0x40, 0x2e, 0x5f, 0xa0, 0xc3, 0xdd, 0xb7, 0xca, 0x79, 0xb0, 0x32,
            0xef, 0x8f, 0xbe, 0xad, 0x59, 0x8e, 0x70, 0xc7, 0xc0, 0x6c, 0xd4, 0x7c, 0x6d, 0x6b, 0x25, 0x51, 0x2b, 0xc7,
            0xcc, 0x88, 0x0a, 0x06, 0x5e, 0xd7, 0x37, 0xf5, 0xc1, 0x94, 0xa4, 0x62, 0x35, 0x5a, 0xc7, 0xd3, 0x57, 0xd5,
            0x68, 0x85, 0xfb, 0x08, 0xad, 0x76, 0xd6, 0x76, 0xb7, 0xb0, 0x94, 0xc0, 0x11, 0xde, 0x26, 0x2d, 0xaf, 0x0c
    };
    TEST_ASSERT_EQUAL_HEX8_ARRAY_MESSAGE(expected_message, sbuf->data, sbuf->size, "message serialization failed");

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
}

void TestSimpleMessage() {
    char _key[20], _value[300];
    size_t encoded_size;

    memset(_value, 0, sizeof(_value));
    mbedtls_base64_encode((unsigned char *) _value, sizeof(_value), &encoded_size, ed25519_public_key,
                          crypto_sign_PUBLICKEYBYTES);
    greentea_send_kv("publicKey", _value);

    msgpack_sbuffer *sbuf = msgpack_sbuffer_new();
    ubirch_protocol *proto = ubirch_protocol_new(proto_signed, UBIRCH_PROTOCOL_TYPE_BIN,
                                                 sbuf, msgpack_sbuffer_write, ed25519_sign, UUID);
    msgpack_packer *pk = msgpack_packer_new(proto, ubirch_protocol_write);

    ubirch_protocol_start(proto, pk);
    msgpack_pack_int(pk, 99);
    ubirch_protocol_finish(proto, pk);

    memset(_value, 0, sizeof(_value));
    mbedtls_base64_encode((unsigned char *) _value, sizeof(_value), &encoded_size,
                          (unsigned char *) sbuf->data, sbuf->size);
    greentea_send_kv("checkMessage", _value, encoded_size);

    greentea_parse_kv(_key, _value, sizeof(_key), sizeof(_value));
    TEST_ASSERT_EQUAL_STRING_MESSAGE("verify", _key, "signature verification failed");
    TEST_ASSERT_EQUAL_STRING_MESSAGE("2", _value, "signed protocol variant failed");

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
}

void TestSimpleAPIVerifyMessage() {
    // create a new message a sign it
    const unsigned char msg[] = {99};
    ubirch_protocol_buffer *upp = ubirch_protocol_pack(proto_signed, UUID, UBIRCH_PROTOCOL_TYPE_BIN, msg, sizeof(msg));

    TEST_ASSERT_NOT_NULL_MESSAGE(upp, "failed to create UPP");
    TEST_ASSERT_NOT_NULL_MESSAGE(upp->data, "no data in generated UPP");
    TEST_ASSERT_NOT_EQUAL_MESSAGE(0, upp->size, "UPP size shouldn't be 0");

    // unpack and verify
    msgpack_unpacker *unpacker = msgpack_unpacker_new(16);
    if (msgpack_unpacker_buffer_capacity(unpacker) < upp->size) {
        msgpack_unpacker_reserve_buffer(unpacker, upp->size);
    }
    memcpy(msgpack_unpacker_buffer(unpacker), upp->data, upp->size);
    msgpack_unpacker_buffer_consumed(unpacker, upp->size);

    TEST_ASSERT_EQUAL_INT_MESSAGE(0, ubirch_protocol_verify(unpacker, ed25519_verify), "message verification failed");

    msgpack_unpacker_free(unpacker);
    ubirch_protocol_buffer_free(upp);
}

void TestSimpleAPISimpleMessage() {
    char _key[20], _value[300];
    size_t encoded_size;

    memset(_value, 0, sizeof(_value));
    mbedtls_base64_encode((unsigned char *) _value, sizeof(_value), &encoded_size, ed25519_public_key,
                          crypto_sign_PUBLICKEYBYTES);
    greentea_send_kv("publicKey", _value);

    const unsigned char msg[] = {0x09, 0xC2};
    ubirch_protocol_buffer *upp = ubirch_protocol_pack(proto_signed, UUID, UBIRCH_PROTOCOL_TYPE_BIN, msg, sizeof(msg));

    TEST_ASSERT_NOT_NULL_MESSAGE(upp, "failed to create UPP");
    TEST_ASSERT_NOT_NULL_MESSAGE(upp->data, "no data in generated UPP");
    TEST_ASSERT_NOT_EQUAL_MESSAGE(0, upp->size, "UPP size shouldn't be 0");

    memset(_value, 0, sizeof(_value));
    mbedtls_base64_encode((unsigned char *) _value, sizeof(_value), &encoded_size,
                          (unsigned char *) upp->data, upp->size);
    greentea_send_kv("checkMessage", _value, encoded_size);

    greentea_parse_kv(_key, _value, sizeof(_key), sizeof(_value));
    TEST_ASSERT_EQUAL_STRING_MESSAGE("verify", _key, "signature verification failed");
    TEST_ASSERT_EQUAL_STRING_MESSAGE("2", _value, "signed protocol variant failed");

    // unpack and verify
    msgpack_unpacker *unpacker = msgpack_unpacker_new(16);
    if (msgpack_unpacker_buffer_capacity(unpacker) < upp->size) {
        msgpack_unpacker_reserve_buffer(unpacker, upp->size);
    }
    memcpy(msgpack_unpacker_buffer(unpacker), upp->data, upp->size);
    msgpack_unpacker_buffer_consumed(unpacker, upp->size);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, ubirch_protocol_verify(unpacker, ed25519_verify), "message verification failed");

    msgpack_unpacker_free(unpacker);
    ubirch_protocol_buffer_free(upp);
}

void TestProtocolSimpleAPIMessageFinish() {
    const unsigned char msg[] = {0x09, 0xC2};
    ubirch_protocol_buffer *upp = ubirch_protocol_pack(proto_signed, UUID, UBIRCH_PROTOCOL_TYPE_BIN, msg, sizeof(msg));

    TEST_ASSERT_NOT_NULL_MESSAGE(upp, "failed to create UPP");
    TEST_ASSERT_NOT_NULL_MESSAGE(upp->data, "no data in generated UPP");
    TEST_ASSERT_NOT_EQUAL_MESSAGE(0, upp->size, "UPP size shouldn't be 0");

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

    // unpack and verify
    msgpack_unpacker *unpacker = msgpack_unpacker_new(16);
    if (msgpack_unpacker_buffer_capacity(unpacker) < upp->size) {
        msgpack_unpacker_reserve_buffer(unpacker, upp->size);
    }
    memcpy(msgpack_unpacker_buffer(unpacker), upp->data, upp->size);
    msgpack_unpacker_buffer_consumed(unpacker, upp->size);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, ubirch_protocol_verify(unpacker, ed25519_verify), "message verification failed");

    msgpack_unpacker_free(unpacker);
    ubirch_protocol_buffer_free(upp);
}

utest::v1::status_t greentea_test_setup(const size_t number_of_cases) {
    GREENTEA_SETUP(600, "ProtocolTests");
    return greentea_test_setup_handler(number_of_cases);
}


int main() {
    Case cases[] = {
//            Case("ubirch protocol [signed] init",
//                 TestProtocolInit, greentea_case_failure_abort_handler),
//            Case("ubirch protocol [signed] new",
//                 TestProtocolNew, greentea_case_failure_abort_handler),
//            Case("ubirch protocol [signed] write",
//                 TestProtocolWrite, greentea_case_failure_abort_handler),
//            Case("ubirch protocol [signed] message signed",
//                 TestSimpleMessage, greentea_case_failure_abort_handler),
//            Case("ubirch protocol [signed] message start",
//                 TestProtocolMessageStart, greentea_case_failure_abort_handler),
//            Case("ubirch protocol [signed] message finish (fails)",
//                 TestProtocolMessageFinishWithoutStart, greentea_case_failure_abort_handler),
//            Case("ubirch protocol [signed] message finish",
//                 TestProtocolMessageFinish, greentea_case_failure_abort_handler),
//            Case("ubirch protocol [signed] message verify",
//                 TestVerifyMessage, greentea_case_failure_abort_handler),
            Case("ubirch protocol simple API [signed] message verify",
                 TestSimpleAPIVerifyMessage, greentea_case_failure_abort_handler),
            Case("ubirch protocol simple API [signed] message signed",
                 TestSimpleAPISimpleMessage, greentea_case_failure_abort_handler),
            Case("ubirch protocol simple API [signed] message finish",
                 TestProtocolSimpleAPIMessageFinish, greentea_case_failure_abort_handler),
    };

    Specification specification(greentea_test_setup, cases, greentea_test_teardown_handler);
    Harness::run(specification);
}