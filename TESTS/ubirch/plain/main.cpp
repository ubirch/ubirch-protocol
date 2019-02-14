#include <unity/unity.h>
#include <ubirch/ubirch_protocol.h>
#include <armnacl.h>
#include <mbedtls/base64.h>

#include "utest/utest.h"
#include "greentea-client/test_env.h"

using namespace utest::v1;

static const unsigned char UUID[16] = {'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p'};

void TestProtocolInit() {
    char dummybuffer[10];
    ubirch_protocol proto = {};
    ubirch_protocol_init(&proto, proto_plain, UBIRCH_PROTOCOL_TYPE_BIN,
                         dummybuffer, msgpack_sbuffer_write, NULL, UUID);

    TEST_ASSERT_EQUAL_PTR(dummybuffer, proto.packer.data);
    TEST_ASSERT_EQUAL_PTR(msgpack_sbuffer_write, proto.packer.callback);
    TEST_ASSERT_EQUAL_HEX16(proto_plain, proto.version);
    TEST_ASSERT_NULL(proto.sign);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(UUID, proto.uuid, 16);
}

void TestProtocolNew() {
    char dummybuffer[10];
    ubirch_protocol *proto = ubirch_protocol_new(proto_plain, UBIRCH_PROTOCOL_TYPE_BIN,
                                                 dummybuffer, msgpack_sbuffer_write, NULL, UUID);

    TEST_ASSERT_EQUAL_PTR(dummybuffer, proto->packer.data);
    TEST_ASSERT_EQUAL_PTR(msgpack_sbuffer_write, proto->packer.callback);
    TEST_ASSERT_EQUAL_HEX16(proto_plain, proto->version);
    TEST_ASSERT_NULL(proto->sign);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(proto->uuid, UUID, 16);

    ubirch_protocol_free(proto);
}

void TestProtocolWrite() {
    msgpack_sbuffer *sbuf = msgpack_sbuffer_new();
    ubirch_protocol *proto = ubirch_protocol_new(proto_plain, UBIRCH_PROTOCOL_TYPE_BIN,
                                                 sbuf, msgpack_sbuffer_write, NULL, UUID);
    msgpack_packer *pk = msgpack_packer_new(proto, ubirch_protocol_write);

    // pack a random (sort of) number
    msgpack_pack_int(pk, 2489);

    unsigned char expected_data[] = {0xcd, 0x09, 0xb9};
    TEST_ASSERT_EQUAL_INT_MESSAGE(sizeof(expected_data), sbuf->size, "written data does not match");
    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected_data, sbuf->data, sizeof(expected_data));
    TEST_ASSERT_EQUAL_INT_MESSAGE(-1, proto->hash.is384, "sha512 must not be initialized");

    msgpack_packer_free(pk);
    ubirch_protocol_free(proto);
    msgpack_sbuffer_free(sbuf);
}

void TestProtocolMessageStart() {
    msgpack_sbuffer *sbuf = msgpack_sbuffer_new();
    ubirch_protocol *proto = ubirch_protocol_new(proto_plain, UBIRCH_PROTOCOL_TYPE_BIN,
                                                 sbuf, msgpack_sbuffer_write, NULL, UUID);
    msgpack_packer *pk = msgpack_packer_new(proto, ubirch_protocol_write);

    TEST_ASSERT_EQUAL_INT(0, ubirch_protocol_start(proto, pk));

    TEST_ASSERT_EQUAL_INT_MESSAGE(-1, proto->hash.is384, "sha512 must not be initialized");
    TEST_ASSERT_EQUAL_INT_MESSAGE(21, sbuf->size, "header size wrong");
    TEST_ASSERT_EQUAL_HEX_MESSAGE(0x94, sbuf->data[0], "msgpack format wrong (expected 4-array)");

    const int expected_version = UBIRCH_PROTOCOL_VERSION << 4 | UBIRCH_PROTOCOL_PLAIN;
    TEST_ASSERT_EQUAL_HEX8_ARRAY_MESSAGE(&expected_version, sbuf->data + 1, 1, "protocol version wrong");
    TEST_ASSERT_EQUAL_HEX_MESSAGE(0xc4, sbuf->data[2], "message uuid marker wrong");
    TEST_ASSERT_EQUAL_HEX8_ARRAY_MESSAGE(UUID, sbuf->data + 4, 16, "message uuid wrong");

    msgpack_packer_free(pk);
    ubirch_protocol_free(proto);
    msgpack_sbuffer_free(sbuf);
}

void TestProtocolUnsupported() {
    msgpack_sbuffer *sbuf = msgpack_sbuffer_new();
    ubirch_protocol *proto = ubirch_protocol_new((ubirch_protocol_variant) 0, UBIRCH_PROTOCOL_TYPE_BIN,
                                                 sbuf, msgpack_sbuffer_write, NULL, UUID);
    msgpack_packer *pk = msgpack_packer_new(proto, ubirch_protocol_write);

    TEST_ASSERT_EQUAL_INT(-3, ubirch_protocol_start(proto, pk));
    
    msgpack_packer_free(pk);
    ubirch_protocol_free(proto);
    msgpack_sbuffer_free(sbuf);
}

void TestProtocolMessageFinishWithoutStart() {
    msgpack_sbuffer *sbuf = msgpack_sbuffer_new();
    ubirch_protocol *proto = ubirch_protocol_new(proto_plain, UBIRCH_PROTOCOL_TYPE_BIN,
                                                 sbuf, msgpack_sbuffer_write, NULL, UUID);
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
    ubirch_protocol *proto = ubirch_protocol_new(proto_plain, UBIRCH_PROTOCOL_TYPE_BIN,
                                                 sbuf, msgpack_sbuffer_write, NULL, UUID);
    msgpack_packer *pk = msgpack_packer_new(proto, ubirch_protocol_write);

    TEST_ASSERT_EQUAL_INT(0, ubirch_protocol_start(proto, pk));
    TEST_ASSERT_EQUAL_INT(0, msgpack_pack_int16(pk, 2498));
    int finish_ok = ubirch_protocol_finish(proto, pk);

    TEST_ASSERT_EQUAL_INT_MESSAGE(0, finish_ok, "message finish failed");
    TEST_ASSERT_EQUAL_INT_MESSAGE(24, sbuf->size, "message length wrong");

    const unsigned char expected_message[25] = {
            0x94, 0x21, 0xc4, 0x10, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d,
            0x6e, 0x6f, 0x70, 0x00, 0xcd, 0x09, 0xc2,
    };

    TEST_ASSERT_EQUAL_HEX8_ARRAY_MESSAGE(expected_message, sbuf->data, sbuf->size, "message serialization failed");

    msgpack_packer_free(pk);
    ubirch_protocol_free(proto);
    msgpack_sbuffer_free(sbuf);
}

void TestSimpleMessage() {
    char _key[20], _value[300];
    size_t encoded_size;
    
    msgpack_sbuffer *sbuf = msgpack_sbuffer_new();
    ubirch_protocol *proto = ubirch_protocol_new(proto_plain, UBIRCH_PROTOCOL_TYPE_BIN,
                                                 sbuf, msgpack_sbuffer_write, NULL, UUID);
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
    TEST_ASSERT_EQUAL_STRING_MESSAGE("verify", _key, "message verification failed");
    TEST_ASSERT_EQUAL_STRING_MESSAGE("1", _value, "protocol variant failed");
}


utest::v1::status_t greentea_test_setup(const size_t number_of_cases) {
    GREENTEA_SETUP(600, "ProtocolTests");
    return greentea_test_setup_handler(number_of_cases);
}


int main() {
    Case cases[] = {
            Case("ubirch protocol [plain] init",
                 TestProtocolInit, greentea_case_failure_abort_handler),
            Case("ubirch protocol [plain] new",
                 TestProtocolNew, greentea_case_failure_abort_handler),
            Case("ubirch protocol [plain] write",
                 TestProtocolWrite, greentea_case_failure_abort_handler),
            Case("ubirch protocol [plain] message start",
                 TestProtocolMessageStart, greentea_case_failure_abort_handler),
            Case("ubirch protocol [plain] message (unsupported)",
                 TestProtocolUnsupported, greentea_case_failure_abort_handler),
            Case("ubirch protocol [plain] message simple",
                 TestSimpleMessage, greentea_case_failure_abort_handler),
            Case("ubirch protocol [plain] message finish (fails)",
                 TestProtocolMessageFinishWithoutStart, greentea_case_failure_abort_handler),
            Case("ubirch protocol [plain] message finish",
                 TestProtocolMessageFinish, greentea_case_failure_abort_handler),
    };

    Specification specification(greentea_test_setup, cases, greentea_test_teardown_handler);
    Harness::run(specification);
}