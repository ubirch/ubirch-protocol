#include <unity/unity.h>
#include "ubirch/ubirch_protocol.h"
#include <mbedtls/base64.h>
#include <msgpack.h>

#include "utest/utest.h"
#include "greentea-client/test_env.h"

using namespace utest::v1;

static const unsigned char UUID[16] = {'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p'};

void TestProtocolNew() {
    const unsigned char allZeros[UBIRCH_PROTOCOL_SIGN_SIZE] = {0};

    ubirch_protocol *upp = ubirch_protocol_new(NULL);

    TEST_ASSERT_NOT_NULL_MESSAGE(upp, "creating UPP context failed");
    TEST_ASSERT_NOT_NULL_MESSAGE(upp->data, "creating UPP data buffer failed");
    TEST_ASSERT_EQUAL_INT(UPP_BUFFER_INIT_SIZE, upp->alloc);
    TEST_ASSERT_EQUAL_PTR_MESSAGE(upp, upp->packer.data, "packer data not initialized");
    TEST_ASSERT_EQUAL_PTR_MESSAGE(ubirch_protocol_write, upp->packer.callback, "packer callback not initialized");
    TEST_ASSERT_NULL(upp->sign);
    TEST_ASSERT_EQUAL_UINT8_ARRAY_MESSAGE(allZeros, upp->signature, UBIRCH_PROTOCOL_SIGN_SIZE,
                                          "last signature should be 0");

    ubirch_protocol_free(upp);
}

void TestProtocolMessagePlain() {
    const char msg[] = {0x24, 0x98, 0x42, 0x21, 0x42, 0x98, 0x24};
    const char expected_message[] = {
            0x94, 0x21, 0xc4, 0x10, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e,
            0x6f, 0x70, 0x00, 0xc4, 0x07, 0x24, 0x98, 0x42, 0x21, 0x42, 0x98, 0x24
    };

    ubirch_protocol *upp = ubirch_protocol_new(NULL);
    TEST_ASSERT_NOT_NULL_MESSAGE(upp, "creating UPP context failed");

    int8_t ret = ubirch_protocol_message(upp, proto_plain, UUID, UBIRCH_PROTOCOL_TYPE_BIN, msg, sizeof(msg));

    TEST_ASSERT_EQUAL_INT_MESSAGE(0, ret, "packing UPP failed");
    TEST_ASSERT_EQUAL_INT_MESSAGE(sizeof(expected_message), upp->size, "message length wrong");
    TEST_ASSERT_EQUAL_HEX8_ARRAY_MESSAGE(expected_message, upp->data, upp->size, "message serialization failed");

    ubirch_protocol_free(upp);
}

void TestSimpleMessagePlain() {
    char _key[20], _value[300];
    size_t encoded_size;
    const char *msg = "simple message";

    ubirch_protocol *upp = ubirch_protocol_new(NULL);
    TEST_ASSERT_NOT_NULL_MESSAGE(upp, "creating UPP context failed");

    int8_t ret = ubirch_protocol_message(upp, proto_plain, UUID, UBIRCH_PROTOCOL_TYPE_BIN, msg, strlen(msg));
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, ret, "packing UPP failed");

    memset(_value, 0, sizeof(_value));
    int encode_error = mbedtls_base64_encode((unsigned char *) _value, sizeof(_value), &encoded_size,
                                             (unsigned char *) upp->data, upp->size);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, encode_error, "mbedtls_base64_encode returned error");;
    greentea_send_kv("checkMessage", _value, encoded_size);

    ubirch_protocol_free(upp);

    greentea_parse_kv(_key, _value, sizeof(_key), sizeof(_value));
    TEST_ASSERT_EQUAL_STRING_MESSAGE("variant", _key, "message verification failed");
    TEST_ASSERT_EQUAL_STRING_MESSAGE("1", _value, "protocol variant check failed");

    greentea_parse_kv(_key, _value, sizeof(_key), sizeof(_value));
    TEST_ASSERT_EQUAL_STRING_MESSAGE("uuid", _key, "unexpected key");
    TEST_ASSERT_EQUAL_HEX8_ARRAY_MESSAGE(UUID, _value, UBIRCH_PROTOCOL_UUID_SIZE, "UUID check failed");

    greentea_parse_kv(_key, _value, sizeof(_key), sizeof(_value));
    TEST_ASSERT_EQUAL_STRING_MESSAGE("payload", _key, "unexpected key");
    TEST_ASSERT_EQUAL_STRING_MESSAGE(msg, _value, "payload check failed");
}

void TestProtocolUninitialized() {
    const char msg[] = {0x24, 0x98};
    ubirch_protocol upp;

    int8_t ret = ubirch_protocol_message(&upp, proto_plain, UUID, UBIRCH_PROTOCOL_TYPE_BIN, msg, sizeof(msg));

    TEST_ASSERT_EQUAL_INT_MESSAGE(-1, ret, "expected to fail");
}

void TestProtocolUnsupported() {
    const char msg[] = {0x24, 0x98};
    ubirch_protocol *upp = ubirch_protocol_new(NULL);
    TEST_ASSERT_NOT_NULL_MESSAGE(upp, "creating UPP context failed");

    int8_t ret = ubirch_protocol_message(upp, (ubirch_protocol_variant) 0, UUID, UBIRCH_PROTOCOL_TYPE_BIN, msg,
                                         sizeof(msg));

    TEST_ASSERT_EQUAL_INT_MESSAGE(-3, ret, "expected to fail");

    ubirch_protocol_free(upp);
}

void TestProtocolLongMessagePlain() {
    /* this message is 550 Bytes long */
    const char *msg = "Lectus urna duis convallis convallis tellus id interdum velit laoreet. Tellus rutrum tellus "
                      "pellentesque eu tincidunt. Ullamcorper eget nulla facilisi etiam dignissim. Amet consectetur "
                      "adipiscing elit ut aliquam purus sit. Libero nunc consequat interdum varius sit amet. Enim "
                      "tortor at auctor urna nunc id cursus metus aliquam. Imperdiet massa tincidunt nunc pulvinar "
                      "sapien. Non diam phasellus vestibulum lorem sed risus. Nunc non blandit massa enim nec. Leo a "
                      "diam sollicitudin tempor id eu nisl nunc. Non enim praesent elementum facilisis leo vel.";

    ubirch_protocol *upp = ubirch_protocol_new(NULL);
    TEST_ASSERT_NOT_NULL_MESSAGE(upp, "creating UPP context failed");

    int8_t ret = ubirch_protocol_message(upp, proto_plain, UUID, UBIRCH_PROTOCOL_TYPE_BIN, msg, strlen(msg));
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, ret, "packing UPP failed");

    const char expected_message[] = {
            0x94, 0x21, 0xc4, 0x10, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e,
            0x6f, 0x70, 0x00, 0xc5, 0x02, 0x26, 0x4c, 0x65, 0x63, 0x74, 0x75, 0x73, 0x20, 0x75, 0x72, 0x6e, 0x61, 0x20,
            0x64, 0x75, 0x69, 0x73, 0x20, 0x63, 0x6f, 0x6e, 0x76, 0x61, 0x6c, 0x6c, 0x69, 0x73, 0x20, 0x63, 0x6f, 0x6e,
            0x76, 0x61, 0x6c, 0x6c, 0x69, 0x73, 0x20, 0x74, 0x65, 0x6c, 0x6c, 0x75, 0x73, 0x20, 0x69, 0x64, 0x20, 0x69,
            0x6e, 0x74, 0x65, 0x72, 0x64, 0x75, 0x6d, 0x20, 0x76, 0x65, 0x6c, 0x69, 0x74, 0x20, 0x6c, 0x61, 0x6f, 0x72,
            0x65, 0x65, 0x74, 0x2e, 0x20, 0x54, 0x65, 0x6c, 0x6c, 0x75, 0x73, 0x20, 0x72, 0x75, 0x74, 0x72, 0x75, 0x6d,
            0x20, 0x74, 0x65, 0x6c, 0x6c, 0x75, 0x73, 0x20, 0x70, 0x65, 0x6c, 0x6c, 0x65, 0x6e, 0x74, 0x65, 0x73, 0x71,
            0x75, 0x65, 0x20, 0x65, 0x75, 0x20, 0x74, 0x69, 0x6e, 0x63, 0x69, 0x64, 0x75, 0x6e, 0x74, 0x2e, 0x20, 0x55,
            0x6c, 0x6c, 0x61, 0x6d, 0x63, 0x6f, 0x72, 0x70, 0x65, 0x72, 0x20, 0x65, 0x67, 0x65, 0x74, 0x20, 0x6e, 0x75,
            0x6c, 0x6c, 0x61, 0x20, 0x66, 0x61, 0x63, 0x69, 0x6c, 0x69, 0x73, 0x69, 0x20, 0x65, 0x74, 0x69, 0x61, 0x6d,
            0x20, 0x64, 0x69, 0x67, 0x6e, 0x69, 0x73, 0x73, 0x69, 0x6d, 0x2e, 0x20, 0x41, 0x6d, 0x65, 0x74, 0x20, 0x63,
            0x6f, 0x6e, 0x73, 0x65, 0x63, 0x74, 0x65, 0x74, 0x75, 0x72, 0x20, 0x61, 0x64, 0x69, 0x70, 0x69, 0x73, 0x63,
            0x69, 0x6e, 0x67, 0x20, 0x65, 0x6c, 0x69, 0x74, 0x20, 0x75, 0x74, 0x20, 0x61, 0x6c, 0x69, 0x71, 0x75, 0x61,
            0x6d, 0x20, 0x70, 0x75, 0x72, 0x75, 0x73, 0x20, 0x73, 0x69, 0x74, 0x2e, 0x20, 0x4c, 0x69, 0x62, 0x65, 0x72,
            0x6f, 0x20, 0x6e, 0x75, 0x6e, 0x63, 0x20, 0x63, 0x6f, 0x6e, 0x73, 0x65, 0x71, 0x75, 0x61, 0x74, 0x20, 0x69,
            0x6e, 0x74, 0x65, 0x72, 0x64, 0x75, 0x6d, 0x20, 0x76, 0x61, 0x72, 0x69, 0x75, 0x73, 0x20, 0x73, 0x69, 0x74,
            0x20, 0x61, 0x6d, 0x65, 0x74, 0x2e, 0x20, 0x45, 0x6e, 0x69, 0x6d, 0x20, 0x74, 0x6f, 0x72, 0x74, 0x6f, 0x72,
            0x20, 0x61, 0x74, 0x20, 0x61, 0x75, 0x63, 0x74, 0x6f, 0x72, 0x20, 0x75, 0x72, 0x6e, 0x61, 0x20, 0x6e, 0x75,
            0x6e, 0x63, 0x20, 0x69, 0x64, 0x20, 0x63, 0x75, 0x72, 0x73, 0x75, 0x73, 0x20, 0x6d, 0x65, 0x74, 0x75, 0x73,
            0x20, 0x61, 0x6c, 0x69, 0x71, 0x75, 0x61, 0x6d, 0x2e, 0x20, 0x49, 0x6d, 0x70, 0x65, 0x72, 0x64, 0x69, 0x65,
            0x74, 0x20, 0x6d, 0x61, 0x73, 0x73, 0x61, 0x20, 0x74, 0x69, 0x6e, 0x63, 0x69, 0x64, 0x75, 0x6e, 0x74, 0x20,
            0x6e, 0x75, 0x6e, 0x63, 0x20, 0x70, 0x75, 0x6c, 0x76, 0x69, 0x6e, 0x61, 0x72, 0x20, 0x73, 0x61, 0x70, 0x69,
            0x65, 0x6e, 0x2e, 0x20, 0x4e, 0x6f, 0x6e, 0x20, 0x64, 0x69, 0x61, 0x6d, 0x20, 0x70, 0x68, 0x61, 0x73, 0x65,
            0x6c, 0x6c, 0x75, 0x73, 0x20, 0x76, 0x65, 0x73, 0x74, 0x69, 0x62, 0x75, 0x6c, 0x75, 0x6d, 0x20, 0x6c, 0x6f,
            0x72, 0x65, 0x6d, 0x20, 0x73, 0x65, 0x64, 0x20, 0x72, 0x69, 0x73, 0x75, 0x73, 0x2e, 0x20, 0x4e, 0x75, 0x6e,
            0x63, 0x20, 0x6e, 0x6f, 0x6e, 0x20, 0x62, 0x6c, 0x61, 0x6e, 0x64, 0x69, 0x74, 0x20, 0x6d, 0x61, 0x73, 0x73,
            0x61, 0x20, 0x65, 0x6e, 0x69, 0x6d, 0x20, 0x6e, 0x65, 0x63, 0x2e, 0x20, 0x4c, 0x65, 0x6f, 0x20, 0x61, 0x20,
            0x64, 0x69, 0x61, 0x6d, 0x20, 0x73, 0x6f, 0x6c, 0x6c, 0x69, 0x63, 0x69, 0x74, 0x75, 0x64, 0x69, 0x6e, 0x20,
            0x74, 0x65, 0x6d, 0x70, 0x6f, 0x72, 0x20, 0x69, 0x64, 0x20, 0x65, 0x75, 0x20, 0x6e, 0x69, 0x73, 0x6c, 0x20,
            0x6e, 0x75, 0x6e, 0x63, 0x2e, 0x20, 0x4e, 0x6f, 0x6e, 0x20, 0x65, 0x6e, 0x69, 0x6d, 0x20, 0x70, 0x72, 0x61,
            0x65, 0x73, 0x65, 0x6e, 0x74, 0x20, 0x65, 0x6c, 0x65, 0x6d, 0x65, 0x6e, 0x74, 0x75, 0x6d, 0x20, 0x66, 0x61,
            0x63, 0x69, 0x6c, 0x69, 0x73, 0x69, 0x73, 0x20, 0x6c, 0x65, 0x6f, 0x20, 0x76, 0x65, 0x6c, 0x2e,
    };
    TEST_ASSERT_EQUAL_INT_MESSAGE(sizeof(expected_message), upp->size, "message length wrong");
    TEST_ASSERT_EQUAL_HEX8_ARRAY_MESSAGE(expected_message, upp->data, upp->size, "message serialization failed");

    ubirch_protocol_free(upp);
}

void TestMsgpackMessagePlain() {
    char _key[20], _value[300];
    size_t encoded_size;
    static const time_t timestamp = 1568392345;

    // create a ubirch protocol context
    ubirch_protocol *upp = ubirch_protocol_new(NULL);
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
    msgpack_pack_bin(&pk, sizeof(UUID));
    msgpack_pack_bin_body(&pk, UUID, sizeof(UUID));

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
    int8_t ret = ubirch_protocol_message(upp, proto_plain, UUID, UBIRCH_PROTOCOL_TYPE_MSGPACK, sbuf.data, sbuf.size);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, ret, "packing UPP failed");

    printUPP(upp->data, upp->size);

    // send message to host
    memset(_value, 0, sizeof(_value));
    int encode_error = mbedtls_base64_encode((unsigned char *) _value, sizeof(_value), &encoded_size,
                                             (unsigned char *) upp->data, upp->size);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, encode_error, "mbedtls_base64_encode returned error");;
    greentea_send_kv("checkMessage", _value, encoded_size);

    ubirch_protocol_free(upp);

    greentea_parse_kv(_key, _value, sizeof(_key), sizeof(_value));
    TEST_ASSERT_EQUAL_STRING_MESSAGE("variant", _key, "message verification failed");
    TEST_ASSERT_EQUAL_STRING_MESSAGE("1", _value, "protocol variant check failed");

    greentea_parse_kv(_key, _value, sizeof(_key), sizeof(_value));
    TEST_ASSERT_EQUAL_STRING_MESSAGE("uuid", _key, "unexpected key");
    TEST_ASSERT_EQUAL_HEX8_ARRAY_MESSAGE(UUID, _value, UBIRCH_PROTOCOL_UUID_SIZE, "UUID check failed");
}

void TestProtocolFree() {      //FIXME not passing
    const char msg[] = {0x24, 0x98};
    ubirch_protocol *upp = ubirch_protocol_new(NULL);
    TEST_ASSERT_NOT_NULL_MESSAGE(upp, "creating UPP context failed");

    int8_t ret = ubirch_protocol_message(upp, proto_plain, UUID, UBIRCH_PROTOCOL_TYPE_BIN, msg, sizeof(msg));
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, ret, "packing failed");

    ubirch_protocol_free(upp);

    TEST_ASSERT_NULL_MESSAGE(upp, "upp not free");
}


utest::v1::status_t greentea_test_setup(const size_t number_of_cases) {
    GREENTEA_SETUP(600, "ProtocolTests");
    return greentea_test_setup_handler(number_of_cases);
}


int main() {
    Case cases[] = {
            Case("ubirch protocol [plain] new upp context",
                 TestProtocolNew, greentea_case_failure_abort_handler),
            Case("ubirch protocol [plain] pack message",
                 TestProtocolMessagePlain, greentea_case_failure_abort_handler),
            Case("ubirch protocol [plain] simple message",
                 TestSimpleMessagePlain, greentea_case_failure_abort_handler),
            Case("ubirch protocol [plain] pack uninitialized UPP context",
                 TestProtocolUninitialized, greentea_case_failure_abort_handler),
            Case("ubirch protocol [plain] pack unsupported protocol variant",
                 TestProtocolUnsupported, greentea_case_failure_abort_handler),
            Case("ubirch protocol [plain] long message",
                 TestProtocolLongMessagePlain, greentea_case_failure_abort_handler),
            Case("ubirch protocol [plain] msgpack message",
                 TestMsgpackMessagePlain, greentea_case_failure_abort_handler),
//            Case("ubirch protocol [plain] free allocated heap",
//                 TestProtocolSimpleAPIFree, greentea_case_failure_abort_handler),
    };

    Specification specification(greentea_test_setup, cases, greentea_test_teardown_handler);
    Harness::run(specification);
}