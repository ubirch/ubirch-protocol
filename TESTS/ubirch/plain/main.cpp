#include <unity/unity.h>
#include "ubirch/ubirch_protocol_api.h"
#include <armnacl.h>
#include <mbedtls/base64.h>

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

void TestProtocolMessage() {
    const unsigned char msg[] = {0x24, 0x98};
    const unsigned char expected_message[] = {
            0x94, 0x21, 0xc4, 0x10, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d,
            0x6e, 0x6f, 0x70, 0x00, 0xc4, 0x02, 0x24, 0x98,
    };

    ubirch_protocol *upp = ubirch_protocol_new(NULL);
    TEST_ASSERT_NOT_NULL_MESSAGE(upp, "creating UPP context failed");

    int8_t ret = ubirch_protocol_message(upp, proto_plain, UUID, UBIRCH_PROTOCOL_TYPE_BIN, msg, sizeof(msg));

    TEST_ASSERT_EQUAL_INT_MESSAGE(0, ret, "packing UPP failed");
    TEST_ASSERT_EQUAL_INT_MESSAGE(sizeof(expected_message), upp->size, "message length wrong");
    TEST_ASSERT_EQUAL_HEX8_ARRAY_MESSAGE(expected_message, upp->data, upp->size, "message serialization failed");

    ubirch_protocol_free(upp);
}

void TestProtocolSimpleMessage() {
    char _key[20], _value[300];
    size_t encoded_size;
    const char *msg = "simple message";

    ubirch_protocol *upp = ubirch_protocol_new(NULL);
    TEST_ASSERT_NOT_NULL_MESSAGE(upp, "creating UPP context failed");

    int8_t ret = ubirch_protocol_message(upp, proto_plain, UUID, UBIRCH_PROTOCOL_TYPE_BIN,
                                         reinterpret_cast<const unsigned char *> (msg), strlen(msg));
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, ret, "packing UPP failed");

    memset(_value, 0, sizeof(_value));
    mbedtls_base64_encode((unsigned char *) _value, sizeof(_value), &encoded_size,
                          (unsigned char *) upp->data, upp->size);
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

void TestProtocolSimpleAPIFree() {      //FIXME not passing
    const unsigned char msg[] = {0x24, 0x98};
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
                 TestProtocolMessage, greentea_case_failure_abort_handler),
            Case("ubirch protocol [plain] simple message",
                 TestProtocolSimpleMessage, greentea_case_failure_abort_handler),
//            Case("ubirch protocol [plain] free heap",
//                 TestProtocolSimpleAPIFree, greentea_case_failure_abort_handler),
    };

    Specification specification(greentea_test_setup, cases, greentea_test_teardown_handler);
    Harness::run(specification);
}