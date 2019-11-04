#include <unity/unity.h>
#include "ubirch/ubirch_api.h"
#include <ubirch/ubirch_ed25519.h>
#include <mbedtls/base64.h>
#include <msgpack.h>

#include "utest/utest.h"
#include "greentea-client/test_env.h"

#define UBIRCH_API_KEY_SERVICE_DEMO          "https://key.demo.ubirch.com/api/keyService/v1/pubkey"
#define UBIRCH_API_KEY_SERVICE_DEV           "https://key.dev.ubirch.com/api/keyService/v1/pubkey"
#define UBIRCH_API_NIOMON_SERVICE_DEMO       "https://niomon.demo.ubirch.com/"
#define UBIRCH_API_NIOMON_SERVICE_DEV        "https://niomon.dev.ubirch.com/"
#define UBIRCH_API_VERIFICATION_SERVICE_DEMO "https://verify.demo.ubirch.com/api/upp"
#define UBIRCH_API_VERIFICATION_SERVICE_DEV  "https://verify.dev.ubirch.com/api/upp"
#define UBIRCH_API_DATA_SERVICE_DEMO         "https://data.demo.ubirch.com/v1"
#define UBIRCH_API_DATA_SERVICE_DEV          "https://data.dev.ubirch.com/v1"

using namespace utest::v1;

void TestAPIGetServiceURL() {
    const char *key_url_demo = ubirch_api_get_service_url(ubirch_key_service, "demo");
    TEST_ASSERT_EQUAL_INT(strlen(UBIRCH_API_KEY_SERVICE_DEMO), strlen(key_url_demo));
    TEST_ASSERT_EQUAL_STRING(UBIRCH_API_KEY_SERVICE_DEMO, key_url_demo);

    const char *niomon_url_dev = ubirch_api_get_service_url(ubirch_niomon_service, "dev");
    TEST_ASSERT_EQUAL_INT(strlen(UBIRCH_API_NIOMON_SERVICE_DEV), strlen(niomon_url_dev));
    TEST_ASSERT_EQUAL_STRING(UBIRCH_API_NIOMON_SERVICE_DEV, niomon_url_dev);
}

utest::v1::status_t greentea_test_setup(const size_t number_of_cases) {
    GREENTEA_SETUP(600, "ProtocolTests");
    return greentea_test_setup_handler(number_of_cases);
}

int main() {
    Case cases[] = {
            Case("ubirch API get service URL",
                 TestAPIGetServiceURL, greentea_case_failure_abort_handler),
    };

    Specification specification(greentea_test_setup, cases, greentea_test_teardown_handler);
    Harness::run(specification);
}