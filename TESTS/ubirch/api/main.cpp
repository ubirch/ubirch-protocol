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

static const unsigned char UUID[16] = {'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p'};

using namespace utest::v1;

void TestAPIGetServiceURL() {
    char *key_url_demo = ubirch_api_get_service_url(ubirch_key_service, "demo");
    TEST_ASSERT_EQUAL_INT(strlen(UBIRCH_API_KEY_SERVICE_DEMO), strlen(key_url_demo));
    TEST_ASSERT_EQUAL_STRING(UBIRCH_API_KEY_SERVICE_DEMO, key_url_demo);
    free(key_url_demo);

    char *niomon_url_dev = ubirch_api_get_service_url(ubirch_niomon_service, "dev");
    TEST_ASSERT_EQUAL_INT(strlen(UBIRCH_API_NIOMON_SERVICE_DEV), strlen(niomon_url_dev));
    TEST_ASSERT_EQUAL_STRING(UBIRCH_API_NIOMON_SERVICE_DEV, niomon_url_dev);
    free(niomon_url_dev);
}

void TestAPInew() {
    const char *auth_base64 = "pseudo_base64_auth_string";
    ubirch_api *api = ubirch_api_new(UUID, auth_base64, "demo", NULL);

    TEST_ASSERT_EQUAL_STRING("X-Ubirch-Hardware-Id", api->headers.keys[0]);
    TEST_ASSERT_EQUAL_STRING("61626364-6566-6768-696a-6b6c", api->headers.values[0]);
    TEST_ASSERT_EQUAL_STRING("X-Ubirch-Credential", api->headers.keys[1]);
    TEST_ASSERT_EQUAL_STRING(auth_base64, api->headers.values[1]);
    TEST_ASSERT_EQUAL_STRING("X-Ubirch-Auth-Type", api->headers.keys[2]);
    TEST_ASSERT_EQUAL_STRING("ubirch", api->headers.values[2]);

    free(api);
}

utest::v1::status_t greentea_test_setup(const size_t number_of_cases) {
    GREENTEA_SETUP(600, "ProtocolTests");
    return greentea_test_setup_handler(number_of_cases);
}

int main() {
    Case cases[] = {
            Case("ubirch API get service URL",
                 TestAPIGetServiceURL, greentea_case_failure_abort_handler),
            Case("ubirch API new",
                 TestAPInew, greentea_case_failure_abort_handler),
    };

    Specification specification(greentea_test_setup, cases, greentea_test_teardown_handler);
    Harness::run(specification);
}