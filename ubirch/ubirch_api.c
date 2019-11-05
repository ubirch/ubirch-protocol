//
// Created by larox on 05.11.19.
//

#include "ubirch_api.h"

static char *ubirch_api_get_service_url(ubirch_api_service service, const char *env) {
    char temp_buffer[100];
    switch (service) {
        case ubirch_key_service:
            sprintf(temp_buffer, UBIRCH_API_KEY_SERVICE, env);
            break;
        case ubirch_niomon_service:
            sprintf(temp_buffer, UBIRCH_API_NIOMON_SERVICE, env);
            break;
        case ubirch_verification_service:
            sprintf(temp_buffer, UBIRCH_API_VERIFICATION_SERVICE, env);
            break;
        case ubirch_data_service:
            sprintf(temp_buffer, UBIRCH_API_DATA_SERVICE, env);
            break;
        default:
            return NULL;
    }
    return strdup(temp_buffer);
}

static char *ubirch_api_get_uuid_string(const unsigned char *uuid) {
    char uuid_string[36];
    const char *format = "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x";
    sprintf(uuid_string, format,
            uuid[0], uuid[1], uuid[2], uuid[3], uuid[4], uuid[5], uuid[6], uuid[7],
            uuid[8], uuid[9], uuid[10], uuid[11], uuid[12], uuid[13], uuid[14], uuid[15]
    );
    return strdup(uuid_string);
}


static void ubirch_api_init_headers(ubirch_api *api, const char *auth_base64) {
    const char *keys[NUMBER_OF_HEADERS] = {
            "X-Ubirch-Hardware-Id",
            "X-Ubirch-Credential",
            "X-Ubirch-Auth-Type"
    };

    const char *uuid_string = ubirch_api_get_uuid_string(api->uuid);
    const char *values[NUMBER_OF_HEADERS] = {
            uuid_string,
            auth_base64,
            "ubirch"
    };

    for (uint8_t i = 0; i < NUMBER_OF_HEADERS; i++) {
        api->headers.keys[i] = (char *) malloc(strlen(keys[i]));
        api->headers.values[i] = (char *) malloc(strlen(values[i]));
        strcpy(api->headers.keys[i], keys[i]);
        strcpy(api->headers.values[i], values[i]);
    }
}

ubirch_api *ubirch_api_new(const unsigned char *uuid, const char *auth_base64,
                           const char *env, send_http_request send_request) {
    ubirch_api *api = (ubirch_api *) malloc(sizeof(ubirch_api));
    if (api == NULL) {
        return NULL;
    }
    memcpy(api->uuid, uuid, UBIRCH_PROTOCOL_UUID_SIZE);
    api->env = (char *) malloc(strlen(env));
    strcpy(api->env, env);
    ubirch_api_init_headers(api, auth_base64);
    api->send_request = send_request;

    return api;
}