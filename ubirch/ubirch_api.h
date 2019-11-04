//
// Created by larox on 02.11.19.
//

#ifndef UBIRCH_PROTOCOL_UBIRCH_API_H
#define UBIRCH_PROTOCOL_UBIRCH_API_H

#ifdef __cplusplus
extern "C" {
#endif

#include "ubirch_protocol.h"

#define UBIRCH_API_KEY_SERVICE          "https://key.%s.ubirch.com/api/keyService/v1/pubkey"
#define UBIRCH_API_NIOMON_SERVICE       "https://niomon.%s.ubirch.com/"
#define UBIRCH_API_VERIFICATION_SERVICE "https://verify.%s.ubirch.com/api/upp"
#define UBIRCH_API_DATA_SERVICE         "https://data.%s.ubirch.com/v1"

#define NUMBER_OF_HEADERS 3

typedef enum ubirch_api_method {
    http_request_get,
    http_request_post,
    http_request_delete
} ubirch_api_method;

typedef enum ubirch_api_service {
    ubirch_key_service,
    ubirch_niomon_service,
    ubirch_verification_service,
    ubirch_data_service
} ubirch_api_service;

typedef struct ubirch_api_headers {
    char *keys[NUMBER_OF_HEADERS];
    char *values[NUMBER_OF_HEADERS];
} ubirch_api_headers;

typedef int (*send_http_request)(ubirch_api_method method, const char *url, ubirch_api_headers);

typedef struct ubirch_api {
    unsigned char uuid[UBIRCH_PROTOCOL_UUID_SIZE];  //!< the UUID of the sender
    ubirch_api_headers headers;
    char *env;
    send_http_request send_request;
} ubirch_api;


inline char *ubirch_api_get_service_url(ubirch_api_service service, const char *env) {
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

inline const char *ubirch_api_get_uuid_string(const unsigned char *uuid) {
    char *uuid_string = (char *) malloc(UBIRCH_PROTOCOL_UUID_SIZE + 5);
    sprintf(uuid_string,
            "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
            uuid[0], uuid[1], uuid[2], uuid[3], uuid[4], uuid[5], uuid[6], uuid[7],
            uuid[8], uuid[9], uuid[10], uuid[11], uuid[12], uuid[13], uuid[14], uuid[15]
    );
    return uuid_string;
}

inline void ubirch_api_init_headers(ubirch_api *api, const char *auth_base64) {
    const char *keys[] = {
            "X-Ubirch-Hardware-Id",
            "X-Ubirch-Credential",
            "X-Ubirch-Auth-Type"
    };

    const char *uuid_string = ubirch_api_get_uuid_string(api->uuid);
    const char *values[] = {
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
    return;
}

inline ubirch_api *ubirch_api_new(const unsigned char *uuid, const char *auth_base64,
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

inline void ubirch_api_free(ubirch_api *api) {
    if (api != NULL) {
        for (uint8_t i = 0; i < NUMBER_OF_HEADERS; i++) {
            if (api->headers.keys[i] != NULL) {
                free(api->headers.keys[i]);
                free(api->headers.values[i]);
            }
        }
        free(api);
    }
}

#ifdef __cplusplus
}
#endif

#endif //UBIRCH_PROTOCOL_UBIRCH_API_H
