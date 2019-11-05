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

typedef int (*send_http_request)(ubirch_api_method method, const char *url, ubirch_api_headers, char *data,
                                 size_t data_len);

typedef struct ubirch_api {
    unsigned char uuid[UBIRCH_PROTOCOL_UUID_SIZE];  //!< the UUID of the sender
    ubirch_api_headers headers;
    char *env;
    send_http_request send_request;
} ubirch_api;

ubirch_api *ubirch_api_new(const unsigned char *uuid, const char *auth_base64,
                           const char *env, send_http_request send_request);

inline void ubirch_api_free(ubirch_api *api) {
    if (api != NULL) {
        if (api->env != NULL) {
            free(api->env);
        }
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
