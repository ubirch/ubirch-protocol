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

/**
 * Callback for sending http post requests
 * @return the response status code
 */
typedef int (*send_post_request)(const char *url, ubirch_api_headers headers, char *data,
                                 size_t data_len);

/**
 * Callback for sending http get requests
 * @return the response status code
 */
typedef int (*send_get_request)(const char *url);

typedef struct ubirch_api {
    char *uuid_string;  //!< the string representation of the device UUID
    ubirch_api_headers headers;
    char *env;
    send_post_request post;
    send_get_request get;
} ubirch_api;

ubirch_api *ubirch_api_new(const unsigned char *uuid, const char *auth_base64, const char *env,
                           send_post_request post, send_get_request get);

/**
 * Check if public key is registered at ubirch key service
 * @return 0 if not registered, 1 if registered
 */
int8_t is_key_registered(ubirch_api *api);

inline void ubirch_api_free(ubirch_api *api) {
    if (api != NULL) {
        if (api->uuid_string != NULL) {
            free(api->uuid_string);
        }
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
