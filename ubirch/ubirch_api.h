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

#define NUMBER_OF_HEADERS 4

typedef enum ubirch_api_service {
    ubirch_key_service,
    ubirch_niomon_service,
    ubirch_verification_service,
    ubirch_data_service
} ubirch_api_service;

typedef struct ubirch_api_headers {
    char **keys;
    char **values;
} ubirch_api_headers;

/**
 * Callback for sending http post requests
 * @return the response status code
 */
typedef int (*send_post_request)(const char *url, ubirch_api_headers headers, size_t number_of_headers,
                                 char *data, size_t data_len);

/**
 * Callback for sending http get requests
 * @return the response status code
 */
typedef int (*send_get_request)(const char *url);

/**
 * The ubirch api context
 */
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
 * @param api
 * @return 0 if not registered
 * @return 1 if registered
 */
int8_t is_key_registered(ubirch_api *api);

/**
 * Register the device public key at the ubirch backend
 * @param api the ubirch api context
 * @param key_reg_upp the msgpack encoded key registration message (UPP)
 * @param len the size of the message
 * @return 0 if key registration successful
 * @return -1 if key registration failed
 */
int8_t ubirch_api_register_key(ubirch_api *api, char *key_reg_upp, size_t len);

/**
 * Send data to the ubirch niomon service. Requires encoding before sending.
 * @param api the ubirch api context
 * @param upp the msgpack encoded message (UPP)
 * @param len the size of the message
 * @return 0 if sending successful
 * @return -1 if sending failed
 */
int8_t ubirch_api_niomon_send(ubirch_api *api, char *upp, size_t len);

/**
 * Verify a given hash with the ubirch backend. Requires base64 encoding before sending.
 * @param api the ubirch api context
 * @param data the base64 encoded hash of the message to verify
 * @param len the size of the base64 encoded hash
 * @return 0 if verification successful
 * @return -1 if verification failed
 */
int8_t ubirch_api_verify(ubirch_api *api, char *data, size_t len);

/**
 * Free memory for a ubirch api context.
 * @param api the api context
 */
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
