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

typedef enum ubirch_api_service {
    ubirch_key_service,
    ubirch_niomon_service,
    ubirch_verification_service,
    ubirch_data_service
} ubirch_api_service;

typedef struct ubirch_api {
    unsigned char uuid[UBIRCH_PROTOCOL_UUID_SIZE];  //!< the UUID of the sender
    const char *auth;                               //!< the user authorization token
} ubirch_api;

inline const char *ubirch_api_get_service_url(ubirch_api_service service, const char *env) {
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
    char *url = (char *) malloc(strlen(temp_buffer));
    strcpy(url, temp_buffer);
    return (const char *) url;
}

inline const char *ubirch_api_get_headers(ubirch_api api) {
    const char *http_headers;
    /**
     * TODO generate http header
     * "X-Ubirch-Hardware-Id": "<<api->uuid>>,
     * "X-Ubirch-Credential": b64encode(<<api->auth>>),
     * "X-Ubirch-Auth-Type": "ubirch"
     * */
    return http_headers;
}

#ifdef __cplusplus
}
#endif

#endif //UBIRCH_PROTOCOL_UBIRCH_API_H
