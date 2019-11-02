//
// Created by larox on 02.11.19.
//

#ifndef UBIRCH_PROTOCOL_UBIRCH_API_H
#define UBIRCH_PROTOCOL_UBIRCH_API_H

#ifdef __cplusplus
extern "C" {
#endif

#define UBIRCH_API_KEY_SERVICE          0x01
#define UBIRCH_API_NIOMON_SERVICE       0x02
#define UBIRCH_API_VERIFICATION_SERVICE 0x03
#define UBIRCH_API_DATA_SERVICE         0x04

typedef enum ubirch_api_service {
    ubirch_key_service = UBIRCH_API_KEY_SERVICE
};

typedef struct ubirch_api {
    unsigned char uuid[UBIRCH_PROTOCOL_UUID_SIZE];      //!< the UUID of the sender
    const char *auth;
};

inline const char *ubirch_api_get_headers(ubirch_api api) {
    /**
     * TODO generate http hearder with
     * "X-Ubirch-Hardware-Id": "<<api->uuid>>,
     * "X-Ubirch-Credential": b64encode(<<api->auth>>),
     * "X-Ubirch-Auth-Type": "ubirch"
     * */
    return http_headers;
}

inline const char *ubirch_api_get_service_url(ubirch_api_service service) {
    //
    return url
}

#ifdef __cplusplus
}
#endif

#endif //UBIRCH_PROTOCOL_UBIRCH_API_H
