/*!
 * @file
 * @brief ubirch protocol API
 *
 * @author Roxana Meixner
 * @date   2019-08-23
 *
 * @copyright &copy; 2019 ubirch GmbH (https://ubirch.com)
 *
 * ```
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * ```
 */

#ifndef UBIRCH_PROTOCOL_API_H
#define UBIRCH_PROTOCOL_API_H

#ifdef __cplusplus
extern "C" {
#endif

#include "ubirch_protocol.h"
#include "ubirch_protocol_kex.h"
#include "ubirch_ed25519.h"

#if defined(MBEDTLS_CONFIG_FILE)
#include <mbedtls/sha512.h>
#else

#include "digest/sha512.h"

#endif

#include <stdio.h>  //TODO take this out (only for testing)

#define UPP_BUFFER_INIT_SIZE 217    //!< initial allocated size for UPP data buffer

typedef struct ubirch_protocol_buffer {
    size_t size;                                        //!< the number of bytes written to data buffer
    char *data;                                         //!< the data buffer to write UPP to
    size_t alloc;                                       //!< the number of bytes allocated for data buffer
    msgpack_packer packer;                              //!< the underlying target packer serializing data
    ubirch_protocol_sign sign;                          //!< the message signing function
    uint8_t version;                                    //!< the specific used protocol version
    uint8_t type;                                       //!< the payload type (0 - unspecified, app specific)
    unsigned char uuid[UBIRCH_PROTOCOL_UUID_SIZE];      //!< the uuid of the sender (used to retrieve the keys)
    unsigned char signature[UBIRCH_PROTOCOL_SIGN_SIZE]; //!< the current or previous signature of a message
    mbedtls_sha512_context hash;                        //!< the streaming hash of the data to sign
    uint8_t status;                                     //!< the status of the protocol package
    size_t header_size;
} ubirch_protocol_buffer;


static inline int ubirch_protocol_buffer_write(void *data, const char *buf, size_t len) {
    fprintf(stderr, "\r\nubirch_protocol_buffer_write\r\n");
    ubirch_protocol_buffer *upp = (ubirch_protocol_buffer *) data;

    // make sure there is enough space in data buffer
    if (upp->alloc - upp->size < len) {
        void *tmp = realloc(upp->data, upp->size + len);
        if (!tmp) { return -1; }
        upp->data = (char *) tmp;
    }

    // update the data hash
    if (upp->version == proto_signed || upp->version == proto_chained) {
        mbedtls_sha512_update(&upp->hash, (const unsigned char *) buf, len);
    }

    // append new data to buffer
    memcpy(upp->data + upp->size, buf, len);
    upp->size += len;

    return 0;
}

/**
 * Initialize Ubirch protocol context
 * @param upp the Ubirch protocol context
 * @param variant protocol variant
 * @param uuid the uuid associated with the data
 * @param payload_type the payload data type indicator (0 -> binary)
 * @return -1 if upp is NULL
 */
static inline int8_t ubirch_protocol_buffer_init(ubirch_protocol_buffer *upp,
                                                 ubirch_protocol_variant variant,
                                                 const unsigned char uuid[UBIRCH_PROTOCOL_UUID_SIZE],
                                                 uint8_t payload_type) {
    if (!upp) { return -1; }

    upp->size = 0;
    upp->data = (char *) malloc(UPP_BUFFER_INIT_SIZE);  // FIXME allocate memory according to variant
//    upp->data = (char *) realloc(upp->data, UPP_BUFFER_INIT_SIZE);
    if (upp->data == NULL) { return -1; }
    upp->alloc = UPP_BUFFER_INIT_SIZE;

    // initialize packer to use write data to UPP data buffer
    msgpack_packer_init(&upp->packer, upp, ubirch_protocol_buffer_write);

    // set user sign function
    if (variant == proto_signed || variant == proto_chained) {
        upp->sign = ed25519_sign;   //TODO always initialize to NULL and let user set?
    } else {
        upp->sign = NULL;
    }

    upp->version = variant; // FIXME optimize
    upp->type = payload_type;
    memcpy(upp->uuid, uuid, UBIRCH_PROTOCOL_UUID_SIZE);
    memset(upp->signature, 0, UBIRCH_PROTOCOL_SIGN_SIZE);
    upp->hash.is384 = -1;
    upp->status = UBIRCH_PROTOCOL_INITIALIZED;

    return 0;
}

/**
 * Start a new message. Writes the header data.
 * @param upp the Ubirch protocol context
 * @return -1 if upp is NULL
 * @return -2 if the protocol was not initialized before
 * @return -3 if the protocol version is not supported
 */
static inline int8_t ubirch_protocol_buffer_start(ubirch_protocol_buffer *upp) {
    if (!upp) { return -1; }
    if (upp->status !=
        UBIRCH_PROTOCOL_INITIALIZED) { return -2; }  //FIXME this check is not safe on uninitialized struct

    if (upp->version == proto_signed || upp->version == proto_chained) {
        mbedtls_sha512_init(&upp->hash);
        mbedtls_sha512_starts(&upp->hash, 0);
    }

    // the message consists of 3 header elements, the payload and (not included) the signature
    switch (upp->version) {
        case proto_plain:
            msgpack_pack_array(&upp->packer, 4);
            break;
        case proto_signed:
            msgpack_pack_array(&upp->packer, 5);
            break;
        case proto_chained:
            msgpack_pack_array(&upp->packer, 6);
            break;
        default:
            return -3;
    }

    // 1 - protocol version
    msgpack_pack_uint8(&upp->packer, upp->version);

    // 2 - device ID
    msgpack_pack_bin(&upp->packer, sizeof(upp->uuid));
    msgpack_pack_bin_body(&upp->packer, upp->uuid, sizeof(upp->uuid));

    // 3 the last signature (if chained)
    if (upp->version == proto_chained) {
        msgpack_pack_bin(&upp->packer, sizeof(upp->signature));
        msgpack_pack_bin_body(&upp->packer, upp->signature, sizeof(upp->signature));
    }

    // 4 the payload type
    msgpack_pack_uint8(&upp->packer, upp->type);

    upp->status = UBIRCH_PROTOCOL_STARTED;
    upp->header_size = upp->size;
    return 0;
}

/**
 * Create new Ubirch protocol context
 * @param variant protocol variant
 * @param uuid the uuid associated with the data
 * @param payload_type the payload data type indicator (0 -> binary)
 * @return the Ubirch protocol context
 */
static inline ubirch_protocol_buffer *ubirch_protocol_buffer_new(ubirch_protocol_variant variant,
                                                                 const unsigned char uuid[UBIRCH_PROTOCOL_UUID_SIZE],
                                                                 uint8_t payload_type) {

    int8_t error = 0;
    //TODO register key pair here?

    //allocate memory for UPP struct
    ubirch_protocol_buffer *upp = (ubirch_protocol_buffer *) malloc(sizeof(ubirch_protocol_buffer));
    if (upp == NULL) { return NULL; }

    // initialize UPP struct
    error = ubirch_protocol_buffer_init(upp, variant, uuid, payload_type);
    if (error) {
        fprintf(stderr, "\r\nUPP INIT FAILED! ERROR: %d\r\n\r\n", error);
        return NULL;
    }

    // pack UPP header
    error = ubirch_protocol_buffer_start(upp);
    if (error) {
        fprintf(stderr, "\r\nUPP START FAILED! ERROR: %d\r\n\r\n", error);
        return NULL;
    }

    return upp;
}


static inline int8_t ubirch_protocol_add_payload(ubirch_protocol_buffer *upp,
                                                 const unsigned char *payload, size_t payload_len) {
    if (!upp) { return -1; }
    if (upp->status != UBIRCH_PROTOCOL_STARTED) { return -2; }

    // 5 add the payload
    if (upp->type == UBIRCH_PROTOCOL_TYPE_REG) {
        // create a key registration packet and add it to UPP
        ubirch_key_info *info = (ubirch_key_info *) payload;
        msgpack_pack_key_register(&upp->packer, info);
    } else {
        // add payload as byte array to UPP
        msgpack_pack_bin(&upp->packer, payload_len);
        msgpack_pack_bin_body(&upp->packer, payload, payload_len);
    }

    upp->status = UBIRCH_PROTOCOL_HAS_PAYLOAD;

    return 0;
}

/**
 * Finish a message. Calculates the signature and attaches it to the message.
 * @param upp the ubirch protocol context
 * @return 0 if successful
 * @return -1 if upp is NULL
 * @return -2 if upp in not ready to be finished, call init, start and add_payload first
 * @return -3 if the signing failed
 */
static inline int8_t ubirch_protocol_buffer_finish(ubirch_protocol_buffer *upp) {
    if (!upp) { return -1; }
    if (upp->status != UBIRCH_PROTOCOL_HAS_PAYLOAD) { return -2; }

    // only add signature if we have a chained or signed message
    if (upp->version == proto_signed || upp->version == proto_chained) {
        unsigned char sha512sum[UBIRCH_PROTOCOL_HASH_SIZE];
        mbedtls_sha512_finish(&upp->hash, sha512sum);
        if (upp->sign(sha512sum, sizeof(sha512sum), upp->signature)) {
            return -3;
        }

        // 6 add signature hash
        msgpack_pack_bin(&upp->packer, UBIRCH_PROTOCOL_SIGN_SIZE);
        msgpack_pack_bin_body(&upp->packer, upp->signature, UBIRCH_PROTOCOL_SIGN_SIZE);
    }

    upp->status = UBIRCH_PROTOCOL_INITIALIZED;

    return 0;
}

/**
 * Pack payload to UPP and sign, if singed or chained type
 * @param upp the Ubirch protocol context
 * @param payload the byte array containing the payload data
 * @param payload_len the number of bytes in the payload
 * @return 0 if successful
 * @return -1 if upp is NULL
 * @return -2 if the signing failed
*/
static inline int8_t ubirch_protocol_pack(ubirch_protocol_buffer *upp,
                                           const unsigned char *payload, size_t payload_len) {

    if (!upp) { return -1; }
    int8_t error = 0;

    // clear buffer
    upp->size = upp->header_size;

    // add payload
    fprintf(stderr, "\r\nadd payload\r\n");
    ubirch_protocol_add_payload(upp, payload, payload_len);

    // sign the package
    fprintf(stderr, "\r\nsign\r\n");
    error = ubirch_protocol_buffer_finish(upp);
    if (error) { return -2; }

    return 0;
}

static inline int8_t ubirch_protocol_set_sign(ubirch_protocol_buffer *upp, ubirch_protocol_sign sign) {
    if (upp->status != UBIRCH_PROTOCOL_INITIALIZED) { return -1; }
    upp->sign = sign;
    return 0;
}


static inline void ubirch_protocol_buffer_free(ubirch_protocol_buffer *buf) {
    if (buf != NULL) {
        if (buf->data != NULL) {
            free(buf->data);
        }

        free(buf);
    }
}

static inline void printUPP(const char *data, const size_t len) {
    printf("\r\n - - - UPP - - - \r\n");
    printf("size: %d Bytes \r\nmsg: ", len);
    for (unsigned int i = 0; i < len; i++) {
//        printf("0x%02x, ", data[i]);
        printf("%02x", data[i]);
    }
    printf("\r\n\r\n");
}

#ifdef __cplusplus
}
#endif

#endif //UBIRCH_PROTOCOL_API_H