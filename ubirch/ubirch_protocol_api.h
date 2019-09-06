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

#ifndef MSGPACK_ZONE_CHUNK_SIZE
#define MSGPACK_ZONE_CHUNK_SIZE 128
#endif

// we use an mbed port of msgpack which tries to include arpa/inet.h if __MBED__ is not defined
// so we fake it here, if we compile for another system. It does not have any other impact.
#ifndef __MBED__
#define __MBED__
#include <msgpack.h>
#undef __MBED__
#else
#include <msgpack.h>
#endif

#if defined(MBEDTLS_CONFIG_FILE)
#include <mbedtls/sha512.h>
#else
#include "digest/sha512.h"
#endif

#include "ubirch_protocol_kex.h"

#define UPP_BUFFER_INIT_SIZE 217    //!< initial allocation size for UPP data buffer, enough space for chained message with 64 byte payload

#define UBIRCH_PROTOCOL_VERSION     2       //!< current ubirch protocol version
#define UBIRCH_PROTOCOL_PLAIN       0x01    //!< plain protocol without signatures (unsafe)
#define UBIRCH_PROTOCOL_SIGNED      0x02    //!< signed messages (unchained)
#define UBIRCH_PROTOCOL_CHAINED     0x03    //!< chained signed messages

#define UBIRCH_PROTOCOL_PUBKEY_SIZE 32      //!< public key size
#define UBIRCH_PROTOCOL_SIGN_SIZE   64      //!< our signatures has 64 bytes (same as size of hash)
#define UBIRCH_PROTOCOL_UUID_SIZE   16      //!< the size of a UUID

#define UBIRCH_PROTOCOL_TYPE_BIN 0x00       //!< payload is undefined and binary
#define UBIRCH_PROTOCOL_TYPE_REG 0x01       //!< payload is defined as key register message
#define UBIRCH_PROTOCOL_TYPE_HSK 0x02       //!< payload is a key handshake message

typedef enum ubirch_protocol_variant {
    proto_plain = ((UBIRCH_PROTOCOL_VERSION << 4) | UBIRCH_PROTOCOL_PLAIN),
    proto_signed = ((UBIRCH_PROTOCOL_VERSION << 4) | UBIRCH_PROTOCOL_SIGNED),
    proto_chained = ((UBIRCH_PROTOCOL_VERSION << 4) | UBIRCH_PROTOCOL_CHAINED)
} ubirch_protocol_variant;

/**
 * The signature function type necessary to sign the message for the ubirch protocol.
 * This function is called from #ubirch_protocol_finish
 *
 * @param buf the data to sign
 * @param len the length of the data buffer
 * @param signature the buffer to hold the returned signature (64 byte)
 * @return 0 on success
 * @return -1 if the signing failed
 */
typedef int (*ubirch_protocol_sign)(const unsigned char *buf, size_t len,
                                    unsigned char signature[UBIRCH_PROTOCOL_SIGN_SIZE]);

/**
 * The verification function to check the validity of the message.
 * This function is called from #ubirch_protocol_verify
 *
 * @param buf the data to verify
 * @param len the length of the data buffer
 * @param signature the signature to check the data with (64 byte)
 * @return 0 on success
 * @return -1 if the verification failed
 */
typedef int (*ubirch_protocol_check)(const unsigned char *buf, size_t len,
                                     const unsigned char signature[UBIRCH_PROTOCOL_SIGN_SIZE]);

/**
 * ubirch protocol context, which holds a data buffer for the ubirch protocol package,
 * the underlying packer, the message signing function as well as the signature of last package.
 */
typedef struct ubirch_protocol_buffer {
    size_t size;                                        //!< the current number of bytes written to data buffer
    char *data;                                         //!< the data buffer to write UPP to
    size_t alloc;                                       //!< the current number of bytes allocated for data buffer
    msgpack_packer packer;                              //!< the underlying target packer for serializing data
    ubirch_protocol_sign sign;                          //!< the message signing function
    unsigned char signature[UBIRCH_PROTOCOL_SIGN_SIZE]; //!< the signature of the previous message, will be 0 on init
} ubirch_protocol_buffer;

/**
 * Callback for msgpack_packer to write data to UPP data buffer.
 *
 * @param data the ubirch protocol context
 * @param buf the data to write
 * @param len the length of the data
 * @return 0 if successful
 * @return -1 if fail to reallocate memory for data buffer
 */
static inline int ubirch_protocol_buffer_write(void *data, const char *buf, size_t len) {
    ubirch_protocol_buffer *upp = (ubirch_protocol_buffer *) data;

    // make sure there is enough space in data buffer
    if (upp->alloc - upp->size < len) {
        void *tmp = realloc(upp->data, upp->size + len);
        if (!tmp) { return -1; }
        upp->data = (char *) tmp;
    }

    // append new data to buffer
    memcpy(upp->data + upp->size, buf, len);
    upp->size += len;

    return 0;
}

/**
 * Create new ubirch protocol context
 *
 * @param sign a callback used for signing a message
 * @return a new initialized ubirch protocol context
 */
static inline ubirch_protocol_buffer *ubirch_protocol_buffer_new(ubirch_protocol_sign sign) {

    //allocate memory for UPP struct
    ubirch_protocol_buffer *upp = (ubirch_protocol_buffer *) malloc(sizeof(ubirch_protocol_buffer));
    if (upp == NULL) { return NULL; }

    // initialize struct, allocate memory for data buffer
    upp->data = (char *) malloc(UPP_BUFFER_INIT_SIZE);
    if (upp->data == NULL) { return NULL; }
    upp->alloc = UPP_BUFFER_INIT_SIZE;

    // initialize packer to write data to UPP data buffer
    msgpack_packer_init(&upp->packer, upp, ubirch_protocol_buffer_write);

    // set user sign function
    upp->sign = sign;

    memset(upp->signature, 0, UBIRCH_PROTOCOL_SIGN_SIZE);

    return upp;
}


/**
 * Start a new message. Writes the header data.
 *
 * @param upp the Ubirch protocol context
 * @return -1 if upp is NULL
 * @return -2 if the protocol version is not supported
 */
static inline int8_t ubirch_protocol_buffer_start(ubirch_protocol_buffer *upp,
                                                  ubirch_protocol_variant variant,
                                                  const unsigned char uuid[UBIRCH_PROTOCOL_UUID_SIZE],
                                                  uint8_t payload_type) {

    // the message consists of 3 header elements, the payload and (not included) the signature
    switch (variant) {
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
            return -2;
    }

    // 1 - protocol version
    msgpack_pack_uint8(&upp->packer, variant);

    // 2 - device ID
    msgpack_pack_bin(&upp->packer, UBIRCH_PROTOCOL_UUID_SIZE);
    msgpack_pack_bin_body(&upp->packer, uuid, UBIRCH_PROTOCOL_UUID_SIZE);

    // 3 the last signature (if chained)
    if (variant == proto_chained) {
        msgpack_pack_bin(&upp->packer, sizeof(upp->signature));
        msgpack_pack_bin_body(&upp->packer, upp->signature, sizeof(upp->signature));
    }

    // 4 the payload type
    msgpack_pack_uint8(&upp->packer, payload_type);

    return 0;
}

static inline int8_t ubirch_protocol_add_payload(ubirch_protocol_buffer *upp,
                                                 uint8_t payload_type,
                                                 const unsigned char *payload, size_t payload_len) {
    // 5 add the payload
    if (payload_type == UBIRCH_PROTOCOL_TYPE_REG) {
        // create a key registration packet and add it to UPP
        ubirch_key_info *info = (ubirch_key_info *) payload;
        msgpack_pack_key_register(&upp->packer, info);
    } else {
        // add payload as byte array to UPP
        msgpack_pack_bin(&upp->packer, payload_len);
        msgpack_pack_bin_body(&upp->packer, payload, payload_len);
    }

    return 0;
}

/**
 * Finish a message. Calculates the signature and attaches it to the message.
 * @param upp the ubirch protocol context
 * @return 0 if successful
 * @return -1 if upp is NULL
 * @return -2 if the signing failed
 */
static inline int8_t ubirch_protocol_buffer_finish(ubirch_protocol_buffer *upp, ubirch_protocol_variant variant) {

    // only add signature if we have a chained or signed message
    if (variant == proto_signed || variant == proto_chained) {
        unsigned char sha512sum[UBIRCH_PROTOCOL_SIGN_SIZE];
        mbedtls_sha512((const unsigned char *) upp->data, upp->size, sha512sum, 0);
        if (upp->sign(sha512sum, sizeof(sha512sum), upp->signature)) {
            return -2;
        }

        // 6 add signature hash
        msgpack_pack_bin(&upp->packer, UBIRCH_PROTOCOL_SIGN_SIZE);
        msgpack_pack_bin_body(&upp->packer, upp->signature, UBIRCH_PROTOCOL_SIGN_SIZE);
    }

    return 0;
}

/**
 * Pack payload to UPP and sign, if singed or chained type
 * @param upp the Ubirch protocol context
 * @param variant protocol variant
 * @param uuid the uuid associated with the data
 * @param payload_type the payload data type indicator (0 -> binary)
 * @param payload the byte array containing the payload data
 * @param payload_len the number of bytes in the payload
 * @return 0 if successful
 * @return -1 if upp is not initialized
 * @return -2 if no sign callback was provided
 * @return -3 if the protocol version is not supported
 * @return -4 if the signing failed
*/
static inline int8_t ubirch_protocol_pack(ubirch_protocol_buffer *upp,
                                          ubirch_protocol_variant variant,
                                          const unsigned char uuid[UBIRCH_PROTOCOL_UUID_SIZE],
                                          uint8_t payload_type,
                                          const unsigned char *payload, size_t payload_len) {
    int8_t error = 0;
    // check if UPP struct has been initialized
    if (upp == NULL || upp->data == NULL) { return -1; }

    // for protocol variants with signature, check if a sign callback is provided
    if (variant == proto_signed || variant == proto_chained) {
        if (upp->sign == NULL) { return -2; }
    }

    // clear buffer
    upp->size = 0;

    // pack UPP header
    error = ubirch_protocol_buffer_start(upp, variant, uuid, payload_type);
    if (error) { return -3; }

    // add payload
    ubirch_protocol_add_payload(upp, payload_type, payload, payload_len);

    // sign the package
    error = ubirch_protocol_buffer_finish(upp, variant);
    if (error) { return -4; }

    return 0;
}

/**
 * Free memory for a ubirch protocol context.
 * @param proto the protocol context
 */
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