/*!
 * @file
 * @brief ubirch protocol implementation based on msgpack
 *
 * The basic ubirch protocol implementation based on msgpack.
 * A ubirch protocol message consists of a header, payload and
 * a signature. The signature is calculated from the hash (sha512)
 * of the msgpack data in front of the signature, excluding
 * the msgpack type marker for the signature.
 *
 * How to generate ubirch protocol messages:
 *
 * ```
 * // create a ubirch protocol context and provide the UUID and sign function
 * ubirch_protocol *upp = ubirch_protocol_new(UUID, ed25519_sign);
 *
 * // to pack a message, pass the ubirch protocol context, the desired protocol variant (plain, signed or chained),
 * // a hint to the message payload type (binary or key registration) and the payload followed by
 * // it's size in bytes. The payload may be a byte array or ubirch key info.
 * int8_t ret = ubirch_protocol_message(upp, proto_chained, UBIRCH_PROTOCOL_TYPE_BIN, msg, sizeof(msg));
 *
 * // generate a chained message, which contains the signature of the previous one, by calling the message function
 * // again, passing the same context to it.
 * ret = ubirch_protocol_message(upp, proto_chained, UUID, UBIRCH_PROTOCOL_TYPE_BIN, next_msg, sizeof(next_msg));
 *
 * // Finally, free the allocated memory for the context
 * ubirch_protocol_free(upp);
 * ```
 * 
 * After calling ubirch_protocol_message, the protocol context contains
 * the ubirch protocol package (upp->data) and it's size in bytes (upp->size).
 *
 *
 * @author Matthias L. Jugel
 * @date   2018-01-01
 *
 * @copyright &copy; 2018 ubirch GmbH (https://ubirch.com)
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

#ifndef UBIRCH_PROTOCOL_H
#define UBIRCH_PROTOCOL_H

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

#define UBIRCH_PROTOCOL_VERSION     2       //!< current ubirch protocol version
#define UBIRCH_PROTOCOL_PLAIN       0x01    //!< plain protocol without signatures (unsafe)
#define UBIRCH_PROTOCOL_SIGNED      0x02    //!< signed messages (unchained)
#define UBIRCH_PROTOCOL_CHAINED     0x03    //!< chained signed messages

#define UBIRCH_PROTOCOL_PUBKEY_SIZE 32      //!< public key size
#define UBIRCH_PROTOCOL_SIGN_SIZE   64      //!< our signatures has 64 bytes
#define UBIRCH_PROTOCOL_HASH_SIZE   64      //!< size of the hash
#define UBIRCH_PROTOCOL_UUID_SIZE   16      //!< the size of a UUID

#define UBIRCH_PROTOCOL_TYPE_BIN     0x00    //!< payload is undefined and binary
#define UBIRCH_PROTOCOL_TYPE_REG     0x01    //!< payload is defined as key register message
#define UBIRCH_PROTOCOL_TYPE_HSK     0x02    //!< payload is a key handshake message
#define UBIRCH_PROTOCOL_TYPE_MSGPACK 0x32   //!< payload is a ubirch standard sensor message (msgpack)
#define UBIRCH_PROTOCOL_TYPE_MAP     0x53   //!< payload is a generic sensor message (json type key/value map)
#define UBIRCH_PROTOCOL_TYPE_TRACKLE_MSG    0x54   //!< payload is a trackle message packet
#define UBIRCH_PROTOCOL_TYPE_RESP    0x55   //!< payload is a ubirch/trackle message response

#define UPP_BUFFER_INIT_SIZE 219            //!< initial allocation size for UPP data buffer, enough space for chained message with 64 byte payload


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
 * @param signature the signature output (64 byte)
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
 * Ubirch protocol context, which holds a data buffer for the ubirch protocol package,
 * the underlying packer, the message signing function as well as the signature of last package.
 */
typedef struct ubirch_protocol {
    size_t size;                                        //!< the current number of bytes written to data buffer
    char *data;                                         //!< the data buffer to write UPP to
    size_t alloc;                                       //!< the current number of bytes allocated for data buffer
    msgpack_packer packer;                              //!< the underlying target packer for serializing data
    ubirch_protocol_sign sign;                          //!< the message signing function
    unsigned char uuid[UBIRCH_PROTOCOL_UUID_SIZE];      //!< the uuid of the sender (used to retrieve the keys)
    unsigned char signature[UBIRCH_PROTOCOL_SIGN_SIZE]; //!< the signature of the previous message, will be 0 on init
} ubirch_protocol;

/**
 * Create new ubirch protocol context. Allocates memory for context and data buffer on heap,
 * initializes msgpack_packer, sets user sign callback and UUID and initializes previous signature to 0.
 *
 * @param uuid the uuid of the sender
 * @param sign the signing function, can be NULL if no signing required (i.e. plain protocol variant)
 * @return a new initialized ubirch protocol context
 */
static ubirch_protocol *ubirch_protocol_new(const unsigned char *uuid, ubirch_protocol_sign sign);

/**
 * Generate a ubirch protocol message
 *
 * @param upp the ubirch protocol context
 * @param variant the protocol variant
 * @param payload_type the payload data type indicator (0 -> binary)
 * @param payload the payload data or key registration info to be sealed
 * @param payload_len the size of the payload in bytes
 * @return 0 if successful
 * @return -1 if upp is not initialized
 * @return -2 if the protocol version is not supported
 * @return -3 if the payload type is not supported
 * @return -4 if the signing failed or no signing callback has been provided
*/
int8_t ubirch_protocol_message(ubirch_protocol *upp, ubirch_protocol_variant variant, uint8_t payload_type,
                               const char *payload, size_t payload_len);

/**
 * Free memory for a ubirch protocol context.
 * @param upp the protocol context
 */
static void ubirch_protocol_free(ubirch_protocol *upp);

/**
 * Verify a messages signature.
 *
 * @param data the message to verify
 * @param data_len the size of the message
 * @param verify the verification function
 * @return 0 if the verification is successful
 * @return -1 if the signature verification has failed
 * @return -2 if data is NULL pointer or the message length is wrong (too short to actually do a check)
 */
int8_t ubirch_protocol_verify(char *data, size_t data_len, ubirch_protocol_check verify);

/**
 * Callback for msgpack_packer to write data to UPP data buffer.
 *
 * @param data the ubirch protocol context
 * @param buf the data to write
 * @param len the length of the data
 * @return 0 if successful
 * @return -1 if fail to reallocate memory for data buffer
 */
static inline int ubirch_protocol_write(void *data, const char *buf, size_t len) {
    ubirch_protocol *upp = (ubirch_protocol *) data;

    // make sure there is enough space in data buffer
    if (upp->alloc - upp->size < len) {
        void *tmp = realloc(upp->data, upp->size + len);
        if (!tmp) { return -1; }
        upp->data = (char *) tmp;
        upp->alloc = upp->size + len;
    }

    // append new data to buffer
    memcpy(upp->data + upp->size, buf, len);
    upp->size += len;

    return 0;
}

inline ubirch_protocol *ubirch_protocol_new(const unsigned char *uuid, ubirch_protocol_sign sign) {
    // allocate memory for context
    ubirch_protocol *upp = (ubirch_protocol *) malloc(sizeof(ubirch_protocol));
    if (upp == NULL) {
        return NULL;
    }
    // allocate memory for data buffer
    upp->data = (char *) malloc(UPP_BUFFER_INIT_SIZE);
    if (upp->data == NULL) {
        free(upp);
        return NULL;
    }
    // initialize context
    upp->size = 0;
    upp->alloc = UPP_BUFFER_INIT_SIZE;
    msgpack_packer_init(&upp->packer, upp, ubirch_protocol_write);
    upp->sign = sign;
    memcpy(upp->uuid, uuid, UBIRCH_PROTOCOL_UUID_SIZE);
    memset(upp->signature, 0, UBIRCH_PROTOCOL_SIGN_SIZE);

    return upp;
}

inline void ubirch_protocol_free(ubirch_protocol *upp) {
    if (upp != NULL) {
        if (upp->data != NULL) {
            free(upp->data);
        }
        free(upp);
    }
}

#ifdef __cplusplus
}
#endif

#endif //UBIRCH_PROTOCOL_H