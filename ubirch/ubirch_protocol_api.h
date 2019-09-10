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

#include "ubirch_protocol.h"
#include "ubirch_protocol_kex.h"

#ifdef __cplusplus
extern "C" {
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
 * Ubirch protocol context, which holds a data buffer for the ubirch protocol package,
 * the underlying packer, the message signing function as well as the signature of last package.
 */
typedef struct ubirch_protocol {
    size_t size;                                        //!< the current number of bytes written to data buffer
    char *data;                                         //!< the data buffer to write UPP to
    size_t alloc;                                       //!< the current number of bytes allocated for data buffer
    msgpack_packer packer;                              //!< the underlying target packer for serializing data
    ubirch_protocol_sign sign;                          //!< the message signing function
    unsigned char signature[UBIRCH_PROTOCOL_SIGN_SIZE]; //!< the signature of the previous message, will be 0 on init
} ubirch_protocol;

/**
 * Create new ubirch protocol context
 *
 * @param sign a callback used for signing a message, can be NULL if no signing required (i.e. plain protocol variant)
 * @return a new initialized ubirch protocol context
 */
static ubirch_protocol *ubirch_protocol_new(ubirch_protocol_sign sign);

/**
 * Generate a ubirch protocol message
 *
 * @param upp the ubirch protocol context
 * @param variant protocol variant
 * @param uuid the uuid associated with the data
 * @param payload_type the payload data type indicator (0 -> binary)
 * @param payload the byte array containing the payload data or key registration info
 * @param payload_len the size of the payload in bytes
 * @return 0 if successful
 * @return -1 if upp is not initialized
 * @return -2 if no sign callback was provided
 * @return -3 if the protocol version is not supported
 * @return -4 if the signing failed
*/
int8_t ubirch_protocol_message(ubirch_protocol *upp, ubirch_protocol_variant variant,
                               const unsigned char *uuid, uint8_t payload_type,
                               const unsigned char *payload, size_t payload_len);

/**
 * Verify a messages signature.
 *
 * @param upp the ubirch protocol context containing the message to verify
 * @param verify the private key to use for verification
 * @return 0 if the verification is successful
 * @return -1 if the signature verification has failed
 * @return -2 if upp is NULL or the message length is wrong (too short to actually do a check)
 */
int8_t ubirch_protocol_verify(ubirch_protocol *upp, ubirch_protocol_check verify);

/**
 * Free memory for a ubirch protocol context.
 * @param upp the protocol context
 */
static void ubirch_protocol_free(ubirch_protocol *upp);

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
    }

    // append new data to buffer
    memcpy(upp->data + upp->size, buf, len);
    upp->size += len;

    return 0;
}

inline ubirch_protocol *ubirch_protocol_new(ubirch_protocol_sign sign) {
    ubirch_protocol *upp = (ubirch_protocol *) malloc(sizeof(ubirch_protocol));
    if (upp == NULL) {
        return NULL;
    }

    // initialize upp context, allocate memory for data buffer
    upp->data = (char *) malloc(UPP_BUFFER_INIT_SIZE);
    if (upp->data == NULL) {
        free(upp);
        return NULL;
    }
    upp->alloc = UPP_BUFFER_INIT_SIZE;

    // initialize packer to write data to UPP data buffer
    msgpack_packer_init(&upp->packer, upp, ubirch_protocol_write);

    // set user sign function
    upp->sign = sign;

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