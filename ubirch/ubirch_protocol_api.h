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
    size_t size;
    char data[UPP_BUFFER_INIT_SIZE];
    size_t alloc;
    msgpack_packer *packer;                             //!< the underlying target packer serializing data
    ubirch_protocol_sign sign;                          //!< the message signing function
    uint8_t version;                                    //!< the specific used protocol version
    uint8_t type;                                       //!< the payload type (0 - unspecified, app specific)
    unsigned char uuid[UBIRCH_PROTOCOL_UUID_SIZE];      //!< the uuid of the sender (used to retrieve the keys)
    unsigned char signature[UBIRCH_PROTOCOL_SIGN_SIZE]; //!< the current or previous signature of a message
    mbedtls_sha512_context hash;                        //!< the streaming hash of the data to sign
    uint8_t status;                                     //!< the status of the protocol package
} ubirch_protocol_buffer;


static inline uint8_t ubirch_protocol_buffer_write(void *data, const char *buf, size_t len) {
    ubirch_protocol_buffer *upp = (ubirch_protocol_buffer *) data;

    if (upp->version == proto_signed || upp->version == proto_chained) {
        mbedtls_sha512_update(&upp->hash, (const unsigned char *) buf, len);
    }

    if (upp->alloc - upp->size < len) {
        void *tmp = realloc(upp->data, upp->size + len);
        if (!tmp) { return -1; }
        upp->data = (char *) tmp;
    }

    memcpy(upp->data + upp->size, buf, len);
    upp->size += len;
    return 0;
}

static inline void ubirch_protocol_buffer_init(ubirch_protocol_buffer *upp,
                                               ubirch_protocol_variant variant,
                                               const unsigned char uuid[UBIRCH_PROTOCOL_UUID_SIZE],
                                               uint8_t payload_type) {
    memset(upp, 0, sizeof(upp));
    upp->alloc = UPP_BUFFER_INIT_SIZE;
    msgpack_packer_init(upp->packer, upp, ubirch_protocol_buffer_write);
    upp->ubirch_protocol_sign = ed25519_sign;
    upp->version = variant;
    upp->type = payload_type;
    memcpy(upp->uuid, uuid, UBIRCH_PROTOCOL_UUID_SIZE);
    upp->hash.is384 = -1;
    upp->status = UBIRCH_PROTOCOL_INITIALIZED;
}

/**
 * Start a new message. Clears out previous data and writes the header data.
 * @param upp the Ubirch protocol context
 * @return -1 if upp is NULL
 * @return -2 if the protocol was not initialized
 * @return -3 if the protocol version is not supported
 */
static inline uint8_t ubirch_protocol_buffer_start(ubirch_protocol_buffer *upp) {
    if (!upp) { return -1; }
    if (upp->status != UBIRCH_PROTOCOL_INITIALIZED) { return -2; }

    if (upp->version == proto_signed || upp->version == proto_chained) {
        mbedtls_sha512_init(&upp->hash);
        mbedtls_sha512_starts(&upp->hash, 0);
    }

    // the message consists of 3 header elements, the payload and (not included) the signature
    switch (upp->version) {
        case proto_plain:
            msgpack_pack_array(upp->packer, 4);
            break;
        case proto_signed:
            msgpack_pack_array(upp->packer, 5);
            break;
        case proto_chained:
            msgpack_pack_array(upp->packer, 6);
            break;
        default:
            return -3;
    }

    // 1 - protocol version
    msgpack_pack_uint8(upp->packer, upp->version);

    // 2 - device ID
    msgpack_pack_bin(upp->packer, sizeof(upp->uuid));
    msgpack_pack_bin_body(upp->packer, upp->uuid, sizeof(upp->uuid));

    // 3 the last signature (if chained)
    if (upp->version == proto_chained) {
        msgpack_pack_bin(upp->packer, sizeof(upp->signature));
        msgpack_pack_bin_body(upp->packer, upp->signature, sizeof(upp->signature));
    }

    // 4 the payload type
    msgpack_pack_uint8(upp->packer, upp->type);

    upp->status = UBIRCH_PROTOCOL_STARTED;
    return 0;
}

/**
 * Finish a message. Calculates the signature and attaches it to the message.
 * @param upp the ubirch protocol context
 * @return 0 if successful
 * @return -1 if upp is NULL
 * @return -2 if used before ubirch_protocol_start or does not have any payload
 * @return -3 if the signing failed
 */
static inline uint8_t ubirch_protocol_add_payload(ubirch_protocol_buffer *upp,
                                                  const unsigned char *payload, size_t payload_len) {
    if (!upp) { return -1; }
    if (upp->status != UBIRCH_PROTOCOL_STARTED) { return -2; }

    // 5 add the payload
    if (payload_type == UBIRCH_PROTOCOL_TYPE_REG) {
        // create a key registration packet and add it to UPP
        ubirch_key_info *info = (ubirch_key_info *) payload;
        msgpack_pack_key_register(upp->packer, info);
    } else {
        // add payload as byte array to UPP
        msgpack_pack_bin(upp->packer, payload_len);
        msgpack_pack_bin_body(upp->packer, payload, payload_len);
    }

    upp->status = UBIRCH_PROTOCOL_HAS_PAYLOAD;

    return 0;
}

/**
 * Finish a message. Calculates the signature and attaches it to the message.
 * @param upp the ubirch protocol context
 * @return 0 if successful
 * @return -1 if upp is NULL
 * @return -2 if used before ubirch_protocol_start or ubirch_protocol_add_payload
 * @return -3 if the signing failed
 */
static inline uint8_t ubirch_protocol_buffer_finish(ubirch_protocol_buffer *upp) {
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
        msgpack_pack_bin(pk, UBIRCH_PROTOCOL_SIGN_SIZE);
        msgpack_pack_bin_body(pk, upp->signature, UBIRCH_PROTOCOL_SIGN_SIZE);
    }

    upp->status = UBIRCH_PROTOCOL_INITIALIZED;

    return 0;
}

/**
 * Create a UPP (Ubirch Protocol Package)
 *
 * @param upp the Ubirch protocol context
 * @param variant protocol variant
 * @param uuid the uuid associated with the data
 * @param payload_type the payload data type indicator (0 -> binary)
 * @param payload the byte array containing the payload data
 * @param payload_len the number of bytes in the payload
 * @return 0 if successful
 * @return -1 if upp is NULL
 * @return -2 protocol version not supported
 * @return -3 if the signing failed
*/
static inline uint8_t ubirch_protocol_pack(ubirch_protocol_buffer *upp,
                                           ubirch_protocol_variant variant,
                                           const unsigned char uuid[UBIRCH_PROTOCOL_UUID_SIZE],
                                           uint8_t payload_type,
                                           const unsigned char *payload, size_t payload_len) {
    uint8_t error = 0;
    if (!upp) { return -1; }
    // initialize UPP context
    ubirch_protocol_buffer_init(upp, variant, uuid, payload_type);

    // pack UPP header
    error = ubirch_protocol_buffer_start(upp);
    if (error) { return -2 }

    // add payload
    ubirch_protocol_add_payload(upp, payload, payload_len);

    // sign the package
    error = ubirch_protocol_buffer_finish(upp);
    if (error) { return -3 }

    return 0;
}

/**
 * Create a chained UPP with new payload (chained to a previously created UPP)
 *
 * @param previous_upp the previous UPP, this buffer will be filled with the new UPP data
 * @param payload the byte array containing the new payload data
 * @param payload_len the number of bytes in the new payload
 * @return 0 if successful
 * @return -1 if previous UPP either empty or was not chained
 * @return -2 if allocating memory for new message failed
 * @return -3 if the signing failed
*/
static inline int ubirch_protocol_chain_message(ubirch_protocol_buffer *previous_upp, const unsigned char *payload,
                                                size_t payload_len) {
    if (!previous_upp || !previous_upp->data || !previous_upp->size) { return -1; }
    // make sure previous UPP was chained
    if (previous_upp->data[1] != proto_chained) { return -1; }

    // get a pointer to start of signature of previous UPP
    char *upp_signature = previous_upp->data + (previous_upp->size - UBIRCH_PROTOCOL_SIGN_SIZE);
    // get a pointer to start of UPP field for previous signature
    char *previous_signature_field = previous_upp->data + 22;  // FIXME magic number (version + UUID + 5 msgpack-bytes)
    // write signature of previous UPP in previous-signature-field of new UPP
    memcpy(previous_signature_field, upp_signature, UBIRCH_PROTOCOL_SIGN_SIZE);

    // make sure, there is enough space for new payload
    size_t unsigned_upp_size = 89 + payload_len;
    if (previous_upp->size - UBIRCH_PROTOCOL_SIGN_SIZE < unsigned_upp_size) {
        void *tmp = realloc(previous_upp->data, unsigned_upp_size + 2 + UBIRCH_PROTOCOL_SIGN_SIZE);
        if (!tmp) { return -2; }
        previous_upp->data = (char *) tmp;
    }
    // update size for new UPP
    previous_upp->size = unsigned_upp_size + 2 + UBIRCH_PROTOCOL_SIGN_SIZE;

    // get a pointer to start of UPP payload field
    char *payload_field = previous_upp->data + 89;  // FIXME magic number (HEADER_SIZE)
    // update msgpack bytes to new size of payload field    // FIXME this only works for payloads <= 0xFF (255 byte)
    previous_upp->data[88] = (const unsigned char) payload_len;
    // write payload to payload field
    memcpy(payload_field, payload, payload_len);

    // add signature
    mbedtls_sha512_context hash;
    hash.is384 = -1;
    mbedtls_sha512_init(&hash);
    mbedtls_sha512_starts(&hash, 0);
    mbedtls_sha512_update(&hash, (const unsigned char *) previous_upp->data, unsigned_upp_size);

    unsigned char sha512sum[UBIRCH_PROTOCOL_SIGN_SIZE];
    unsigned char signature[UBIRCH_PROTOCOL_SIGN_SIZE];
    mbedtls_sha512_finish(&hash, sha512sum);

    if (ed25519_sign(sha512sum, sizeof(sha512sum), signature)) {
        return -3;
    }

    // get a pointer to start of signature field for new upp
    char *new_upp_signature = previous_upp->data + (unsigned_upp_size);
    // add msgpack bytes
    unsigned char msgpack_bytes[2] = {0xc4, UBIRCH_PROTOCOL_SIGN_SIZE};
    memcpy(new_upp_signature, msgpack_bytes, 2);
    // append signature hash to UPP
    memcpy(new_upp_signature + 2, signature, UBIRCH_PROTOCOL_SIGN_SIZE);

    return 0;
}

static inline void ubirch_protocol_buffer_free(ubirch_protocol_buffer *buf) {
    if (buf == NULL) { return; }
    free(buf->data);
    msgpack_packer_free(buf->packer);
    free(buf);
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