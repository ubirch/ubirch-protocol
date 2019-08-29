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
    char *data;
    size_t alloc;
    msgpack_packer *packer;                             //!< the underlying target packer
    ubirch_protocol_sign sign;                          //!< the message signing function
    uint8_t version;                                    //!< the specific used protocol version
    uint8_t type;                                       //!< the payload type (0 - unspecified, app specific)
    unsigned char uuid[UBIRCH_PROTOCOL_UUID_SIZE];      //!< the uuid of the sender (used to retrieve the keys)
    unsigned char signature[UBIRCH_PROTOCOL_SIGN_SIZE]; //!< the current or previous signature of a message
    mbedtls_sha512_context hash;                        //!< the streaming hash of the data to sign
    uint8_t status;                                     //!< the status of the protocol package
} ubirch_protocol_buffer;


static inline int ubirch_protocol_buffer_write(void *data, const char *buf, size_t len) {
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

static inline ubirch_protocol_buffer *ubirch_protocol_new(ubirch_protocol_variant variant,
                                                          const unsigned char uuid[UBIRCH_PROTOCOL_UUID_SIZE],
                                                          uint8_t payload_type) {

    *upp = (ubirch_protocol_buffer *) calloc(1, sizeof(ubirch_protocol_buffer));
    if (!upp) { return NULL; }

    upp->data = (char *) realloc(upp->data, UPP_BUFFER_INIT_SIZE);
    if (!upp->data) { return NULL; }

    upp->alloc = UPP_BUFFER_INIT_SIZE;

    upp->packer = msgpack_packer_new(upp, ubirch_protocol_buffer_write);
    if (upp->packer) { return NULL; }

    if (variant == proto_plain) {
        upp->ubirch_protocol_sign = NULL
    } else {
        upp->ubirch_protocol_sign = ed25519_sign;
    }

    upp->version = variant;
    upp->type = payload_type;
    memcpy(upp->uuid, uuid, UBIRCH_PROTOCOL_UUID_SIZE);
    upp->hash.is384 = -1;

    upp->status = UBIRCH_PROTOCOL_INITIALIZED;

    return upp;
}

/**
 * Create a UPP (Ubirch Protocol Package)
 *
 * @param variant protocol variant
 * @param uuid the uuid associated with the data
 * @param payload_type the payload data type indicator (0 -> binary)
 * @param payload the byte array containing the payload data
 * @param payload_len the number of bytes in the payload
 * @return struct containing UPP and its size
*/
static inline ubirch_protocol_buffer *ubirch_protocol_pack(ubirch_protocol_variant variant,
                                                           const unsigned char uuid[UBIRCH_PROTOCOL_UUID_SIZE],
                                                           uint8_t payload_type,
                                                           const unsigned char *payload, size_t payload_len) {

    ubirch_protocol_buffer *upp = ubirch_protocol_buffer_new();
    if (!upp) { return NULL; }

    // pack UPP header
    ubirch_protocol_start(proto, pk);

    // add payload
    if (payload_type == UBIRCH_PROTOCOL_TYPE_REG) {
        // create a key registration packet and add it to UPP as payload
        ubirch_key_info *info = (ubirch_key_info *) payload;
        msgpack_pack_key_register(pk, info);
    } else {
        // add payload as byte array to UPP
        msgpack_pack_bin(pk, payload_len);
        msgpack_pack_bin_body(pk, payload, payload_len);
    }

    // sign the package
    ubirch_protocol_finish(proto, pk);

    // allocate memory and store generated UPP in struct
    upp->data = (char *) realloc(upp->data, sbuf->size);
    if (!upp->data) { return NULL; }

    memcpy(upp->data, sbuf->data, sbuf->size);
    upp->size = sbuf->size;

    // free allocated memory
    msgpack_packer_free(pk);
    ubirch_protocol_free(proto);
    msgpack_sbuffer_free(sbuf);

    return upp;
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