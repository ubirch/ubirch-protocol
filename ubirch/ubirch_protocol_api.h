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

#include <stdio.h>  //TODO take this out (only for testing)

typedef struct ubirch_protocol_buffer {
    size_t size;
    char *data;
} ubirch_protocol_buffer;

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

    // prepare msgpack buffer and packer
    msgpack_sbuffer *sbuf = msgpack_sbuffer_new();

    ubirch_protocol *proto = (variant == proto_plain) ? ubirch_protocol_new(variant, payload_type, sbuf,
                                                                            msgpack_sbuffer_write, NULL, uuid)
                                                      : ubirch_protocol_new(variant, payload_type, sbuf,
                                                                            msgpack_sbuffer_write, ed25519_sign, uuid);
    if (!proto) { return NULL; }

    msgpack_packer *pk = msgpack_packer_new(proto, ubirch_protocol_write);
    if (!pk) { return NULL; }

//    TODO load PREVIOUS_SIGNATURE for chained msgs before ubirch_protocol_start
//    memcpy(proto->signature,PREVIOUS_SIGNATURE, UBIRCH_PROTOCOL_SIGN_SIZE);

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
    ubirch_protocol_buffer *upp = (ubirch_protocol_buffer *) calloc(1, sizeof(ubirch_protocol_buffer));
    if (!upp) { return NULL; }
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

static inline void ubirch_protocol_buffer_free(ubirch_protocol_buffer *buf) {
    if (buf == NULL) { return; }
    free(buf->data);
    free(buf);
}

static inline void printUPP(const char *data, const size_t len) {
    printf("\r\n - - - UPP - - - \r\n");
    printf("size: %d Bytes \r\nmsg: ", len);
    for (unsigned int i = 0; i < len; i++) {
        printf("0x%02x, ", data[i]);
    }
    printf("\r\n\r\n");
}

#ifdef __cplusplus
}
#endif

#endif //UBIRCH_PROTOCOL_API_H