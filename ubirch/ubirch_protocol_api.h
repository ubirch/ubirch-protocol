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

typedef struct ubirch_protocol_buffer {
    size_t size;
    char *data;
} ubirch_protocol_buffer;

/**
* Function to create a UPP (Ubirch Protocol Package)
* @param upp the buffer for the created UPP
* @param upp_len the length of the created UPP buffer
* @return 0 if the UPP was successfully created
* @return -1 if UPP creation failed
*/
static inline ubirch_protocol_buffer *ubirch_protocol_pack(ubirch_protocol_variant variant,
                                                           const unsigned char uuid[UBIRCH_PROTOCOL_UUID_SIZE],
                                                           ubirch_protocol_payload_type type,
                                                           const char *payload, size_t payload_len) {

    // prepare msgpack packer and UPP header
    msgpack_sbuffer *sbuf = msgpack_sbuffer_new();
    ubirch_protocol *proto = ubirch_protocol_new(variant, type, sbuf, msgpack_sbuffer_write, ed25519_sign, uuid);
    msgpack_packer *pk = msgpack_packer_new(proto, ubirch_protocol_write);
    ubirch_protocol_start(proto, pk);

    // add payload as byte array to package
    msgpack_pack_bin(pk, payload_len);
    msgpack_pack_bin_body(pk, payload, payload_len);

    // sign the package
    ubirch_protocol_finish(proto, pk);

    // store generated UPP in struct
    ubirch_protocol_buffer *upp = (ubirch_protocol_buffer *) calloc(1, sizeof(ubirch_protocol_buffer));
    memcpy(upp->data, sbuf->data, sbuf->size);
    upp->size = sbuf->size;

    // free allocated heap
    msgpack_packer_free(pk);
    ubirch_protocol_free(proto);
    msgpack_sbuffer_free(sbuf);

    return upp;
}

#ifdef __cplusplus
}
#endif

#endif //UBIRCH_PROTOCOL_API_H




















