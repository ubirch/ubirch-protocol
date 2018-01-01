/*!
 * @file
 * @brief ubirch protocol implementation based on msgpack
 *
 * ...
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

#include <msgpack.h>
#include <armnacl.h>
#include "sha256.h"

#define UBIRCH_PROTOCOL_VERSION     0x0401

typedef void (*ubirch_protocol_sign)(const char *buf, size_t len, unsigned char signature[crypto_sign_BYTES]);

typedef struct ubirch_protocol {
    msgpack_packer packer;
    ubirch_protocol_sign sign;
    unsigned char uuid[16];
    unsigned char signature[crypto_sign_BYTES];
    mbedtls_sha256_context hash;
} ubirch_protocol;

static void
ubirch_protocol_init(ubirch_protocol *proto, void *data, msgpack_packer_write callback,
                     ubirch_protocol_sign sign, const unsigned char uuid[16]);

static ubirch_protocol *ubirch_protocol_new(void *data, msgpack_packer_write callback,
                                            ubirch_protocol_sign sign, const unsigned char uuid[16]);

static void ubirch_protocol_free(ubirch_protocol *proto);

static void ubirch_protocol_start(ubirch_protocol *proto, msgpack_packer *pk);

static void ubirch_protocol_finish(ubirch_protocol *proto, msgpack_packer *pk);

static inline int ubirch_protocol_write(void *data, const char *buf, size_t len) {
    ubirch_protocol *proto = (ubirch_protocol *) data;
    mbedtls_sha256_update(&proto->hash, (const unsigned char *) buf, len);
    return proto->packer.callback(proto->packer.data, buf, len);
}

inline void ubirch_protocol_init(ubirch_protocol *proto, void *data, msgpack_packer_write callback,
                     ubirch_protocol_sign sign, const unsigned char uuid[16]) {
    proto->packer.data = data;
    proto->packer.callback = callback;
    proto->sign = sign;
    memcpy(proto->uuid, uuid, 16);
}

inline ubirch_protocol *ubirch_protocol_new(void *data, msgpack_packer_write callback,
                                            ubirch_protocol_sign sign, const unsigned char uuid[16]) {
    ubirch_protocol *proto = (ubirch_protocol *) calloc(1, sizeof(ubirch_protocol));
    if (!proto) { return NULL; }
    ubirch_protocol_init(proto, data, callback, sign, uuid);

    return proto;
}

inline void ubirch_protocol_free(ubirch_protocol *proto) {
    free(proto);
}

inline void ubirch_protocol_start(ubirch_protocol *proto, msgpack_packer *pk) {
    if(proto == NULL || pk == NULL) return;

    mbedtls_sha256_init(&proto->hash);
    mbedtls_sha256_starts(&proto->hash, 0);

    // the message consists of 3 header elements, the payload and (not included) the signature
    msgpack_pack_array(pk, 5);

    // 1 - protocol version
    msgpack_pack_fix_uint16(pk, UBIRCH_PROTOCOL_VERSION);

    // 2 - device ID
    msgpack_pack_raw(pk, 16);
    msgpack_pack_raw_body(pk, proto->uuid, sizeof(proto->uuid));

    // 3 the last signature
    msgpack_pack_raw(pk, sizeof(proto->signature));
    msgpack_pack_raw_body(pk, proto->signature, sizeof(proto->signature));
}

inline void ubirch_protocol_finish(ubirch_protocol *proto, msgpack_packer *pk) {
    if (proto == NULL || pk == NULL) return;

    unsigned char sha256sum[32];
    mbedtls_sha256_finish(&proto->hash, sha256sum);
    proto->sign((const char *) sha256sum, sizeof(sha256sum), proto->signature);

    // 5 add signature hash
    msgpack_pack_raw(pk, crypto_sign_BYTES);
    msgpack_pack_raw_body(pk, proto->signature, crypto_sign_BYTES);
}

