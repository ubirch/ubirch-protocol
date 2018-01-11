/*!
 * @file
 * @brief ubirch protocol key exchange
 *
 * @author Matthias L. Jugel
 * @date   2018-01-11
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
#include <msgpack/msgpack.h>
#include "ubirch_protocol_kex.h"

static const char *proto_reg_key_uuid = "deviceID";
static const char *proto_reg_key_pub_key = "pubKey";
static const char *proto_reg_key_prev_pub_key = "prevPubKey";
static const char *proto_reg_key_algorithm = "algorithm";
static const char *proto_reg_key_created = "created";
static const char *proto_reg_key_valid_not_before = "validNotBefore";
static const char *proto_reg_key_valid_not_after = "validNotAfter";

inline int msgpack_pack_key_register(msgpack_packer *pk,
                                     const unsigned char *uuid,
                                     const unsigned char *pub_key,
                                     const char *algorithm,
                                     long created, long valid_not_before, long valid_not_after,
                                     const unsigned char *old_pub_key) {
    // calculate size of the data map (6 fixed entries)
    msgpack_pack_map(pk, 6 + (old_pub_key != NULL ? 1 : 0));
    // 1 - pack the device UUID
    msgpack_pack_raw(pk, strlen(proto_reg_key_uuid));
    msgpack_pack_raw_body(pk, proto_reg_key_uuid, strlen(proto_reg_key_uuid));
    msgpack_pack_raw(pk, UBIRCH_PROTOCOL_UUID_SIZE);
    msgpack_pack_raw_body(pk, uuid, UBIRCH_PROTOCOL_UUID_SIZE);
    // 2 - pack the public key
    msgpack_pack_raw(pk, strlen(proto_reg_key_pub_key));
    msgpack_pack_raw_body(pk, proto_reg_key_uuid, strlen(proto_reg_key_pub_key));
    msgpack_pack_raw(pk, UBIRCH_PROTOCOL_PUBKEY_SIZE);
    msgpack_pack_raw_body(pk, pub_key, UBIRCH_PROTOCOL_PUBKEY_SIZE);
    // 3 - pack the algorithm
    msgpack_pack_raw(pk, strlen(proto_reg_key_algorithm));
    msgpack_pack_raw_body(pk, proto_reg_key_algorithm, strlen(proto_reg_key_algorithm));
    msgpack_pack_raw(pk, strlen(algorithm));
    msgpack_pack_raw_body(pk, algorithm, strlen(algorithm));
    // 4 - pack the created date
    msgpack_pack_raw(pk, strlen(proto_reg_key_created));
    msgpack_pack_raw_body(pk, proto_reg_key_created, strlen(proto_reg_key_created));
    msgpack_pack_long(pk, created);
    // 5 - pack the valid not before date
    msgpack_pack_raw(pk, strlen(proto_reg_key_valid_not_before));
    msgpack_pack_raw_body(pk, proto_reg_key_valid_not_before, strlen(proto_reg_key_valid_not_before));
    msgpack_pack_long(pk, created);
    // 6 - pack the valid not fater date
    msgpack_pack_raw(pk, strlen(proto_reg_key_valid_not_after));
    msgpack_pack_raw_body(pk, proto_reg_key_valid_not_after, strlen(proto_reg_key_valid_not_after));
    msgpack_pack_long(pk, created);

    // 7 - pack the previous public key (optional)
    if (old_pub_key != NULL) {
        msgpack_pack_raw(pk, strlen(proto_reg_key_prev_pub_key));
        msgpack_pack_raw_body(pk, proto_reg_key_prev_pub_key, strlen(proto_reg_key_prev_pub_key));
        msgpack_pack_raw(pk, UBIRCH_PROTOCOL_PUBKEY_SIZE);
        msgpack_pack_raw_body(pk, pub_key, UBIRCH_PROTOCOL_PUBKEY_SIZE);
    }

    return 0;
}