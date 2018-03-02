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
#include "ubirch_protocol_kex.h"

static const char *proto_reg_key_algorithm = UBIRCH_KEX_ALGORITHM;
static const char *proto_reg_key_created = UBIRCH_KEX_CREATED;
static const char *proto_reg_key_uuid = UBIRCH_KEX_UUID;
static const char *proto_reg_key_prev_pub_key_id = UBIRCH_KEX_PREV_PUBKEY_ID;
static const char *proto_reg_key_pub_key = UBIRCH_KEX_PUBKEY;
static const char *proto_reg_key_pub_key_id = UBIRCH_KEX_PUBKEY_ID;
static const char *proto_reg_key_valid_not_after = UBIRCH_KEX_VALID_NOT_AFTER;
static const char *proto_reg_key_valid_not_before = UBIRCH_KEX_VALID_NOT_BEFORE;

/*
 *   1   "algorithm": "ECC_ED25519",
 *   2   "created": 1234567890,
 *   3   "hwDeviceID": "... (convert to UUID style)",
 *   4   "previousPubKeyId": "(convert to base64, optional)"
 *   5   "pubKey": "... (convert to base64)",
 *   6   "pubKeyId": "(convert to base64, optional)",
 *   7   "validNotAfter": 1234567899,
 *   8   "validNotBefore": 1234567890,
 */
inline int msgpack_pack_key_register(msgpack_packer *pk, ubirch_key_info *info) {
    size_t packetSize = 8;

    // reduce size of this packet by checking validity of info
    if(info->previousPubKeyId == NULL) packetSize -= 1;
    if(info->pubKeyId == NULL) packetSize -= 1;
    if(info->validNotAfter == 0) packetSize -= 1;
    if(info->validNotBefore == 0) packetSize -= 1;

    msgpack_pack_map(pk, packetSize);

    // 1 - pack the algorithm
    msgpack_pack_raw(pk, strlen(proto_reg_key_algorithm));
    msgpack_pack_raw_body(pk, proto_reg_key_algorithm, strlen(proto_reg_key_algorithm));
    msgpack_pack_raw(pk, strlen(info->algorithm));
    msgpack_pack_raw_body(pk, info->algorithm, strlen(info->algorithm));

    // 2 - pack the created date
    msgpack_pack_raw(pk, strlen(proto_reg_key_created));
    msgpack_pack_raw_body(pk, proto_reg_key_created, strlen(proto_reg_key_created));
    msgpack_pack_unsigned_int(pk, info->created);

    // 3 - pack the device hardware id
    msgpack_pack_raw(pk, strlen(proto_reg_key_uuid));
    msgpack_pack_raw_body(pk, proto_reg_key_uuid, strlen(proto_reg_key_uuid));
    msgpack_pack_raw(pk, sizeof(info->hwDeviceId));
    msgpack_pack_raw_body(pk, info->hwDeviceId, sizeof(info->hwDeviceId));

    // 4 - pack the previous pub key id
    if(info->previousPubKeyId != NULL) {
        msgpack_pack_raw(pk, strlen(proto_reg_key_prev_pub_key_id));
        msgpack_pack_raw_body(pk, proto_reg_key_prev_pub_key_id, strlen(proto_reg_key_prev_pub_key_id));
        msgpack_pack_raw(pk, strlen(info->previousPubKeyId));
        msgpack_pack_raw_body(pk, info->previousPubKeyId, strlen(info->previousPubKeyId));
    }

    // 5 - pack the public key
    msgpack_pack_raw(pk, strlen(proto_reg_key_pub_key));
    msgpack_pack_raw_body(pk, proto_reg_key_pub_key, strlen(proto_reg_key_pub_key));
    msgpack_pack_raw(pk, sizeof(info->pubKey));
    msgpack_pack_raw_body(pk, info->pubKey, sizeof(info->pubKey));

    // 6 - pack the public key id (if applicable)
    if(info->pubKeyId != NULL) {
        msgpack_pack_raw(pk, strlen(proto_reg_key_pub_key_id));
        msgpack_pack_raw_body(pk, proto_reg_key_pub_key_id, strlen(proto_reg_key_pub_key_id));
        msgpack_pack_raw(pk, strlen(info->pubKeyId));
        msgpack_pack_raw_body(pk, info->pubKeyId, strlen(info->pubKeyId));
    }

    // 6 - pack the valid not after date
    msgpack_pack_raw(pk, strlen(proto_reg_key_valid_not_after));
    msgpack_pack_raw_body(pk, proto_reg_key_valid_not_after, strlen(proto_reg_key_valid_not_after));
    msgpack_pack_unsigned_int(pk, info->validNotAfter);

    // 7 - pack the valid not before date
    msgpack_pack_raw(pk, strlen(proto_reg_key_valid_not_before));
    msgpack_pack_raw_body(pk, proto_reg_key_valid_not_before, strlen(proto_reg_key_valid_not_before));
    msgpack_pack_unsigned_int(pk, info->validNotBefore);

    return 0;
}