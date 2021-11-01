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

#define BYTES_LENGTH_TO_BASE64_STRING_LENGTH(__len) (((__len + 2) / 3) * 4)

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
 *   4   "prevPubKeyId": "(convert to base64, optional)"
 *   5   "pubKey": "... (convert to base64)",
 *   6   "pubKeyId": "(convert to base64, optional)",
 *   7   "validNotAfter": 1234567899,
 *   8   "validNotBefore": 1234567890,
 */
inline int msgpack_pack_key_register(msgpack_packer *pk, ubirch_key_info *info) {
    size_t packetSize = 8;

    // reduce size of this packet by checking validity of info
    if(info->prevPubKeyId == NULL) packetSize -= 1;
    if(info->pubKeyId == NULL) packetSize -= 1;
    if(info->validNotAfter == 0) packetSize -= 1;
    if(info->validNotBefore == 0) packetSize -= 1;

    msgpack_pack_map(pk, packetSize);

    // 1 - pack the algorithm
    msgpack_pack_str(pk, strlen(proto_reg_key_algorithm));
    msgpack_pack_str_body(pk, proto_reg_key_algorithm, strlen(proto_reg_key_algorithm));
    msgpack_pack_str(pk, strlen(info->algorithm));
    msgpack_pack_str_body(pk, info->algorithm, strlen(info->algorithm));

    // 2 - pack the created date
    msgpack_pack_str(pk, strlen(proto_reg_key_created));
    msgpack_pack_str_body(pk, proto_reg_key_created, strlen(proto_reg_key_created));
    msgpack_pack_unsigned_int(pk, info->created);

    // 3 - pack the device hardware id
    msgpack_pack_str(pk, strlen(proto_reg_key_uuid));
    msgpack_pack_str_body(pk, proto_reg_key_uuid, strlen(proto_reg_key_uuid));
    msgpack_pack_bin(pk, sizeof(info->hwDeviceId));
    msgpack_pack_bin_body(pk, info->hwDeviceId, sizeof(info->hwDeviceId));

    // 4 - pack the previous pub key id
    if(info->prevPubKeyId != NULL) {
        msgpack_pack_str(pk, strlen(proto_reg_key_prev_pub_key_id));
        msgpack_pack_str_body(pk, proto_reg_key_prev_pub_key_id, strlen(proto_reg_key_prev_pub_key_id));
        msgpack_pack_bin(pk, strlen(info->prevPubKeyId));
        msgpack_pack_bin_body(pk, info->prevPubKeyId, strlen(info->prevPubKeyId));
    }

    // 5 - pack the public key
    msgpack_pack_str(pk, strlen(proto_reg_key_pub_key));
    msgpack_pack_str_body(pk, proto_reg_key_pub_key, strlen(proto_reg_key_pub_key));
    msgpack_pack_bin(pk, sizeof(info->pubKey));
    msgpack_pack_bin_body(pk, info->pubKey, sizeof(info->pubKey));

    // 6 - pack the public key id (if applicable)
    if(info->pubKeyId != NULL) {
        msgpack_pack_str(pk, strlen(proto_reg_key_pub_key_id));
        msgpack_pack_str_body(pk, proto_reg_key_pub_key_id, strlen(proto_reg_key_pub_key_id));
        msgpack_pack_bin(pk, strlen(info->pubKeyId));
        msgpack_pack_bin_body(pk, info->pubKeyId, strlen(info->pubKeyId));
    }

    // 6 - pack the valid not after date
    msgpack_pack_str(pk, strlen(proto_reg_key_valid_not_after));
    msgpack_pack_str_body(pk, proto_reg_key_valid_not_after, strlen(proto_reg_key_valid_not_after));
    msgpack_pack_unsigned_int(pk, info->validNotAfter);

    // 7 - pack the valid not before date
    msgpack_pack_str(pk, strlen(proto_reg_key_valid_not_before));
    msgpack_pack_str_body(pk, proto_reg_key_valid_not_before, strlen(proto_reg_key_valid_not_before));
    msgpack_pack_unsigned_int(pk, info->validNotBefore);

    return 0;
}

int json_pack_key_update(ubirch_update_key_info *update, char *json_string_buffer, size_t json_string_buffer_size) {
    const char *timestring_format = "%Y-%m-%dT%H:%M:%S.000Z";
    const size_t timestring_size = 25;

    const char *inner_json_format_string =
        "{"
            "\"%s\":\"%s\"," /* algorithm */
            "\"%s\":\"%s\"," /* created */
            "\"%s\":\"%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x\"," /* uuid */
            "\"%s\":\"%s\"," /* pubKey */
            "\"%s\":\"%s\"," /* pubKeyId */
            "\"%s\":\"%s\"," /* prevPubKeyId */
            "\"%s\":\"%s\"," /* validNotAfter */
            "\"%s\":\"%s\""  /* validNotBefore */
        "}";

    // expected size (380)
    // 6 = number of quotation marks + colon + comma
    const size_t json_string_size = 2 // {}
        + 6 + strlen(proto_reg_key_algorithm) + strlen(UBIRCH_KEX_ALG_ECC_ED25519)
        + 6 + strlen(proto_reg_key_created) + timestring_size
        + 6 + strlen(proto_reg_key_uuid) + 36
        + 6 + strlen(proto_reg_key_pub_key) + BYTES_LENGTH_TO_BASE64_STRING_LENGTH(UBIRCH_PROTOCOL_PUBKEY_SIZE)
        + 6 + strlen(proto_reg_key_pub_key_id) + BYTES_LENGTH_TO_BASE64_STRING_LENGTH(UBIRCH_PROTOCOL_PUBKEY_SIZE)
        + 6 + strlen(proto_reg_key_prev_pub_key_id) + BYTES_LENGTH_TO_BASE64_STRING_LENGTH(UBIRCH_PROTOCOL_PUBKEY_SIZE)
        + 6 + strlen(proto_reg_key_valid_not_after) + timestring_size
        + 5 + strlen(proto_reg_key_valid_not_before) + timestring_size;

    if (json_string_buffer_size < json_string_size) {
        return -1;
    }

    // convert unix time to timestring
    struct tm* timeinfo;

    char timestring_created[timestring_size];
    timeinfo = localtime(&update->created);
    strftime(timestring_created, timestring_size, timestring_format, timeinfo);

    char timestring_validNotAfter[timestring_size];
    timeinfo = localtime(&update->validNotAfter);
    strftime(timestring_validNotAfter, timestring_size, timestring_format, timeinfo);

    char timestring_validNotBefore[timestring_size];
    timeinfo = localtime(&update->validNotBefore);
    strftime(timestring_validNotBefore, timestring_size, timestring_format, timeinfo);

    return sprintf(json_string_buffer, inner_json_format_string,
        UBIRCH_KEX_ALGORITHM, update->algorithm,
        UBIRCH_KEX_CREATED, timestring_created,
        //
        UBIRCH_KEX_UUID,
        update->hwDeviceId[0],
        update->hwDeviceId[1],
        update->hwDeviceId[2],
        update->hwDeviceId[3],
        update->hwDeviceId[4],
        update->hwDeviceId[5],
        update->hwDeviceId[6],
        update->hwDeviceId[7],
        update->hwDeviceId[8],
        update->hwDeviceId[9],
        update->hwDeviceId[10],
        update->hwDeviceId[11],
        update->hwDeviceId[12],
        update->hwDeviceId[13],
        update->hwDeviceId[14],
        update->hwDeviceId[15],
        //
        UBIRCH_KEX_PUBKEY, update->pubKey,
        UBIRCH_KEX_PUBKEY_ID, update->pubKey,
        UBIRCH_KEX_PREV_PUBKEY_ID, update->prevPubKeyId,
        //
        UBIRCH_KEX_VALID_NOT_AFTER, timestring_validNotAfter,
        UBIRCH_KEX_VALID_NOT_BEFORE, timestring_validNotBefore);
}
