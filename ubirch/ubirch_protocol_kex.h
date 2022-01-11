/*!
 * @file
 * @brief ubirch protocol key exchange
 *
 * Key registration and key exchange messages. These messages
 * allow the registration of device keys as well as aid in the
 * processor of creating a trust relationship between devices,
 * or backend services.
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

#ifndef UBIRCH_PROTOCOL_KEX_H
#define UBIRCH_PROTOCOL_KEX_H

#include "ubirch_protocol.h"
#include <msgpack.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

#define UBIRCH_KEX_ALG_ECC_ED25519  "ECC_ED25519"

#define UBIRCH_KEX_ALGORITHM        "algorithm"
#define UBIRCH_KEX_CREATED          "created"
#define UBIRCH_KEX_UUID             "hwDeviceId"
#define UBIRCH_KEX_PREV_PUBKEY_ID   "prevPubKeyId"
#define UBIRCH_KEX_PUBKEY           "pubKey"
#define UBIRCH_KEX_PUBKEY_ID        "pubKeyId"
#define UBIRCH_KEX_VALID_NOT_AFTER  "validNotAfter"
#define UBIRCH_KEX_VALID_NOT_BEFORE "validNotBefore"

typedef struct ubirch_key_info {
    char *algorithm;
    int64_t created;
    unsigned char hwDeviceId[UBIRCH_PROTOCOL_UUID_SIZE];
    char *prevPubKeyId;
    unsigned char pubKey[UBIRCH_PROTOCOL_PUBKEY_SIZE];
    char *pubKeyId;
    int64_t validNotAfter;
    int64_t validNotBefore;
} ubirch_key_info;

/**
 * Create a key registration message. This message consists of a map of entries
 * with the keys defined in @refitem proto_register_keys
 *
 * Sending this message to the key server will register an untrusted key.
 * A key exchange must be initiated with the server to create a trust
 * relationship between the device the key belongs to and the backend
 * service.
 *
 * The msgpack structure can be converted into a json message:
 * @code{.json}
 * {
 *      "algorithm": "ECC_ED25519",
 *      "created": 1234567890,
 *      "hwDeviceID": "... (convert to UUID style)",
 *      "prevPubKeyId": "(convert to base64, optional)",
 *      "pubKey": "... (convert to base64)",
 *      "pubKeyId": "(convert to base64, optional)",
 *      "validNotAfter": 1234567899,
 *      "validNotBefore": 1234567890
 * }
 * @endcode
 *
 * The message must be signed by the public key.
 *
 * @code{.c}
 * msgpack_sbuffer *sbuf = msgpack_sbuffer_new();
 * ubirch_protocol *proto = ubirch_protocol_new(proto_signed, UBIRCH_PROTOCOL_TYPE_REG,
 *                                              sbuf, msgpack_sbuffer_write, ed25519_sign, UUID);
 * msgpack_packer *pk = msgpack_packer_new(proto, ubirch_protocol_write);
 * ubirch_protocol_start(proto, pk);
 *
 * // initialize the key register info struct
 * ...
 * // create the packet
 * msgpack_pack_key_register(pk, &info);
 * // finish the complete message
 * ubirch_protocol_finish(proto, pk);
 *
 * msgpack_packer_free(pk);
 * ubirch_protocol_free(proto);
 * msgpack_sbuffer_free(sbuf);
 * @endcode
 * The function uses the msgpack interface.
 *
 * @param pk the msgpack packer
 * @param info the registration structure
 */
int msgpack_pack_key_register(msgpack_packer *pk, ubirch_key_info *info);


typedef struct ubirch_update_key_info {
    char *algorithm;
    time_t created;
    unsigned char *hwDeviceId;
    char *prevPubKeyId;
    char *pubKey;
    time_t validNotAfter;
    time_t validNotBefore;
} ubirch_update_key_info;

/*
 *
 * returns len of string
 */
int json_pack_key_update(ubirch_update_key_info *update, char *json_string_buffer, size_t json_string_buffer_size);

#ifdef __cplusplus
}
#endif

#endif
