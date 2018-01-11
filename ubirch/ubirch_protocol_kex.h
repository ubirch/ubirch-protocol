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
#include "../msgpack/msgpack.h"

#ifdef __cplusplus
extern "C" {
#endif

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
 *      "deviceID": "...",
 *      "pubKey": "...".
 *      "algorithm": "ed25519"
 *      "created": 1234567890,
 *      "validNotBefore": 1234567890,
 *      "validNotAfter": 1234567899
 *      "prevPubKey": "..."
 * }
 * @endcode
 *
 * The function uses the msgpack interface.
 *
 * @param uuid the device uuid
 * @param pub_key the public key
 * @param algorithm the used algorithm
 * @param old_pub_key if this is a new key, link to old key
 * @param created when was this key created
 * @param valid_not_before the key is not valid before date
 * @param valid_not_after the key is not valid after date
 */
static int msgpack_pack_key_register(msgpack_packer *pk,
                                     const unsigned char *uuid,
                                     const unsigned char *pub_key,
                                     const char *algorithm,
                                     long created, long valid_not_before, long valid_not_after,
                                     const unsigned char *old_pub_key);



#ifdef __cplusplus
}
#endif

#endif