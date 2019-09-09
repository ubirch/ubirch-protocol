/*!
 * @file
 * @brief ubirch protocol implementation based on msgpack
 *
 * The basic ubirch protocol implementation based on msgpack.
 * A ubirch protocol message consists of a header, payload and
 * a signature. The signature is calculated from the streaming
 * hash (sha512) of the msgpack data in front of the signature,
 * excluding the msgpack type marker for the signature.
 *
 * The generation of messages is similar to msgpack:
 *
 * ```
 * // creata a standard msgpack stream buffer
 * msgpack_sbuffer *sbuf = msgpack_sbuffer_new();
 * // create a ubirch protocol context from the buffer, its writer
 * // and provide the signature function as well as the UUID
 * ubirch_protocol *proto = ubirch_protocol_new(sbuf, msgpack_sbuffer_write, ed25519_sign,
 *                                              (const unsigned char *) UUID);
 * // create a msgpack packer from the ubirch protocol
 * msgpack_packer *pk = msgpack_packer_new(proto, ubirch_protocol_write);
 *
 * // pack a message by starting with the header
 * ubirch_protocol_start(proto, pk);
 * // add payload (must be a single element, use map/array for multiple data points)
 * msgpack_pack_int(pk, 99);
 * // finish the message (calculates signature)
 * ubirch_protocol_finish(proto, pk);
 * ```
 * 
 * The protocol context takes care of hashing and sending the data to
 * the stream buffer. Instead of a stream buffer, the data may be
 * written directly to the network using a custom write function instead of
 * `msgpack_sbuffer_write`.
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

#ifndef UBIRCH_PROTOCOL_H
#define UBIRCH_PROTOCOL_H

#ifdef __cplusplus
extern "C" {
#endif

#ifndef MSGPACK_ZONE_CHUNK_SIZE
#define MSGPACK_ZONE_CHUNK_SIZE 128
#endif

#define UBIRCH_PROTOCOL_VERSION     2       //!< current ubirch protocol version
#define UBIRCH_PROTOCOL_PLAIN       0x01    //!< plain protocol without signatures (unsafe)
#define UBIRCH_PROTOCOL_SIGNED      0x02    //!< signed messages (unchained)
#define UBIRCH_PROTOCOL_CHAINED     0x03    //!< chained signed messages

#define UBIRCH_PROTOCOL_PUBKEY_SIZE 32      //!< public key size
#define UBIRCH_PROTOCOL_SIGN_SIZE   64      //!< our signatures has 64 bytes (same as size of hash)
#define UBIRCH_PROTOCOL_UUID_SIZE   16      //!< the size of a UUID

#define UBIRCH_PROTOCOL_TYPE_BIN 0x00       //!< payload is undefined and binary
#define UBIRCH_PROTOCOL_TYPE_REG 0x01       //!< payload is defined as key register message
#define UBIRCH_PROTOCOL_TYPE_HSK 0x02       //!< payload is a key handshake message

#define UPP_BUFFER_INIT_SIZE 219            //!< initial allocation size for UPP data buffer, enough space for chained message with 64 byte payload

#ifdef __cplusplus
}
#endif

#endif //UBIRCH_PROTOCOL_H