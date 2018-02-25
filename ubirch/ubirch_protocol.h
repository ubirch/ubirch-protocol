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

#include <msgpack.h>

#ifdef MBEDTLS_CONFIG_FILE

#include <mbedtls/sha512.h>

#else
#include "digest/sha512.h"
#endif

#define UBIRCH_PROTOCOL_VERSION     1       //!< current ubirch protocol version
#define UBIRCH_PROTOCOL_PLAIN       0x01    //!< plain protocol without signatures (unsafe)
#define UBIRCH_PROTOCOL_SIGNED      0x02    //!< signed messages (unchained)
#define UBIRCH_PROTOCOL_CHAINED     0x03    //!< chained signed messages

#define UBIRCH_PROTOCOL_PUBKEY_SIZE 32      //!< public key size
#define UBIRCH_PROTOCOL_SIGN_SIZE   64      //!< our signatures has 64 bytes
#define UBIRCH_PROTOCOL_HASH_SIZE   64      //!< size of the hash
#define UBIRCH_PROTOCOL_UUID_SIZE   16      //!< the size of a UUID

#define UBIRCH_PROTOCOL_INITIALIZED 1       //!< protocol is initialized
#define UBIRCH_PROTOCOL_STARTED     2       //!< protocol has started

#define UBIRCH_PROTOCOL_TYPE_BIN 0x00       //!< payload is undefined and binary
#define UBIRCH_PROTOCOL_TYPE_REG 0x01       //!< patload is defined as key register message

typedef enum ubirch_protocol_variant {
    proto_plain = ((UBIRCH_PROTOCOL_VERSION << 4) | UBIRCH_PROTOCOL_PLAIN),
    proto_signed = ((UBIRCH_PROTOCOL_VERSION << 4) | UBIRCH_PROTOCOL_SIGNED),
    proto_chained = ((UBIRCH_PROTOCOL_VERSION << 4) | UBIRCH_PROTOCOL_CHAINED)
} ubirch_protocol_variant;

/**
 * The signature function type necessary to sign the message for the ubirch protocol.
 * This function is called from #ubirch_protocol_finish
 *
 * @param buf the data to sign
 * @param size_t len the length of the data buffer
 * @param signature signature output (64 byte)
 */
typedef int (*ubirch_protocol_sign)(const unsigned char *buf, size_t len,
                                    unsigned char signature[UBIRCH_PROTOCOL_SIGN_SIZE]);

/**
 * The verification function to check the validity of the message.
 * This function is called from #ubirch_protocol_verify
 *
 * @param buf the data to verify
 * @param size_t the length of the data buffer
 * @param signature the signature to check the dsata with (64 byte)
 */
typedef int (*ubirch_protocol_check)(const unsigned char *buf, size_t len,
                                     const unsigned char signature[UBIRCH_PROTOCOL_SIGN_SIZE]);

/**
 * ubirch protocol context, which holds the underlying packer, the uuid and current and previous signature
 * as well as the current hash.
 */
typedef struct ubirch_protocol {
    msgpack_packer packer;                              //!< the underlying target packer
    ubirch_protocol_sign sign;                          //!< the message signing function
    uint16_t version;                                   //!< the specific used protocol version
    unsigned int type;                                  //!< the payload type (0 - unspecified, app specific)
    unsigned char uuid[UBIRCH_PROTOCOL_UUID_SIZE];      //!< the uuid of the sender (used to retrieve the keys)
    unsigned char signature[UBIRCH_PROTOCOL_SIGN_SIZE]; //!< the current or previous signature of a message
    mbedtls_sha512_context hash;                        //!< the streaming hash of the data to sign
    unsigned int status;                                //!< amount of bytes packed
} ubirch_protocol;

/**
 * Initialize a new ubirch protocol context.
 *
 * @param proto the ubirch protocol context
 * @param variant protocol variant
 * @param data_type the payload data type indicator (0 - binary)
 * @param data the data object buffer associated with the context
 * @param callback the writer callback for writing data to network or buffer
 * @param sign a callback used for signing a message
 * @param uuid the uuid associated with the data
 */
static void ubirch_protocol_init(ubirch_protocol *proto, ubirch_protocol_variant variant,
                                 unsigned int data_type, void *data,
                                 msgpack_packer_write callback, ubirch_protocol_sign sign,
                                 const unsigned char uuid[UBIRCH_PROTOCOL_UUID_SIZE]);

/**
 * Create a new ubirch protocol context.
 *
 * @param variant protocol variant
 * @param data_type the payload data type indicator (0 - binary)
 * @param data the data object buffer associated with the context
 * @param callback the writer callback for writing data to network or buffer
 * @param sign a callback used for signing a message
 * @param uuid the uuid associated with the data
 * @return a new initialized context
 */
static ubirch_protocol *ubirch_protocol_new(ubirch_protocol_variant variant,
                                            unsigned int data_type, void *data,
                                            msgpack_packer_write callback, ubirch_protocol_sign sign,
                                            const unsigned char uuid[UBIRCH_PROTOCOL_UUID_SIZE]);

/**
 * Free memory for a ubirch protocol context.
 * @param proto the protocol context
 */
static void ubirch_protocol_free(ubirch_protocol *proto);

/**
 * Start a new message. Clears out previous data and re-initialized the signature
 * handler. Also writes the header data.
 * @param proto the ubirch protocol context
 * @param pk the msgpack packer used for serializing data
 * @return -1 if packer or proto are NULL
 * @return -2 if the protocol was not initialized
 * @return -3 if the protocol version is not supported
 */
static int ubirch_protocol_start(ubirch_protocol *proto, msgpack_packer *pk);

/**
 * Finish a message. Calculates the signature and attaches it to the message.
 * @param proto the ubirch protocol context
 * @param pk the msgpack packer used for serializing data
 * @return 0 if successful
 * @return -1 if either packer or protocol are NULL
 * @return -2 if used before ubirch_protocol_start
 * @return -3 if the signing failed
 */
static int ubirch_protocol_finish(ubirch_protocol *proto, msgpack_packer *pk);
/**
 * Verify a messages signature.
 * This function requires 256 bytes of heap memory to v
 * @param unpacker the unpacker containing the data
 * @param verify the private key to use for verification
 * @return 0 if the verification is successful
 * @return -1 if the signature verification has failed
 * @return -2 if the message length is wrong (too short to actually to a check)
 */
static int ubirch_protocol_verify(msgpack_unpacker *unpacker, ubirch_protocol_check verify);

/**
 * The ubirch protocol msgpack writer. This writer takes care of updating the hash
 * and writing original data to the underlying write callback.
 * @param data the ubirch protocol context
 * @param buf the data to writer and hash
 * @param len the length of the data
 * @return 0 if successful
 */
static inline int ubirch_protocol_write(void *data, const char *buf, size_t len) {
    ubirch_protocol *proto = (ubirch_protocol *) data;
    if (proto->version & proto_signed || proto->version == proto_chained) {
        mbedtls_sha512_update(&proto->hash, (const unsigned char *) buf, len);
    }
    return proto->packer.callback(proto->packer.data, buf, len);
}

inline void ubirch_protocol_init(ubirch_protocol *proto, enum ubirch_protocol_variant variant,
                                 unsigned int data_type, void *data,
                                 msgpack_packer_write callback, ubirch_protocol_sign sign,
                                 const unsigned char uuid[UBIRCH_PROTOCOL_UUID_SIZE]) {
    proto->packer.data = data;
    proto->packer.callback = callback;
    proto->sign = sign;
    proto->hash.is384 = -1;
    proto->version = variant;
    proto->type = data_type;
    memcpy(proto->uuid, uuid, UBIRCH_PROTOCOL_UUID_SIZE);
    proto->status = UBIRCH_PROTOCOL_INITIALIZED;
}

inline ubirch_protocol *ubirch_protocol_new(enum ubirch_protocol_variant variant,
                                            unsigned int data_type, void *data,
                                            msgpack_packer_write callback, ubirch_protocol_sign sign,
                                            const unsigned char uuid[UBIRCH_PROTOCOL_UUID_SIZE]) {
    ubirch_protocol *proto = (ubirch_protocol *) calloc(1, sizeof(ubirch_protocol));
    if (!proto) { return NULL; }
    ubirch_protocol_init(proto, variant, data_type, data, callback, sign, uuid);

    return proto;
}

inline void ubirch_protocol_free(ubirch_protocol *proto) {
    free(proto);
}

inline int ubirch_protocol_start(ubirch_protocol *proto, msgpack_packer *pk) {
    if (proto == NULL || pk == NULL) return -1;
    if (proto->status != UBIRCH_PROTOCOL_INITIALIZED) return -2;

    if (proto->version == proto_signed || proto->version == proto_chained) {
        mbedtls_sha512_init(&proto->hash);
        mbedtls_sha512_starts(&proto->hash, 0);
    }

    // the message consists of 3 header elements, the payload and (not included) the signature
    switch (proto->version) {
        case proto_plain:
            msgpack_pack_array(pk, 4);
            break;
        case proto_signed:
            msgpack_pack_array(pk, 5);
            break;
        case proto_chained:
            msgpack_pack_array(pk, 6);
            break;
        default:
            return -3;
    }

    // 1 - protocol version
    msgpack_pack_fix_uint16(pk, proto->version);

    // 2 - device ID
    msgpack_pack_raw(pk, 16);
    msgpack_pack_raw_body(pk, proto->uuid, sizeof(proto->uuid));

    // 3 the last signature (if chained)
    if (proto->version == proto_chained) {
        msgpack_pack_raw(pk, sizeof(proto->signature));
        msgpack_pack_raw_body(pk, proto->signature, sizeof(proto->signature));
    }

    // 4 the payload type
    msgpack_pack_int(pk, proto->type);

    proto->status = UBIRCH_PROTOCOL_STARTED;
    return 0;
}

inline int ubirch_protocol_finish(ubirch_protocol *proto, msgpack_packer *pk) {
    if (proto == NULL || pk == NULL) return -1;
    if (proto->status != UBIRCH_PROTOCOL_STARTED) return -2;

    // only add signature if we have a chained or signed message
    if (proto->version == proto_signed || proto->version == proto_chained) {
        unsigned char sha512sum[UBIRCH_PROTOCOL_HASH_SIZE];
        mbedtls_sha512_finish(&proto->hash, sha512sum);
        if (proto->sign(sha512sum, sizeof(sha512sum), proto->signature)) {
            return -3;
        }

        // 5 add signature hash
        msgpack_pack_raw(pk, UBIRCH_PROTOCOL_SIGN_SIZE);
        msgpack_pack_raw_body(pk, proto->signature, UBIRCH_PROTOCOL_SIGN_SIZE);
    }

    proto->status = UBIRCH_PROTOCOL_INITIALIZED;

    return 0;
}

inline int ubirch_protocol_verify(msgpack_unpacker *unpacker, ubirch_protocol_check verify) {
    const size_t msgpack_sig_length = UBIRCH_PROTOCOL_SIGN_SIZE + 3;
    const size_t message_size = msgpack_unpacker_message_size(unpacker);

    // make sure we have something to check, if it is just the signature, fail
    if (message_size <= msgpack_sig_length) return -2;

    // hash the message data
    unsigned char *data = (unsigned char *) (unpacker->buffer + unpacker->off);
    unsigned char sha512sum[UBIRCH_PROTOCOL_HASH_SIZE];
    mbedtls_sha512(data, message_size - msgpack_sig_length, sha512sum, 0);

    // get a pointer to the signature
    unsigned char *signature = data + (message_size - UBIRCH_PROTOCOL_SIGN_SIZE);

    return verify(sha512sum, UBIRCH_PROTOCOL_HASH_SIZE, signature);
}

#ifdef __cplusplus
}
#endif

#endif //UBIRCH_PROTOCOL_H