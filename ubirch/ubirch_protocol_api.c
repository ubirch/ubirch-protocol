/*!
 * @file
 * @brief ubirch protocol API
 *
 * @author Roxana Meixner
 * @date   2019-09-10
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

#include "ubirch_protocol_api.h"

/**
 * Start a new message. Writes the header data to ubirch protocol package.
 *
 * @param upp the ubirch protocol context
 * @param variant protocol variant
 * @param uuid the uuid associated with the data
 * @param payload_type the payload data type indicator (0 - binary)
 * @return -1 if upp is NULL
 * @return -2 if the protocol version is not supported
 */
static int8_t ubirch_protocol_start(ubirch_protocol *upp, ubirch_protocol_variant variant,
                                    const unsigned char *uuid, uint8_t payload_type) {
    if (upp == NULL) return -1;

    // the message consists of 3 header elements, the payload and (not included) the signature
    switch (variant) {
        case proto_plain:
            msgpack_pack_array(&upp->packer, 4);
            break;
        case proto_signed:
            msgpack_pack_array(&upp->packer, 5);
            break;
        case proto_chained:
            msgpack_pack_array(&upp->packer, 6);
            break;
        default:
            return -2;
    }

    // 1 - protocol version
    msgpack_pack_uint8(&upp->packer, variant);

    // 2 - device ID
    msgpack_pack_bin(&upp->packer, UBIRCH_PROTOCOL_UUID_SIZE);
    msgpack_pack_bin_body(&upp->packer, uuid, UBIRCH_PROTOCOL_UUID_SIZE);

    // 3 the last signature (if chained)
    if (variant == proto_chained) {
        msgpack_pack_bin(&upp->packer, sizeof(upp->signature));
        msgpack_pack_bin_body(&upp->packer, upp->signature, sizeof(upp->signature));
    }

    // 4 the payload type
    msgpack_pack_uint8(&upp->packer, payload_type);

    return 0;
}

/**
 * Add payload to ubirch protocol package.
 *
 * @param upp the ubirch protocol context
 * @param payload_type the payload data type indicator (0 - binary)
 * @param payload the payload for the UPP, can be key registration info or byte array.
 * @param payload_len the size of the payload in bytes
 * @return -1 if upp is NULL
 */
static int8_t ubirch_protocol_add_payload(ubirch_protocol *upp, uint8_t payload_type,
                                          const unsigned char *payload, size_t payload_len) {
    if (upp == NULL) return -1;

    // 5 add the payload
    if (payload_type == UBIRCH_PROTOCOL_TYPE_REG) {
        // create a key registration packet and add it to UPP
        ubirch_key_info *info = (ubirch_key_info *) payload;
        msgpack_pack_key_register(&upp->packer, info);
    } else {
        // add payload as byte array to UPP
        msgpack_pack_bin(&upp->packer, payload_len);
        msgpack_pack_bin_body(&upp->packer, payload, payload_len);
    }

    return 0;
}

/**
 * Finish a message. Calculates the signature and attaches it to the message.
 *
 * @param upp the ubirch protocol context
 * @param variant protocol variant
 * @return 0 if successful
 * @return -1 if upp is NULL
 * @return -2 if the signing failed
 */
static int8_t ubirch_protocol_finish(ubirch_protocol *upp, ubirch_protocol_variant variant) {
    if (upp == NULL) return -1;

    // only add signature if we have a chained or signed message
    if (variant == proto_signed || variant == proto_chained) {
        unsigned char sha512sum[UBIRCH_PROTOCOL_SIGN_SIZE];
        mbedtls_sha512((const unsigned char *) upp->data, upp->size, sha512sum, 0);
        if (upp->sign(sha512sum, sizeof(sha512sum), upp->signature)) {
            return -2;
        }

        // 6 add signature hash
        msgpack_pack_bin(&upp->packer, UBIRCH_PROTOCOL_SIGN_SIZE);
        msgpack_pack_bin_body(&upp->packer, upp->signature, UBIRCH_PROTOCOL_SIGN_SIZE);
    }

    return 0;
}

int8_t ubirch_protocol_message(ubirch_protocol *upp, ubirch_protocol_variant variant,
                               const unsigned char *uuid, uint8_t payload_type,
                               const unsigned char *payload, size_t payload_len) {
    int8_t error = 0;
    // check if UPP struct has been initialized
    if (upp == NULL || upp->data == NULL || upp->packer.data != upp) { return -1; }

    // for protocol variants with signature, check if context has a sign callback
    if (variant == proto_signed || variant == proto_chained) {
        if (upp->sign == NULL) { return -2; }
    }

    // clear buffer
    upp->size = 0;

    // pack UPP header
    error = ubirch_protocol_start(upp, variant, uuid, payload_type);
    if (error) { return -3; }

    // add the payload
    ubirch_protocol_add_payload(upp, payload_type, payload, payload_len);

    // sign the package
    error = ubirch_protocol_finish(upp, variant);
    if (error) { return -4; }

    return 0;
}

int8_t ubirch_protocol_verify(char *data, size_t data_len, ubirch_protocol_check verify) {
    if (data == NULL) { return -2; }

    // separate message and signature
    const size_t unsigned_message_len = data_len - (UBIRCH_PROTOCOL_SIGN_SIZE + 2);

    // make sure we have something to check, if it is just the signature, fail
    if (unsigned_message_len <= 0) { return -2; }

    // hash the message data
    unsigned char sha512sum[UBIRCH_PROTOCOL_SIGN_SIZE];
    mbedtls_sha512((const unsigned char *) data, unsigned_message_len, sha512sum, 0);

    // get a pointer to the signature
    const unsigned char *signature = (const unsigned char *) data + (data_len - UBIRCH_PROTOCOL_SIGN_SIZE);

    // verify signature with user verify function
    return verify(sha512sum, UBIRCH_PROTOCOL_SIGN_SIZE, signature);
}
