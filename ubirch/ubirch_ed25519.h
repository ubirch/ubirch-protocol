/*!
 * @file
 * @brief helper functions wrapping the ED25519 sign/verify
 *
 * @author Matthias L. Jugel
 * @date   2018-02-23
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

#ifndef UBIRCH_PROTOCOL_ED25519_H
#define UBIRCH_PROTOCOL_ED25519_H

#include <armnacl.h>

#ifdef __cplusplus
extern "C" {
#endif

extern unsigned char ed25519_secret_key[crypto_sign_SECRETKEYBYTES];    //!< reference to the secret key for signing
extern unsigned char ed25519_public_key[crypto_sign_PUBLICKEYBYTES];    //!< reference to the public key for signing

/**
 * Function to sign a payload and return the signature.
 * @param data the buffer with the data to sign
 * @param len the length of the data buffer
 * @param signature the buffer to hold the returned signature
 * @return 0 on success
 * @return -1 if the signing failed
 */
static int ed25519_sign(const unsigned char *data, size_t len, unsigned char signature[crypto_sign_BYTES]);

/**
 * Function to sign a payload with a given secret key and return the signature.
 * @param data the buffer with the data to sign
 * @param len the length of the data buffer
 * @param signature the buffer to hold the returned signature
 * @param secret_key the secret key to use
 * @return 0 on success
 * @return -1 if the signing failed
 */
static int ed25519_sign_key(const unsigned char *data, size_t len, unsigned char signature[crypto_sign_BYTES],
                            const unsigned char secret_key[crypto_sign_SECRETKEYBYTES]);

/**
 * Function to verify a data buffer with the provided signature.
 * @param data the buffer with the data to verify
 * @param len the length of the data buffer
 * @param signature a buffer with the corresponding signature
 * @return 0 on success
 * @return -1 if the verification failed
 */
static int ed25519_verify(const unsigned char *data, size_t len, const unsigned char signature[crypto_sign_BYTES]);

/**
 * Function to verify a data buffer with the given public key and the provided signature.
 * @param data the buffer with the data to verify
 * @param len the length of the data buffer
 * @param signature a buffer with the corresponding signature
 * @param public_key the public key to use for verification
 * @return 0 on success
 * @return -1 if the verification failed
 */
static int ed25519_verify(const unsigned char *data, size_t len, const unsigned char signature[crypto_sign_BYTES]);

inline int ed25519_sign_key(const unsigned char *data, size_t len, unsigned char signature[crypto_sign_BYTES],
                            const unsigned char secret_key[crypto_sign_SECRETKEYBYTES]) {
    crypto_uint16 mlen;
    unsigned char *sm = (unsigned char *) malloc(crypto_sign_BYTES + len);
    if (!sm) return -1;

    // sign the message
    crypto_sign(sm, &mlen, data, (crypto_uint16) len, secret_key);
    memcpy(signature, sm, crypto_sign_BYTES);

    free(sm);

    return 0;
}

inline int ed25519_sign(const unsigned char *data, const size_t len,
                        unsigned char signature[crypto_sign_BYTES]) {
    return ed25519_sign_key(data, len, signature, ed25519_secret_key);
}

inline int ed25519_verify_key(const unsigned char *data, const size_t len,
                          const unsigned char signature[crypto_sign_BYTES],
                              const unsigned char public_key[crypto_sign_PUBLICKEYBYTES]) {
    crypto_uint16 smlen = (crypto_uint16) (crypto_sign_BYTES + len);
    crypto_uint16 mlen;

    unsigned char *sm = (unsigned char *) malloc(smlen);
    if (!sm) return -1;

    unsigned char *m = (unsigned char *) malloc(smlen);
    if (!m) {
        free(sm);
        return -1;
    }

    // initialize signed message structure
    memcpy(sm, signature, crypto_sign_BYTES);
    memcpy(sm + crypto_sign_BYTES, data, len);

    // verify signature
    int ret = crypto_sign_open(m, &mlen, sm, smlen, public_key);

    free(m);
    free(sm);

    return ret;
}

inline int ed25519_verify(const unsigned char *data, const size_t len,
                              const unsigned char signature[crypto_sign_BYTES]) {
    return ed25519_verify_key(data, len, signature, ed25519_public_key);
}

#ifdef __cplusplus
}
#endif

#endif // UBIRCH_PROTOCOL_ED25519_H
