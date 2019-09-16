![ubirch logo](https://ubirch.de/wp-content/uploads/2018/10/cropped-uBirch_Logo.png)

# ubirch protocol (v2)

1. [Basic Message Format](#basic-message-format)
    1. [Field Types](#field-types)
2. [Checking the Signature](#checking-the-signature) 
3. [API](#api)
    1. [Simple Message Example](#simple-message-example)
    2. [Chained Message Example](#chained-message-example)
    3. [Message Responses](#message-responses)
    4. [Key Registration](#key-registration)    
4. [Building](#building)
5. [Testing](#testing)

          
The ubirch-protocol is a protocol to ensure the integrity and identity of data
flowing through the data acquisition and transformation networks. An implementation by 
[ubirch](http://ubirch.com) handles data verification, and forwarding as well as blockchain 
transactions to lock data points in time for proofable logs.

> **Why individually signed data?** Without signatures on data, any sensor value stored in the blockchain is useless.
> Without proof of identity (owner) and verification of integrity (unchanged) data may just have come anywhere 
> and be modified in transit or on backend servers.  

#### License 

The protocol and its implementation are publicized under the [Apache License 2.0](LICENSE).

We are grateful for the insights and support by [Erik Tews](https://www.datenzone.de) and 
[Andreas Schuler](http://schulerdev.de/).

#### Contact

* [ubirch GmbH](https://ubirch.com)
* Twitter: [@ubirch_iot](https://twitter.com/ubirch_iot)

----              

## Basic Message Format

The ubirch protocol basic message format wraps the payload with an authentication header and a signature. 
The complete message, including header,payload and signature are combined in a serialized [msgpack](https://msgpack.org) 
array. 

```
+=========+======+==================+======+=========+-------------+
| VERSION | UUID | [PREV-SIGNATURE] | TYPE | PAYLOAD | [SIGNATURE] |
+=========+======+==================+======+=========+-------------+
=   ➔ data used for signature (4 elements)
[]  ➔ optional fields, depending on lower 4 bit of version
```

### Field Types

- **VERSION** - [Integer](https://github.com/msgpack/msgpack/blob/master/spec.md#int-format-family)
    - `0010|0001` - version 2, simple message without signatures, `[VE, ID, TY, PL]`
    - `0010|0010` - version 2, signed message without chained signatures, `[VE, ID, TY, PL, SI]`
    - `0010|0011` - version 2, signed message with chained signatures, `[VE, ID, PS, TY, PL, SI]`
- **UUID** - [128 bit, 16-byte array](https://github.com/msgpack/msgpack/blob/master/spec.md#bin-format-family)   
- **PREV-SIGNATURE** - [512 bit, 64-byte array](https://github.com/msgpack/msgpack/blob/master/spec.md#bin-format-family)
- **TYPE** - [Integer](https://github.com/msgpack/msgpack/blob/master/spec.md#int-format-family), positive fixnum 
   (1 byte, see [Payload Type](#payload-type))
- **PAYLOAD** - [Byte array](https://github.com/msgpack/msgpack/blob/master/spec.md#bin-format-family) 
with a length upto (2^32)-1 bytes or any msgpack type
- **SIGNATURE** - [512 bit, 64-byte array](https://github.com/msgpack/msgpack/blob/master/spec.md#bin-format-family) 
  ([ED25519](https://ed25519.cr.yp.to) signature, 64 bytes)
   > Calculated over the [SHA512](https://en.wikipedia.org/wiki/SHA-2) of the binary representation of previous fields.

#### Payload Type

| Payload Type | Description |
|--------------|-------------|
| `0x00` (`00`)| [binary, or unknown payload type](https://github.com/ubirch/ubirch-protocol/blob/master/README_PAYLOAD.md#binary-or-unknown-payload-type) |
| `0x01` (`01`)| [key registration message](https://github.com/ubirch/ubirch-protocol/blob/master/README_PAYLOAD.md#key-registration-message) |
| `0x03` (`03`)| [msgpack object payload type](https://github.com/ubirch/ubirch-protocol/blob/master/README_PAYLOAD.md#msgpack-payload-type) |
| `0x32` (`50`)| [ubirch standard sensor message (msgpack)](https://github.com/ubirch/ubirch-protocol/blob/master/README_PAYLOAD.md#ubirch-standard-sensor-message) |
| `0x53` (`83`)| [generic sensor message (json type key/value map)](https://github.com/ubirch/ubirch-protocol/blob/master/README_PAYLOAD.md#generic-sensor-message) |
| `0x54` (`84`)| [trackle message packet](https://github.com/ubirch/ubirch-protocol/blob/master/README_PAYLOAD.md#trackle-message-packet) |
| `0x55` (`85`)| [ubirch/trackle message response](https://github.com/ubirch/ubirch-protocol/blob/master/README_PAYLOAD.md#ubirch-trackle-message-response) |

## Checking the Signature   
   
The structure allows a recipient to take off the last 64 bytes of the message and check the signature of the
message taking length - 66 bytes hashed with [SHA512](https://en.wikipedia.org/wiki/SHA-2).

Trivial Example (Python, chained message type):

```python
import msgpack
import ed25519
import hashlib

publicKey = "b12a906051f102881bbb487ee8264aa05d8d0fcc51218f2a47f562ceb9b0d068"
messageHex = "9522c4106eac4d0b16e645088c4622e7451ea5a1ccef01c440c8f1c19fb64ca6ecd68a336bbffb39e8f4e6ee686de725ce9e23f76945fc2d734b4e77f9f02cb0bb2d4f8f8e361efc5ea10033bdc741a24cff4d7eb08db6340b"
message = messageHex.decode('hex')

vk = ed25519.VerifyingKey(publicKey, encoding='hex')

unpacked = msgpack.unpackb(message)
signature = unpacked[4]
try:
    tohash = message[0:-66]
    hash = hashlib.sha512(tohash).digest()
    vk.verify(signature, hash)
    print "message signature verified"
except Exception as e:
    print "message signature verification failed"
```

Case must be taken, unpacking the message structure, to ensure no data beyond the limits is read.

## API

The Ubirch protocol API provides the following functions:

- **`ubirch_protocol_new(sign)`** creates a new Ubirch protocol context, which contains a data buffer for the message 
to be packed. A callback function for signing the message is passed as an argument. *If you only want to pack a plain 
message without signature, NULL can be passed.*

- **`ubirch_protocol_message(&upp_ctx, variant, uuid, payload_type, payload, payload_len);`** packs the message and 
writes it to the context data buffer. This function takes the following arguments: the Ubirch protocol context, 
the desired protocol variant (plain, signed, chained), a hint to the data type of the payload, the payload data and 
the payload size in bytes. 

- **`ubirch_protocol_free(&upp_ctx)`** frees the allocated memory of the protocol context.

- **`ubirch_protocol_verify(&upp, upp_len, verify)`** takes a Ubirch protocol package and verifies it. 
You need to provide a verify callback function.

    
### Simple Message Example
```c
// create a ubirch protocol context and provide the sign function
ubirch_protocol *upp = ubirch_protocol_new(ed25519_sign);

// pack a message, pass the ubirch protocol context, protocol variant (plain, signed or chained),
// UUID, payload type (0 for binary), the payload and it's size.
const char *msg = "message";
ubirch_protocol_message(upp, proto_signed, uuid, 0, msg, sizeof(msg));

// SEND THE MESSAGE (upp->data, upp->size)

// free the protocol context
ubirch_protocol_free(upp);
```

#### Example: binary output (simple signed message)
```
00000000: 9522 c410 6162 6364 6566 6768 696a 6b6c  ."..abcdefghijkl
00000010: 6d6e 6f70 00cd 09c2 c440 2e5f a0c3 ddb7  mnop.....@._....
00000020: ca79 b032 ef8f bead 598e 70c7 c06c d47c  .y.2....Y.p..l.|
00000030: 6d6b 2551 2bc7 cc88 0a06 5ed7 37f5 c194  mk%Q+.....^.7...
00000040: a462 355a c7d3 57d5 6885 fb08 ad76 d676  .b5Z..W.h....v.v
00000050: b7b0 94c0 11de 262d af0c                 ......&-..
```

### Chained Message Example

> ⚠  Chained messages include the signature of the previous message
> to create a safe chain of verifiable messages. You need to keep the
> Ubirch protocol context alive to create a message chain.  

The example is very similar to above, except that the Ubirch protocol
context is not deleted after use.

```c
// create a ubirch protocol context and provide the sign function
ubirch_protocol *upp = ubirch_protocol_new(ed25519_sign);

// FIRST MESSAGE
const char *msg1 = "message1";
ubirch_protocol_message(upp, proto_chained, uuid, 0, msg1, sizeof(msg1));

// SEND THE FIRST MESSAGE (upp->data, upp->size)

// SECOND MESSAGE
const char *msg2 = "message2";
ubirch_protocol_message(upp, proto_chained, uuid, 0, msg2, sizeof(msg2));

// SEND THE SECOND MESSAGE (upp->data, upp->size)

// ...more packing and sending, if you like

// free the protocol context
ubirch_protocol_free(upp);
```


#### Example: binary output (chained message)

Message 1:
```
00000000: 9623 c410 6162 6364 6566 6768 696a 6b6c  .#..abcdefghijkl
00000010: 6d6e 6f70 c440 0000 0000 0000 0000 0000  mnop.@..........
00000020: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000030: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000040: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000050: 0000 0000 0000 00a9 6d65 7373 6167 6520  ........message 
00000060: 31c4 404a a4be 4dd7 fd69 b641 4e49 9466  1.@J..M..i.ANI.f
00000070: 983e 0bf8 bb4d 34ea 4d7b a492 4ce1 d9fd  .>...M4.M{..L...
00000080: 7fc6 8a8f 4f90 a721 f100 4069 de0f dd06  ....O..!..@i....
00000090: 0560 50b5 32de 5cfb c965 a6a8 897d 09f2  .`P.2.\..e...}..
000000a0: dfbb 08                                  ...
```

Message 2:
```
00000000: 9623 c410 6162 6364 6566 6768 696a 6b6c  .#..abcdefghijkl
00000010: 6d6e 6f70 c440 4aa4 be4d d7fd 69b6 414e  mnop.@J..M..i.AN
00000020: 4994 6698 3e0b f8bb 4d34 ea4d 7ba4 924c  I.f.>...M4.M{..L
00000030: e1d9 fd7f c68a 8f4f 90a7 21f1 0040 69de  .......O..!..@i.
00000040: 0fdd 0605 6050 b532 de5c fbc9 65a6 a889  ....`P.2.\..e...
00000050: 7d09 f2df bb08 00a9 6d65 7373 6167 6520  }.......message 
00000060: 32c4 40f9 5cc5 7631 34a3 f576 2a07 134e  2.@.\.v14..v*..N
00000070: 15b4 844a db71 a0bb 1cba 1473 74b2 4149  ...J.q.....st.AI
00000080: 78db 3b0c d3db f0fa 3e34 516d b380 0f2f  x.;.....>4Qm.../
00000090: 3afe 96da 2618 d842 afcf 0fbf a92c 4fe5  :...&..B.....,O.
000000a0: 3353 06                                  3S.
```

### Message Responses

Message responses will have the same structure as normal messages, but use the signature of the original message
in place of the previous signature (for the chained message protocol). This ties the request and response together.
 
### Key Registration

Devices must register at the key service to make their existence known.
The key registration message is the first step and simply publishes a key
with some meta-data to the key service. It will later be used for looking
up keys for a certain device, i.e. when doing an initial trust hand shake.

A key registration message is a msgpack map which can be directly converted to `JSON`:
```json
{
    "algorithm": "ECC_ED25519",
    "created": 1234567890,
    "hwDeviceID": "... (convert to UUID style)",
    "previousPubKeyId": "(convert to base64, optional)",
    "pubKey": "... (convert to base64)",
    "pubKeyId": "(convert to base64, optional)",
    "validNotAfter": 1234567899,
    "validNotBefore": 1234567890
}
```
> Some values are binary and should be converted to base64 or an ASCII UUID style in JSON.
    
The key info struct has fields for all necessary parts of a registration packet. 
```c
typedef struct ubirch_key_info {
    char *algorithm;
    unsigned int created;
    unsigned char hwDeviceId[UBIRCH_PROTOCOL_UUID_SIZE];
    char *previousPubKeyId;
    unsigned char pubKey[UBIRCH_PROTOCOL_PUBKEY_SIZE];
    char *pubKeyId;
    unsigned int validNotAfter;
    unsigned int validNotBefore;
} ubirch_key_info;
```
All fields are mandatory, except `previousPubKeyId` and `pubKeyId`.     

As the registration packet must be signed by the owner of the key, use the following way of wrapping it in a
ubirch protocol message:

```c
// create key registration info
ubirch_key_info info = {};
info.algorithm = (char *)(UBIRCH_KEX_ALG_ECC_ED25519);
info.created = timestamp;
memcpy(info.hwDeviceId, UUID, sizeof(UUID));
memcpy(info.pubKey, public_key, sizeof(public_key));
info.validNotAfter = NOTAFTERTIMESTAMP;
info.validNotBefore = NOTBEFORTIMESTAMP;

// create protocol context
ubirch_protocol *upp = ubirch_protocol_new(ed25519_sign);

// pack key info
ubirch_protocol_message(upp, proto_signed, UUID, UBIRCH_PROTOCOL_TYPE_REG, (const char *) &info, sizeof(info));

// send the data
sendPacket(upp->data, upp->size);

// free allocated ressources
ubirch_protocol_free(upp);
```

## Building


The library depends on [`msgpack-c`](https://os.mbed.com/users/yihui/code/msgpack/) and the ubirch 
[`NaCL`](https://github.com/ubirch/ubirch-mbed-nacl-cm0) (based on [µNaCl](https://munacl.cryptojedi.org/), ECC ED25519)
implementation. 

> The `NaCL` port requires a random number generator. Two generators for the `Nordic nRF52` and the `NXP K82F` are
> provided with the port. See `ubirch-mbed-nacl-cm0/source/randombytes.h` for a function prototype to implement.

### mbed

Building and testing for [mbed](https://mbed.com):

```bash
mbed new .
mbed target UBRIDGE # set your own target here
mbed toolchain GCC_ARM
mbed update         # to download the dependencies
mbed compile --library
```

If you don't want to use the mbedtls digest function, use the mbed configuration system:
```json
{
   "target_overrides": {
      "*": {
         "ubirch-protocol.mbedtls": null
      }
   }
}
```
This will disable mbedtls sha512 and use the digest provided with ubirch-protocol.

### Bosch XDK

If you would like to include this library in the Bosch XDK SDK use the provided `BoschXDK110.mk` Makefile:

```bash
make -f BoschXDK110.mk dist
```

This creates a distribution directory `BUILD/xdk/ubirch-protocol`, which can be included into the 3rd part libraries
directory of SDK `SDK/xdk110/Libraries` and edit the config file roughly following [this guide](https://xdk.bosch-connectivity.com/documents/37728/286250/XDK110_Library_Guide.pdf):

* `SDK/xdk110/Common/application.mk`:
	- add `UBIRCH_LIBRARY_DIR = $(BCDS_LIBRARIES_PATH)/ubirch-protocol`
	- add to `BCDS_XDK_EXT_INCLUDES`
	```
	-isystem $(UBIRCH_LIBRARY_DIR)/msgpack \
	-isystem $(UBIRCH_LIBRARY_DIR)/nacl \
	-isystem $(UBIRCH_LIBRARY_DIR) \
	```
* `SDK/xdk110/Common/Libraries.mk`
	- add to `BCDS_THIRD_PARTY_LIBS`
	```
	$(UBIRCH_LIBRARY_DIR)/ubirch_protocol.a
	```

Now you can include and use the `ubirch_protocol.h`, `msgpack` functionality and of course our `NaCL` port.

> Just like the TLS library in XDK, this is preliminary as the TRNG of the XDK is not enabled. 
> [See known issues](http://xdk.bosch-connectivity.com/xdk_docs/html/_known_issues.html).

You will need to add a function with the signature `void randombytes(unsigned char *x,unsigned long long xlen);`
to your code.  **Do not use the dummy function found in the NaCL library file named `randombytes.c`** It does not 
provide random numbers!

### ESP32

To use this library in your ESP32 project, you can add it as a git submodule
to your components directory:

```bash
git submodule add
```

## Testing

Tests are run using the [mbed](https://mbed.com) test infrastructure. They require python host tests.

```bash
pip install -r requirements.txt
mbed update 
mbed test -n tests-ubirch*
```

### Test Output

### [NRF52-DK](https://www.nordicsemi.com/eng/Products/Bluetooth-low-energy/nRF52-DK)


```
+------------------+---------------+----------------------+--------+--------------------+-------------+
| target           | platform_name | test suite           | result | elapsed_time (sec) | copy_method |
+------------------+---------------+----------------------+--------+--------------------+-------------+
| NRF52_DK-GCC_ARM | NRF52_DK      | tests-ubirch-chained | OK     | 84.69              | default     |
| NRF52_DK-GCC_ARM | NRF52_DK      | tests-ubirch-kex     | OK     | 23.52              | default     |
| NRF52_DK-GCC_ARM | NRF52_DK      | tests-ubirch-plain   | OK     | 22.71              | default     |
| NRF52_DK-GCC_ARM | NRF52_DK      | tests-ubirch-signed  | OK     | 45.4               | default     |
+------------------+---------------+----------------------+--------+--------------------+-------------+
mbedgt: test suite results: 4 OK
mbedgt: test case report:
+------------------+---------------+----------------------+--------------------------------------------------+--------+--------+--------+--------------------+
| target           | platform_name | test suite           | test case                                        | passed | failed | result | elapsed_time (sec) |
+------------------+---------------+----------------------+--------------------------------------------------+--------+--------+--------+--------------------+
| NRF52_DK-GCC_ARM | NRF52_DK      | tests-ubirch-chained | ubirch protocol [chained] init                   | 1      | 0      | OK     | 0.05               |
| NRF52_DK-GCC_ARM | NRF52_DK      | tests-ubirch-chained | ubirch protocol [chained] message chained        | 1      | 0      | OK     | 8.96               |
| NRF52_DK-GCC_ARM | NRF52_DK      | tests-ubirch-chained | ubirch protocol [chained] message finish         | 1      | 0      | OK     | 3.52               |
| NRF52_DK-GCC_ARM | NRF52_DK      | tests-ubirch-chained | ubirch protocol [chained] message finish (fails) | 1      | 0      | OK     | 0.08               |
| NRF52_DK-GCC_ARM | NRF52_DK      | tests-ubirch-chained | ubirch protocol [chained] message simple         | 1      | 0      | OK     | 4.54               |
| NRF52_DK-GCC_ARM | NRF52_DK      | tests-ubirch-chained | ubirch protocol [chained] message start          | 1      | 0      | OK     | 0.38               |
| NRF52_DK-GCC_ARM | NRF52_DK      | tests-ubirch-chained | ubirch protocol [chained] new                    | 1      | 0      | OK     | 0.07               |
| NRF52_DK-GCC_ARM | NRF52_DK      | tests-ubirch-chained | ubirch protocol [chained] static message         | 1      | 0      | OK     | 45.62              |
| NRF52_DK-GCC_ARM | NRF52_DK      | tests-ubirch-chained | ubirch protocol [chained] write                  | 1      | 0      | OK     | 0.07               |
| NRF52_DK-GCC_ARM | NRF52_DK      | tests-ubirch-kex     | ubirch protocol [kex] init                       | 1      | 0      | OK     | 0.37               |
| NRF52_DK-GCC_ARM | NRF52_DK      | tests-ubirch-kex     | ubirch protocol [kex] register signed            | 1      | 0      | OK     | 3.68               |
| NRF52_DK-GCC_ARM | NRF52_DK      | tests-ubirch-plain   | ubirch protocol [plain] init                     | 1      | 0      | OK     | 0.05               |
| NRF52_DK-GCC_ARM | NRF52_DK      | tests-ubirch-plain   | ubirch protocol [plain] message (unsupported)    | 1      | 0      | OK     | 0.07               |
| NRF52_DK-GCC_ARM | NRF52_DK      | tests-ubirch-plain   | ubirch protocol [plain] message finish           | 1      | 0      | OK     | 0.12               |
| NRF52_DK-GCC_ARM | NRF52_DK      | tests-ubirch-plain   | ubirch protocol [plain] message finish (fails)   | 1      | 0      | OK     | 0.09               |
| NRF52_DK-GCC_ARM | NRF52_DK      | tests-ubirch-plain   | ubirch protocol [plain] message simple           | 1      | 0      | OK     | 1.15               |
| NRF52_DK-GCC_ARM | NRF52_DK      | tests-ubirch-plain   | ubirch protocol [plain] message start            | 1      | 0      | OK     | 0.11               |
| NRF52_DK-GCC_ARM | NRF52_DK      | tests-ubirch-plain   | ubirch protocol [plain] new                      | 1      | 0      | OK     | 0.05               |
| NRF52_DK-GCC_ARM | NRF52_DK      | tests-ubirch-plain   | ubirch protocol [plain] write                    | 1      | 0      | OK     | 0.05               |
| NRF52_DK-GCC_ARM | NRF52_DK      | tests-ubirch-signed  | ubirch protocol [signed] init                    | 1      | 0      | OK     | 0.07               |
| NRF52_DK-GCC_ARM | NRF52_DK      | tests-ubirch-signed  | ubirch protocol [signed] message finish          | 1      | 0      | OK     | 8.16               |
| NRF52_DK-GCC_ARM | NRF52_DK      | tests-ubirch-signed  | ubirch protocol [signed] message finish (fails)  | 1      | 0      | OK     | 0.08               |
| NRF52_DK-GCC_ARM | NRF52_DK      | tests-ubirch-signed  | ubirch protocol [signed] message signed          | 1      | 0      | OK     | 8.07               |
| NRF52_DK-GCC_ARM | NRF52_DK      | tests-ubirch-signed  | ubirch protocol [signed] message start           | 1      | 0      | OK     | 0.25               |
| NRF52_DK-GCC_ARM | NRF52_DK      | tests-ubirch-signed  | ubirch protocol [signed] message verify          | 1      | 0      | OK     | 7.86               |
| NRF52_DK-GCC_ARM | NRF52_DK      | tests-ubirch-signed  | ubirch protocol [signed] new                     | 1      | 0      | OK     | 0.05               |
| NRF52_DK-GCC_ARM | NRF52_DK      | tests-ubirch-signed  | ubirch protocol [signed] write                   | 1      | 0      | OK     | 0.05               |
+------------------+---------------+----------------------+--------------------------------------------------+--------+--------+--------+--------------------+
mbedgt: test case results: 27 OK
mbedgt: completed in 177.38 sec
```

### UBRIDGE (NXP K82F)

```
mbedgt: test suite report:
+-----------------+---------------+----------------------+--------+--------------------+-------------+
| target          | platform_name | test suite           | result | elapsed_time (sec) | copy_method |
+-----------------+---------------+----------------------+--------+--------------------+-------------+
| UBRIDGE-GCC_ARM | UBRIDGE       | tests-ubirch-chained | OK     | 40.04              | default     |
| UBRIDGE-GCC_ARM | UBRIDGE       | tests-ubirch-kex     | OK     | 20.38              | default     |
| UBRIDGE-GCC_ARM | UBRIDGE       | tests-ubirch-plain   | OK     | 21.63              | default     |
| UBRIDGE-GCC_ARM | UBRIDGE       | tests-ubirch-signed  | OK     | 26.15              | default     |
+-----------------+---------------+----------------------+--------+--------------------+-------------+
mbedgt: test suite results: 4 OK
mbedgt: test case report:
+-----------------+---------------+----------------------+--------------------------------------------------+--------+--------+--------+--------------------+
| target          | platform_name | test suite           | test case                                        | passed | failed | result | elapsed_time (sec) |
+-----------------+---------------+----------------------+--------------------------------------------------+--------+--------+--------+--------------------+
| UBRIDGE-GCC_ARM | UBRIDGE       | tests-ubirch-chained | ubirch protocol [chained] init                   | 1      | 0      | OK     | 0.06               |
| UBRIDGE-GCC_ARM | UBRIDGE       | tests-ubirch-chained | ubirch protocol [chained] message chained        | 1      | 0      | OK     | 3.66               |
| UBRIDGE-GCC_ARM | UBRIDGE       | tests-ubirch-chained | ubirch protocol [chained] message finish         | 1      | 0      | OK     | 0.55               |
| UBRIDGE-GCC_ARM | UBRIDGE       | tests-ubirch-chained | ubirch protocol [chained] message finish (fails) | 1      | 0      | OK     | 0.09               |
| UBRIDGE-GCC_ARM | UBRIDGE       | tests-ubirch-chained | ubirch protocol [chained] message simple         | 1      | 0      | OK     | 1.89               |
| UBRIDGE-GCC_ARM | UBRIDGE       | tests-ubirch-chained | ubirch protocol [chained] message start          | 1      | 0      | OK     | 0.08               |
| UBRIDGE-GCC_ARM | UBRIDGE       | tests-ubirch-chained | ubirch protocol [chained] new                    | 1      | 0      | OK     | 0.07               |
| UBRIDGE-GCC_ARM | UBRIDGE       | tests-ubirch-chained | ubirch protocol [chained] static message         | 1      | 0      | OK     | 12.44              |
| UBRIDGE-GCC_ARM | UBRIDGE       | tests-ubirch-chained | ubirch protocol [chained] write                  | 1      | 0      | OK     | 0.06               |
| UBRIDGE-GCC_ARM | UBRIDGE       | tests-ubirch-kex     | ubirch protocol [kex] init                       | 1      | 0      | OK     | 0.07               |
| UBRIDGE-GCC_ARM | UBRIDGE       | tests-ubirch-kex     | ubirch protocol [kex] register signed            | 1      | 0      | OK     | 0.53               |
| UBRIDGE-GCC_ARM | UBRIDGE       | tests-ubirch-plain   | ubirch protocol [plain] init                     | 1      | 0      | OK     | 0.05               |
| UBRIDGE-GCC_ARM | UBRIDGE       | tests-ubirch-plain   | ubirch protocol [plain] message (unsupported)    | 1      | 0      | OK     | 0.09               |
| UBRIDGE-GCC_ARM | UBRIDGE       | tests-ubirch-plain   | ubirch protocol [plain] message finish           | 1      | 0      | OK     | 0.08               |
| UBRIDGE-GCC_ARM | UBRIDGE       | tests-ubirch-plain   | ubirch protocol [plain] message finish (fails)   | 1      | 0      | OK     | 0.09               |
| UBRIDGE-GCC_ARM | UBRIDGE       | tests-ubirch-plain   | ubirch protocol [plain] message simple           | 1      | 0      | OK     | 1.16               |
| UBRIDGE-GCC_ARM | UBRIDGE       | tests-ubirch-plain   | ubirch protocol [plain] message start            | 1      | 0      | OK     | 0.06               |
| UBRIDGE-GCC_ARM | UBRIDGE       | tests-ubirch-plain   | ubirch protocol [plain] new                      | 1      | 0      | OK     | 0.06               |
| UBRIDGE-GCC_ARM | UBRIDGE       | tests-ubirch-plain   | ubirch protocol [plain] write                    | 1      | 0      | OK     | 0.06               |
| UBRIDGE-GCC_ARM | UBRIDGE       | tests-ubirch-signed  | ubirch protocol [signed] init                    | 1      | 0      | OK     | 0.06               |
| UBRIDGE-GCC_ARM | UBRIDGE       | tests-ubirch-signed  | ubirch protocol [signed] message finish          | 1      | 0      | OK     | 1.26               |
| UBRIDGE-GCC_ARM | UBRIDGE       | tests-ubirch-signed  | ubirch protocol [signed] message finish (fails)  | 1      | 0      | OK     | 0.08               |
| UBRIDGE-GCC_ARM | UBRIDGE       | tests-ubirch-signed  | ubirch protocol [signed] message signed          | 1      | 0      | OK     | 2.49               |
| UBRIDGE-GCC_ARM | UBRIDGE       | tests-ubirch-signed  | ubirch protocol [signed] message start           | 1      | 0      | OK     | 0.06               |
| UBRIDGE-GCC_ARM | UBRIDGE       | tests-ubirch-signed  | ubirch protocol [signed] message verify          | 1      | 0      | OK     | 1.24               |
| UBRIDGE-GCC_ARM | UBRIDGE       | tests-ubirch-signed  | ubirch protocol [signed] new                     | 1      | 0      | OK     | 0.05               |
| UBRIDGE-GCC_ARM | UBRIDGE       | tests-ubirch-signed  | ubirch protocol [signed] write                   | 1      | 0      | OK     | 0.06               |
+-----------------+---------------+----------------------+--------------------------------------------------+--------+--------+--------+--------------------+
mbedgt: test case results: 27 OK
mbedgt: completed in 110.15 sec
```
