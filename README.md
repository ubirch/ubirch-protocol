# ubirch protocol

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

> **Why individually signed data?** Without signatures on data, any sensor value stored in the blockchain is
> trash. Without proof of identity (owner) and verification of integrity (unchanged) data may just have come anywhere and be modified in transit or on
> backend servers.  

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

- **VERSION** - [16 bit Integer](https://github.com/msgpack/msgpack/blob/master/spec.md#int-format-family)
    - `000000000001|0001` - version 1, simple message without signatures, `[VE, ID, TY, PL]`
    - `000000000001|0010` - version 1, signed message without chained signatures, `[VE, ID, TY, PL, SI]`
    - `000000000001|0011` - version 1, signed message with chained signatures, `[VE, ID, PS, TY, PL, SI]`
- **UUID** - [128 bit, 16-byte array](https://github.com/msgpack/msgpack/blob/master/spec.md#bin-format-family)   
- **PREV-SIGNATURE** - [512 bit, 64-byte array](https://github.com/msgpack/msgpack/blob/master/spec.md#bin-format-family)
- **TYPE** - [Integer](https://github.com/msgpack/msgpack/blob/master/spec.md#int-format-family) (1 byte 0x00 if unknown)
- **PAYLOAD** - ANY msgpack type (incl. raw alternative data)
- **SIGNATURE** - [512 bit, 64-byte array](https://github.com/msgpack/msgpack/blob/master/spec.md#bin-format-family) 
  ([ED25519](https://ed25519.cr.yp.to) signature, 64 bytes)
   > Calculated over the [SHA512](https://en.wikipedia.org/wiki/SHA-2) of the binary representation of previous fields.

An example is below, with the UUID (`abcdefghijklmnop`) and a subsequent message containing the chained previous
signature:

#### Payload Type

| Payload Type | Description |
|--------------|-------------|
| `0x00` (`00`)| binary, or unknown payload type |
| `0x01` (`01`)| generic sensor message (json type key/value map) |
| `0x54` (`84`)| trackle message packet |
| `0x55` (`85`)| trackle message response |




## Checking the Signature   
   
The structure allows a recipient to take off the last 64 bytes of the message and check the signature of the
message taking length - 67 bytes hashed with [SHA512](https://en.wikipedia.org/wiki/SHA-2).

Trivial Example (Python, chained message type):

```python
import msgpack
import ed25519
import hashlib

publicKey = "7c76c47c5161d0a03e7ae987010f324b875c23da813132cf8ffdaa5593e63e6a"
messageHex = "95cd0012b06162636465666768696a6b6c6d6e6f700063da00404eb006a2756ebc06549eef2b322ee950b159fbe21c38f8afd363d822afff2027b3e2e77074709225e5a38ce1d12a2dd4c4ca2359116b992ceac28321d2c17003"
message = messageHex.decode('hex')

vk = ed25519.VerifyingKey(publicKey, encoding='hex')

unpacked = msgpack.unpackb(message)
signature = unpacked[4]
try:
    tohash = message[0:-67]
    hash = hashlib.sha512(tohash).digest()
    vk.verify(signature, hash)
    print "message signature verified"
except Exception as e:
    print "message signature verification failed"
```

Case must be taken, unpacking the message structure, to ensure no data beyond the limits is read.

## API

The ubirch protocol API is derived from the msgpack API, adding a context similar to the buffer 
implementations (`sbuffer`), which wraps the packer to hash the data. A message is then created
using the `ubirch_protocol_start()` function and signing it with `ubirch_protocol_finish()`.


- **`ubirch_protocol_new(variant, type, data, writer, sign, uuid)`** creates a new protocol context with the provided 
    variant (plain, signed, chained), data type, data and writer. Additionally a sign function and a uuid are necessary. 
- **`ubirch_protocol_start(proto, packer)`** 
    start a new message using the ubirch protocol context and the provided msgpack packer.
- **`ubirch_protocol_finish(proto, packer)`** 
    finish the message, signing the header and payload.
    
### Simple Message Example

```c
// creata a standard msgpack stream buffer
msgpack_sbuffer *sbuf = msgpack_sbuffer_new();
// create a ubirch protocol context from the buffer, its writer
// and provide the signature function as well as the UUID
// create variant chained and data type 0 (unknown, binary)
ubirch_protocol *proto = ubirch_protocol_new(proto_chained, 0, sbuf, msgpack_sbuffer_write, ed25519_sign, UUID);
// create a msgpack packer from the ubirch protocol
msgpack_packer *pk = msgpack_packer_new(proto, ubirch_protocol_write);

// pack a message by starting with the header
ubirch_protocol_start(proto, pk);
// add payload (must be a single element, use map/array for multiple data points)
msgpack_pack_int(pk, 99);
// finish the message (calculates signature)
ubirch_protocol_finish(proto, pk);

// free packer and protocol
msgpack_packer_free(pk);
ubirch_protocol_free(proto); 
```

The protocol context takes care of hashing and sending the data to
the stream buffer. Instead of a stream buffer, the data may be
written directly to the network using a custom write function instead of
`msgpack_sbuffer_write`.

#### Example: binary output 
```
00000000: 96cd 0013 b061 6263 6465 6667 6869 6a6b  .....abcdefghijk
00000010: 6c6d 6e6f 70da 0040 0000 0000 0000 0000  lmnop..@........
00000020: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000030: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000040: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000050: 0000 0000 0000 0000 0063 da00 40b0 d504  .........c..@...
00000060: f311 c934 7b81 bac5 a648 4609 4edc fcb8  ...4{....HF.N...
00000070: 89c4 3c6c 3b6e b63d 487f 8603 daf1 aae4  ..<l;n.=H.......
00000080: 2fba f873 7d92 e848 77a2 e0a1 bac9 304e  /..s}..Hw.....0N
00000090: 7098 2c8c b96b 80a6 4544 ffb8 01         p.,..k..ED...
```

### Chained Message Example

> ⚠  Chained messages include the signature of the previous message
> to create a safe chain of verifyable messages. You need to keep the
> ubirch protocol context alive to create a message chain.  

The example is very similar to above, except that the ubirch protocol
context is not deleted after use.

```c
// create buffer, writer, ubirch protocol context and packer
msgpack_sbuffer *sbuf = msgpack_sbuffer_new();
ubirch_protocol *proto = ubirch_protocol_new(proto_chained, 0,
                                             sbuf, msgpack_sbuffer_write, ed25519_sign, UUID);
msgpack_packer *pk = msgpack_packer_new(proto, ubirch_protocol_write);

// FIRST MESSAGE
ubirch_protocol_start(proto, pk);
msgpack_pack_raw(pk, strlen(TEST_PAYLOAD));
msgpack_pack_raw_body(pk, TEST_PAYLOAD, strlen(TEST_PAYLOAD));
ubirch_protocol_finish(proto, pk);

// clear buffer for next message
msgpack_sbuffer_clear(sbuf);

// SECOND MESSAGE
ubirch_protocol_start(proto, pk);
msgpack_pack_raw(pk, strlen("CHAINED"));
msgpack_pack_raw_body(pk, "CHAINED", strlen("CHAINED"));
ubirch_protocol_finish(proto, pk);

// ... keep on sending

// free packer and protocol
msgpack_packer_free(pk);
ubirch_protocol_free(proto); 
```

#### MESSAGE 1: binary output:
```
00000000: 96cd 0013 b061 6263 6465 6667 6869 6a6b  .....abcdefghijk
00000010: 6c6d 6e6f 70da 0040 0000 0000 0000 0000  lmnop..@........
00000020: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000030: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000040: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000050: 0000 0000 0000 0000 00a9 6d65 7373 6167  ..........messag
00000060: 6520 31da 0040 7d8d ffc7 3a07 5a1f bdbe  e 1..@}...:.Z...
00000070: a2a5 3976 60d7 783e d006 c139 7ff7 632e  ..9v`.x>...9..c.
00000080: 5a84 99a5 b1a2 e985 6a5d 58a8 5e2f 2c2b  Z.......j]X.^/,+
00000090: 5717 bd0b 1755 5f6d 9f85 cb53 b455 03ae  W....U_m...S.U..
000000a0: 9e12 738e 330c                           ..s.3.
```

#### MESSAGE 2: binary output
```
00000000: 96cd 0013 b061 6263 6465 6667 6869 6a6b  .....abcdefghijk
00000010: 6c6d 6e6f 70da 0040 7d8d ffc7 3a07 5a1f  lmnop..@}...:.Z.
00000020: bdbe a2a5 3976 60d7 783e d006 c139 7ff7  ....9v`.x>...9..
00000030: 632e 5a84 99a5 b1a2 e985 6a5d 58a8 5e2f  c.Z.......j]X.^/
00000040: 2c2b 5717 bd0b 1755 5f6d 9f85 cb53 b455  ,+W....U_m...S.U
00000050: 03ae 9e12 738e 330c 00a9 6d65 7373 6167  ....s.3...messag
00000060: 6520 32da 0040 7296 a621 0200 f88e 68a8  e 2..@r..!....h.
00000070: ae91 b4a9 5604 163c fb3c 0b98 c933 d6bb  ....V..<.<...3..
00000080: d603 bcbf 8838 f3a3 e99c 5726 bbea f133  .....8....W&...3
00000090: 056c a420 f780 d783 0486 e245 6aed 20e5  .l. .......Ej. .
000000a0: 62dd 5361 f20b                           b.Sa..
```

### Message Responses

Message responses will have the same structure as normal message, but use the signature of the original message
in place of the previous signature (for the chained message protocol). This ties the request and response together.
 
### Key Registration

Devices must register at the key service to make their existence known.
The key registration message is the first step and simply published a key
with some meta-data to the key service. It will later be used for looking
up keys for a certain device, i.e. when doing an initial trust hand shake.

- **`int msgpack_pack_key_register(msgpack_packer *pk, ubirch_key_info *info)`**
    creates a msgpack message that can be used to register a given public key with the key service.
    
The info struct has fields for all necessary parts of a registration packet. All fields are mandatory, except
`previousPubKeyId` and `pubKeyId`.     

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

As the registration packet must be signed by the owner of the key, use the following way of wrapping it in a
ubirch protocol message:

```c
// create buffer, protocol and packer
msgpack_sbuffer *sbuf = msgpack_sbuffer_new();
ubirch_protocol *proto = ubirch_protocol_new(proto_signed, UBIRCH_PROTOCOL_TYPE_REG,
                                             sbuf, msgpack_sbuffer_write, ed25519_sign, UUID);
msgpack_packer *pk = msgpack_packer_new(proto, ubirch_protocol_write);

// start the ubirch protocol message
ubirch_protocol_start(proto, pk);

// create key registration info
ubirch_key_info info = {};
info.algorithm = const_cast<char *>(UBIRCH_KEX_ALG_ECC_ED25519);
info.created = timestamp;
memcpy(info.hwDeviceId, UUID, sizeof(UUID));
memcpy(info.pubKey, public_key, sizeof(public_key));
info.validNotAfter = NOTAFTERTIMESTAMP;
info.validNotBefore = NOTBEFORTIMESTAMP;
msgpack_pack_key_register(pk, &info);

// finish the ubirch protocol message
ubirch_protocol_finish(proto, pk);

// send the data
sendPacket(sbuf->data, sbuf->size);

// free allocated ressources
msgpack_packer_free(pk);
ubirch_protocol_free(proto);
msgpack_sbuffer_free(sbuf);
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

## Testing

Tests are run using the [mbed](https://mbed.com) test infrastructure. They require python host tests.

```bash
pip install -r requirements.txt
mbed update 
mbed test -n tests-ubirch*
```

### Test Output

```
+------------------+---------------+----------------------+--------+--------------------+-------------+
| target           | platform_name | test suite           | result | elapsed_time (sec) | copy_method |
+------------------+---------------+----------------------+--------+--------------------+-------------+
| NRF52_DK-GCC_ARM | NRF52_DK      | tests-ubirch-chained | OK     | 51.61              | default     |
| NRF52_DK-GCC_ARM | NRF52_DK      | tests-ubirch-kex     | OK     | 26.65              | default     |
| NRF52_DK-GCC_ARM | NRF52_DK      | tests-ubirch-plain   | OK     | 28.55              | default     |
| NRF52_DK-GCC_ARM | NRF52_DK      | tests-ubirch-signed  | OK     | 37.76              | default     |
+------------------+---------------+----------------------+--------+--------------------+-------------+
mbedgt: test suite results: 4 OK
mbedgt: test case report:
+------------------+---------------+----------------------+--------------------------------------------------+--------+--------+--------+--------------------+
| target           | platform_name | test suite           | test case                                        | passed | failed | result | elapsed_time (sec) |
+------------------+---------------+----------------------+--------------------------------------------------+--------+--------+--------+--------------------+
| NRF52_DK-GCC_ARM | NRF52_DK      | tests-ubirch-chained | ubirch protocol [chained] init                   | 1      | 0      | OK     | 0.05               |
| NRF52_DK-GCC_ARM | NRF52_DK      | tests-ubirch-chained | ubirch protocol [chained] message chained        | 1      | 0      | OK     | 2.43               |
| NRF52_DK-GCC_ARM | NRF52_DK      | tests-ubirch-chained | ubirch protocol [chained] message finish         | 1      | 0      | OK     | 0.94               |
| NRF52_DK-GCC_ARM | NRF52_DK      | tests-ubirch-chained | ubirch protocol [chained] message finish (fails) | 1      | 0      | OK     | 0.09               |
| NRF52_DK-GCC_ARM | NRF52_DK      | tests-ubirch-chained | ubirch protocol [chained] message simple         | 1      | 0      | OK     | 1.28               |
| NRF52_DK-GCC_ARM | NRF52_DK      | tests-ubirch-chained | ubirch protocol [chained] message start          | 1      | 0      | OK     | 0.08               |
| NRF52_DK-GCC_ARM | NRF52_DK      | tests-ubirch-chained | ubirch protocol [chained] new                    | 1      | 0      | OK     | 0.05               |
| NRF52_DK-GCC_ARM | NRF52_DK      | tests-ubirch-chained | ubirch protocol [chained] static message         | 1      | 0      | OK     | 12.27              |
| NRF52_DK-GCC_ARM | NRF52_DK      | tests-ubirch-chained | ubirch protocol [chained] write                  | 1      | 0      | OK     | 0.05               |
| NRF52_DK-GCC_ARM | NRF52_DK      | tests-ubirch-kex     | ubirch protocol [kex] init                       | 1      | 0      | OK     | 0.06               |
| NRF52_DK-GCC_ARM | NRF52_DK      | tests-ubirch-kex     | ubirch protocol [kex] register signed            | 1      | 0      | OK     | 0.91               |
| NRF52_DK-GCC_ARM | NRF52_DK      | tests-ubirch-plain   | ubirch protocol [plain] init                     | 1      | 0      | OK     | 0.05               |
| NRF52_DK-GCC_ARM | NRF52_DK      | tests-ubirch-plain   | ubirch protocol [plain] message (unsupported)    | 1      | 0      | OK     | 0.08               |
| NRF52_DK-GCC_ARM | NRF52_DK      | tests-ubirch-plain   | ubirch protocol [plain] message finish           | 1      | 0      | OK     | 0.07               |
| NRF52_DK-GCC_ARM | NRF52_DK      | tests-ubirch-plain   | ubirch protocol [plain] message finish (fails)   | 1      | 0      | OK     | 0.07               |
| NRF52_DK-GCC_ARM | NRF52_DK      | tests-ubirch-plain   | ubirch protocol [plain] message simple           | 1      | 0      | OK     | 0.15               |
| NRF52_DK-GCC_ARM | NRF52_DK      | tests-ubirch-plain   | ubirch protocol [plain] message start            | 1      | 0      | OK     | 0.07               |
| NRF52_DK-GCC_ARM | NRF52_DK      | tests-ubirch-plain   | ubirch protocol [plain] new                      | 1      | 0      | OK     | 0.06               |
| NRF52_DK-GCC_ARM | NRF52_DK      | tests-ubirch-plain   | ubirch protocol [plain] write                    | 1      | 0      | OK     | 0.06               |
| NRF52_DK-GCC_ARM | NRF52_DK      | tests-ubirch-signed  | ubirch protocol [signed] init                    | 1      | 0      | OK     | 0.07               |
| NRF52_DK-GCC_ARM | NRF52_DK      | tests-ubirch-signed  | ubirch protocol [signed] message finish          | 1      | 0      | OK     | 2.2                |
| NRF52_DK-GCC_ARM | NRF52_DK      | tests-ubirch-signed  | ubirch protocol [signed] message finish (fails)  | 1      | 0      | OK     | 0.08               |
| NRF52_DK-GCC_ARM | NRF52_DK      | tests-ubirch-signed  | ubirch protocol [signed] message signed          | 1      | 0      | OK     | 2.42               |
| NRF52_DK-GCC_ARM | NRF52_DK      | tests-ubirch-signed  | ubirch protocol [signed] message start           | 1      | 0      | OK     | 0.06               |
| NRF52_DK-GCC_ARM | NRF52_DK      | tests-ubirch-signed  | ubirch protocol [signed] message verify          | 1      | 0      | OK     | 2.2                |
| NRF52_DK-GCC_ARM | NRF52_DK      | tests-ubirch-signed  | ubirch protocol [signed] new                     | 1      | 0      | OK     | 0.05               |
| NRF52_DK-GCC_ARM | NRF52_DK      | tests-ubirch-signed  | ubirch protocol [signed] write                   | 1      | 0      | OK     | 0.07               |
+------------------+---------------+----------------------+--------------------------------------------------+--------+--------+--------+--------------------+
```


