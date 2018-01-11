# ubirch protocol

1. [Basic Message Format](#basic-message-format)
    1. [Field Types](#field-types)
2. [Checking the Signature](#checking-the-signature) 
3. [API](#api)
    1. [Simple Message Example](#simple-message-example)
    2. [Chained Message Example](#chained-message-example)
    3. [Key Registration](#key-registration)
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
+=========+======+==================+=========+-------------+
| VERSION | UUID | [PREV-SIGNATURE] | PAYLOAD | [SIGNATURE] |
+=========+======+==================+=========+-------------+
=   ➔ data used for signature (4 elements)
[]  ➔ optional fields, depending on lower 4 bit of version
```

#### Field Types

- **VERSION** - [16 bit Integer](https://github.com/msgpack/msgpack/blob/master/spec.md#int-format-family)
    - `000000000001|0001` - version 1, simple message without signatures, `[VE, ID, PL]`
    - `000000000001|0010` - version 1, signed message without chained signatures, `[VE, ID, PL, SI]`
    - `000000000001|0011` - version 1, signed message with chained signatures, `[VE, ID, PS, PL, SI]`
- **UUID** - [128 bit, 16-byte array](https://github.com/msgpack/msgpack/blob/master/spec.md#bin-format-family)   
- **PREV-SIGNATURE** - [512 bit, 64-byte array](https://github.com/msgpack/msgpack/blob/master/spec.md#bin-format-family)
- **PAYLOAD** - ANY msgpack type (incl. raw alternative data)
- **SIGNATURE** - [512 bit, 64-byte array](https://github.com/msgpack/msgpack/blob/master/spec.md#bin-format-family) 
  ([ED25519](https://ed25519.cr.yp.to) signature, 64 bytes)
   > Calculated over the [SHA256](https://en.wikipedia.org/wiki/SHA-2) of the binary representation of previous fields.

An example is below, with the UUID (`abcdefghijklmnop`) and a subsequent message containing the chained previous
signature:


## Checking the Signature   
   
The structure allows a recipient to take off the last 64 bytes of the message and check the signature of the
message taking length - 67 bytes hashed with [SHA256](https://en.wikipedia.org/wiki/SHA-2).

Trivial Example (Python, chained message type):

```python
import msgpack
import ed25519
import hashlib

publicKey = "7c76c47c5161d0a03e7ae987010f324b875c23da813132cf8ffdaa5593e63e6a"
messageHex = "95cd0401b06162636465666768696a6b6c6d6e6f70da0040161c4d0e934e80fe0fd7be40a5971752e190868665ff135a8da24b97b709847919a10972d8dd53c49c376ae12b641b5a2c9c70cb3565dd426d37b998816d7105a7434841494e4544da0040c6ea0d8398a708050f49e9150879f0f216173ba372bd41c4e72f956d39896c02d632073eefd5f7860dd6d83ca970c84e5dc75121f288c2aad7a17dd5f056bf05"
message = messageHex.decode('hex')

vk = ed25519.VerifyingKey(publicKey, encoding='hex')

unpacked = msgpack.unpackb(message)
signature = unpacked[4]
try:
    tohash = message[0:-67]
    hash = hashlib.sha256(tohash).digest()
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


- **`ubirch_protocol_new(data, writer, sign, uuid)`** creates a new protocol context with the provided data and writer. Additionally a sign 
    function and a uuid are necessary.
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
ubirch_protocol *proto = ubirch_protocol_new(proto_chained, sbuf, msgpack_sbuffer_write, ed25519_sign, UUID);
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
00000000: 95cd 0013 b061 6263 6465 6667 6869 6a6b  .....abcdefghijk
00000010: 6c6d 6e6f 70da 0040 0000 0000 0000 0000  lmnop..@........
00000020: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000030: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000040: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000050: 0000 0000 0000 0000 63da 0040 1206 a337  ........c..@...7
00000060: 1d51 9dff c879 666d cf13 6dd8 d5af 2b10  .Q...yfm..m...+.
00000070: 337c 8552 3574 4c23 688d 0dc8 10b9 1ed4  3|.R5tL#h.......
00000080: 1634 7ca4 482a 48c9 4eee 881c 3015 1303  .4|.H*H.N...0...
00000090: b94f 7166 c379 0034 c35b c407            .Oqf.y.4.[..
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
ubirch_protocol *proto = ubirch_protocol_new(proto_chained,
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
00000000: 95cd 0013 b061 6263 6465 6667 6869 6a6b  .....abcdefghijk
00000010: 6c6d 6e6f 70da 0040 0000 0000 0000 0000  lmnop..@........
00000020: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000030: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000040: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000050: 0000 0000 0000 0000 a96d 6573 7361 6765  .........message
00000060: 2031 da00 4038 8ce9 3fe9 fde3 0006 3582   1..@8..?.....5.
00000070: ad33 6ad1 410b 7e4d d955 1400 5dd6 a690  .3j.A.~M.U..]...
00000080: 82c3 25d8 e8ff 9d4f 6b3d 1131 7a3b a1b3  ..%....Ok=.1z;..
00000090: 76d2 7d3f 1ba7 35c7 5b68 cfc8 57bd bf41  v.}?..5.[h..W..A
000000a0: 1674 837f 05                             .t...
```

#### MESSAGE 2: binary output
```
00000000: 95cd 0013 b061 6263 6465 6667 6869 6a6b  .....abcdefghijk
00000010: 6c6d 6e6f 70da 0040 388c e93f e9fd e300  lmnop..@8..?....
00000020: 0635 82ad 336a d141 0b7e 4dd9 5514 005d  .5..3j.A.~M.U..]
00000030: d6a6 9082 c325 d8e8 ff9d 4f6b 3d11 317a  .....%....Ok=.1z
00000040: 3ba1 b376 d27d 3f1b a735 c75b 68cf c857  ;..v.}?..5.[h..W
00000050: bdbf 4116 7483 7f05 a96d 6573 7361 6765  ..A.t....message
00000060: 2032 da00 404d d420 0c77 1142 c0b9 4e12   2..@M. .w.B..N.
00000070: 9605 626e f3e5 19be 2f8d ffb6 dc29 1598  ..bn..../....)..
00000080: 4014 fb93 36c7 7422 64fd 68b8 e3ff cd5d  @...6.t"d.h....]
00000090: 38e6 93b4 f8ab 4199 09f4 9136 ed73 dce2  8.....A....6.s..
000000a0: cd6d 89f0 06                             .m...
```

## Key Registration

Devices must register at the key service to make their existence known.
The key registration message is the first step and simply published a key
with some meta-data to the key service. It will later be used for looking
up keys for a certain device, i.e. when doing an initial trust hand shake.

- **`msgpack_pack_key_register(packer, uuid, pubkey, algorithm, created, validNotBefore, validNotAfter, prevPubKey)`**
    creates a msgpack message that can be used to register a given public key with the key service

These messages directly translate into `JSON`:
```json
{
     "deviceID": "...",
     "pubKey": "...",
     "algorithm": "ed25519",
     "created": 1234567890,
     "validNotBefore": 1234567890,
     "validNotAfter": 1234567899,
     "prevPubKey": "..."
}
```

## Building

Building and testing for [mbed](https://mbed.com):

```bash
mbed new .
mbed target UBRIDGE # set your own target here
mbed toolchain GCC_ARM
mbed update         # to download the dependencies
mbed compile --library
```

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
| NRF52_DK-GCC_ARM | NRF52_DK      | tests-ubirch-chained | OK     | 24.89              | default     |
| NRF52_DK-GCC_ARM | NRF52_DK      | tests-ubirch-plain   | OK     | 20.49              | default     |
| NRF52_DK-GCC_ARM | NRF52_DK      | tests-ubirch-signed  | OK     | 22.16              | default     |
+------------------+---------------+----------------------+--------+--------------------+-------------+
mbedgt: test suite results: 3 OK
mbedgt: test case report:
+------------------+---------------+----------------------+--------------------------------------------------+--------+--------+--------+--------------------+
| target           | platform_name | test suite           | test case                                        | passed | failed | result | elapsed_time (sec) |
+------------------+---------------+----------------------+--------------------------------------------------+--------+--------+--------+--------------------+
| NRF52_DK-GCC_ARM | NRF52_DK      | tests-ubirch-chained | ubirch protocol [chained] init                   | 1      | 0      | OK     | 0.07               |
| NRF52_DK-GCC_ARM | NRF52_DK      | tests-ubirch-chained | ubirch protocol [chained] message chained        | 1      | 0      | OK     | 2.48               |
| NRF52_DK-GCC_ARM | NRF52_DK      | tests-ubirch-chained | ubirch protocol [chained] message finish         | 1      | 0      | OK     | 0.96               |
| NRF52_DK-GCC_ARM | NRF52_DK      | tests-ubirch-chained | ubirch protocol [chained] message finish (fails) | 1      | 0      | OK     | 0.07               |
| NRF52_DK-GCC_ARM | NRF52_DK      | tests-ubirch-chained | ubirch protocol [chained] message simple         | 1      | 0      | OK     | 1.28               |
| NRF52_DK-GCC_ARM | NRF52_DK      | tests-ubirch-chained | ubirch protocol [chained] message start          | 1      | 0      | OK     | 0.07               |
| NRF52_DK-GCC_ARM | NRF52_DK      | tests-ubirch-chained | ubirch protocol [chained] new                    | 1      | 0      | OK     | 0.06               |
| NRF52_DK-GCC_ARM | NRF52_DK      | tests-ubirch-chained | ubirch protocol [chained] write                  | 1      | 0      | OK     | 0.07               |
| NRF52_DK-GCC_ARM | NRF52_DK      | tests-ubirch-plain   | ubirch protocol [plain] init                     | 1      | 0      | OK     | 0.06               |
| NRF52_DK-GCC_ARM | NRF52_DK      | tests-ubirch-plain   | ubirch protocol [plain] message (unsupported)    | 1      | 0      | OK     | 0.07               |
| NRF52_DK-GCC_ARM | NRF52_DK      | tests-ubirch-plain   | ubirch protocol [plain] message finish           | 1      | 0      | OK     | 0.07               |
| NRF52_DK-GCC_ARM | NRF52_DK      | tests-ubirch-plain   | ubirch protocol [plain] message finish (fails)   | 1      | 0      | OK     | 0.08               |
| NRF52_DK-GCC_ARM | NRF52_DK      | tests-ubirch-plain   | ubirch protocol [plain] message simple           | 1      | 0      | OK     | 0.21               |
| NRF52_DK-GCC_ARM | NRF52_DK      | tests-ubirch-plain   | ubirch protocol [plain] message start            | 1      | 0      | OK     | 0.06               |
| NRF52_DK-GCC_ARM | NRF52_DK      | tests-ubirch-plain   | ubirch protocol [plain] new                      | 1      | 0      | OK     | 0.06               |
| NRF52_DK-GCC_ARM | NRF52_DK      | tests-ubirch-plain   | ubirch protocol [plain] write                    | 1      | 0      | OK     | 0.05               |
| NRF52_DK-GCC_ARM | NRF52_DK      | tests-ubirch-signed  | ubirch protocol [signed] init                    | 1      | 0      | OK     | 0.07               |
| NRF52_DK-GCC_ARM | NRF52_DK      | tests-ubirch-signed  | ubirch protocol [signed] message finish          | 1      | 0      | OK     | 0.96               |
| NRF52_DK-GCC_ARM | NRF52_DK      | tests-ubirch-signed  | ubirch protocol [signed] message finish (fails)  | 1      | 0      | OK     | 0.08               |
| NRF52_DK-GCC_ARM | NRF52_DK      | tests-ubirch-signed  | ubirch protocol [signed] message signed          | 1      | 0      | OK     | 1.19               |
| NRF52_DK-GCC_ARM | NRF52_DK      | tests-ubirch-signed  | ubirch protocol [signed] message start           | 1      | 0      | OK     | 0.08               |
| NRF52_DK-GCC_ARM | NRF52_DK      | tests-ubirch-signed  | ubirch protocol [signed] new                     | 1      | 0      | OK     | 0.05               |
| NRF52_DK-GCC_ARM | NRF52_DK      | tests-ubirch-signed  | ubirch protocol [signed] write                   | 1      | 0      | OK     | 0.06               |
+------------------+---------------+----------------------+--------------------------------------------------+--------+--------+--------+--------------------+
mbedgt: test case results: 23 OK
```


