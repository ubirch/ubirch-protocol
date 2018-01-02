# ubirch protocol

## Basic Message Format

The ubirch protocol basic message format wraps the payload with an authentication header and a signature. 
The complete message, including header,payload and signature are combined in a serialized [msgpack](https://msgpack.org) 
array. 

```
+=========+======+================+=========+-----------+
| VERSION | UUID | PREV-SIGNATURE | PAYLOAD | SIGNATURE |
+=========+======+================+=========+-----------+
= ➔ data used for signature (4 elements)
```

#### Field Types

- **VERSION** - [16 bit Integer](https://github.com/msgpack/msgpack/blob/master/spec.md#int-format-family)
- **UUID** - [128 bit, 16-byte array](https://github.com/msgpack/msgpack/blob/master/spec.md#bin-format-family)   
- **PREV-SIGNATURE** - [512 bit, 64-byte array](https://github.com/msgpack/msgpack/blob/master/spec.md#bin-format-family)
- **PAYLOAD** - ANY msgpack type (incl. raw alternative data)
- **SIGNATURE** - [512 bit, 64-byte array](https://github.com/msgpack/msgpack/blob/master/spec.md#bin-format-family) 
  ([ED25519](https://ed25519.cr.yp.to) signature, 64 bytes)
   > Calculated over the [SHA256](https://en.wikipedia.org/wiki/SHA-2) of the binary representation of previous fields.

An example is below, with the UUID (`abcdefghijklmnop`) and a subsequent message containing the chained previous
signature:


## Checking the signature   
   
The structure allows a recipient to take off the last 64 bytes of the message and check the signature of the
message taking length - 67 bytes hashed with [SHA256](https://en.wikipedia.org/wiki/SHA-2).

Trivial Example:

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

# API

The ubirch protocol API is derived from the msgpack API, adding a context similar to the buffer 
implementations (`sbuffer`), which wraps the packer to hash the data. A message is then created
using the `ubirch_protocol_start()` function and signing it with `ubirch_protocol_finish()`.


- **`ubirch_protocol_new(data, writer, sign, uuid)`** creates a new protocol context with the provided data and writer. Additionally a sign 
    function and a uuid are necessary.
- **`ubirch_protocol_start(proto, packer)`** 
    start a new message using the ubirch protocol context and the provided msgpack packer.
- **`ubirch_protocol_finish(proto, packer)`** 
    finish the message, signing the header and payload.
    
## Simple Message Example

```
// creata a standard msgpack stream buffer
msgpack_sbuffer *sbuf = msgpack_sbuffer_new();
// create a ubirch protocol context from the buffer, its writer
// and provide the signature function as well as the UUID
ubirch_protocol *proto = ubirch_protocol_new(sbuf, msgpack_sbuffer_write, ed25519_sign,
                                          (const unsigned char *) UUID);
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

### Example: binary output 
```
00000000: 95cd 0401 b061 6263 6465 6667 6869 6a6b  .....abcdefghijk
00000010: 6c6d 6e6f 70da 0040 0000 0000 0000 0000  lmnop..@........
00000020: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000030: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000040: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000050: 0000 0000 0000 0000 63da 0040 a541 ec82  ........c..@.A..
00000060: 440d 1861 8c04 c0de 40e2 85a2 b73f 5a24  D..a....@....?Z$
00000070: 13e5 9be2 851d 20f1 2d82 1d37 3dd2 0623  ...... .-..7=..#
00000080: bdb7 e33f 6818 448b 9237 5e5e 7db9 cf1f  ...?h.D..7^^}...
00000090: e5e5 c453 b496 0d80 c0cc 3f08            ...S......?.
```

## Chained Message Example

> ⚠ Chained messages include the signature of the previous message
> to create a safe chain of verifyable messages. You need to keep the
> ubirch protocol context alive to create a message chain.  

The example is very similar to above, except that the ubirch protocol
context is not deleted after use.

```
// create buffer, writer, ubirch protocol context and packer
msgpack_sbuffer *sbuf = msgpack_sbuffer_new();
ubirch_protocol *proto = ubirch_protocol_new(sbuf, msgpack_sbuffer_write, ed25519_sign,
                                             (const unsigned char *) UUID);
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
00000000: 95cd 0401 b061 6263 6465 6667 6869 6a6b  .....abcdefghijk
00000010: 6c6d 6e6f 70da 0040 0000 0000 0000 0000  lmnop..@........
00000020: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000030: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000040: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000050: 0000 0000 0000 0000 a96d 6573 7361 6765  .........message
00000060: 2031 da00 4075 6f6c 2e17 5b5c ae74 63ea   1..@uol..[\.tc.
00000070: c471 141f d0e7 8bc8 0c62 e2fa 8d5c 329a  .q.......b...\2.
00000080: 048c 11ee f720 7c7a a611 0334 d123 0618  ..... |z...4.#..
00000090: 78d6 9c0b 2ef0 7ca1 ce26 86c1 ede2 3f0c  x.....|..&....?.
000000a0: 57a0 8507 00                             W....
```

#### MESSAGE 2: binary output
```
00000000: 95cd 0401 b061 6263 6465 6667 6869 6a6b  .....abcdefghijk
00000010: 6c6d 6e6f 70da 0040 756f 6c2e 175b 5cae  lmnop..@uol..[\.
00000020: 7463 eac4 7114 1fd0 e78b c80c 62e2 fa8d  tc..q.......b...
00000030: 5c32 9a04 8c11 eef7 207c 7aa6 1103 34d1  \2...... |z...4.
00000040: 2306 1878 d69c 0b2e f07c a1ce 2686 c1ed  #..x.....|..&...
00000050: e23f 0c57 a085 0700 a96d 6573 7361 6765  .?.W.....message
00000060: 2032 da00 40dc 9073 f135 bd9d d8ee ca6e   2..@..s.5.....n
00000070: 27e0 e716 7da7 bbc5 5752 2f22 96f8 d13f  '...}...WR/"...?
00000080: 4be9 2ec1 98b9 c7e3 07d3 8753 2617 a316  K..........S&...
00000090: 1098 9744 5f92 54a4 a2d7 19d1 d13b 57af  ...D_.T......;W.
000000a0: 0f3b a9a2 0a                             .;...
```
