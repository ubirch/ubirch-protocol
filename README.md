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
  ([ED25519](https://ed25519.cr.yp.to/) signature, 64 bytes)
   > Calculated over the [SHA256](https://en.wikipedia.org/wiki/SHA-2) of the binary representation of previous fields.

An example is below, with the UUID (`abcdefghijklmnop`) and a subsequent message containing the chained previous
signature:

```
MESSAGE 1:
00000000: 95cd 0401 b061 6263 6465 6667 6869 6a6b  .....abcdefghijk
00000010: 6c6d 6e6f 70da 0040 0000 0000 0000 0000  lmnop..@........
00000020: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000030: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000040: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000050: 0000 0000 0000 0000 aa30 3132 3334 3536  .........0123456
00000060: 3738 39da 0040 161c 4d0e 934e 80fe 0fd7  789..@..M..N....
00000070: be40 a597 1752 e190 8686 65ff 135a 8da2  .@...R....e..Z..
00000080: 4b97 b709 8479 19a1 0972 d8dd 53c4 9c37  K....y...r..S..7
00000090: 6ae1 2b64 1b5a 2c9c 70cb 3565 dd42 6d37  j.+d.Z,.p.5e.Bm7
000000a0: b998 816d 7105                           ...mq.

MESSAGE 2:
00000000: 95cd 0401 b061 6263 6465 6667 6869 6a6b  .....abcdefghijk
00000010: 6c6d 6e6f 70da 0040 161c 4d0e 934e 80fe  lmnop..@..M..N..
00000020: 0fd7 be40 a597 1752 e190 8686 65ff 135a  ...@...R....e..Z
00000030: 8da2 4b97 b709 8479 19a1 0972 d8dd 53c4  ..K....y...r..S.
00000040: 9c37 6ae1 2b64 1b5a 2c9c 70cb 3565 dd42  .7j.+d.Z,.p.5e.B
00000050: 6d37 b998 816d 7105 a743 4841 494e 4544  m7...mq..CHAINED
00000060: da00 40c6 ea0d 8398 a708 050f 49e9 1508  ..@.........I...
00000070: 79f0 f216 173b a372 bd41 c4e7 2f95 6d39  y....;.r.A../.m9
00000080: 896c 02d6 3207 3eef d5f7 860d d6d8 3ca9  .l..2.>.......<.
00000090: 70c8 4e5d c751 21f2 88c2 aad7 a17d d5f0  p.N].Q!......}..
000000a0: 56bf 05                                  V..
```

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