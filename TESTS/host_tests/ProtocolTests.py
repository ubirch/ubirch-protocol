import base64
import hashlib
from time import sleep

import msgpack

from mbed_host_tests import BaseHostTest, event_callback
import ed25519

class CryptoProtocolTests(BaseHostTest):

    @event_callback("publicKey")
    def __importKey(self, key, value, timestamp):
        self.vk = ed25519.VerifyingKey(value, encoding="base64")

    @event_callback("checkMessage")
    def __verifySignature(self, key, value, timestamp):
        message = base64.b64decode(value.split(";", 1)[0])
        self.log("msg: "+ message.encode('hex'))
        try:
            signature = b''
            unpacked = msgpack.unpackb(message)
            protocolVariant = unpacked[0] & 0x000F
            if protocolVariant == 2 or protocolVariant == 3:
                if protocolVariant == 2: signature = unpacked[4]
                if protocolVariant == 3: signature = unpacked[5]
                tohash = message[0:-66]
                hash = hashlib.sha512(tohash).digest()
                self.log("hash      : " + hash.encode('hex'))
                self.log("public key: " + self.vk.to_bytes().encode('hex'))
                self.log("signature : " + signature.encode('hex'))
                self.vk.verify(signature, hash)
            # sometimes the python script is too fast, looks like the DUT is
            # not ready to accept the response then :(
            sleep(1)
            self.send_kv("verify", protocolVariant)
        except Exception as e:
            self.send_kv("error", e.message)
