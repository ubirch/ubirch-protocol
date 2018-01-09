import base64
import hashlib

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
        try:
            unpacked = msgpack.unpackb(message)
            protocolVariant = unpacked[0] & 0x000F
            if protocolVariant == 2 or protocolVariant == 3:
                if protocolVariant == 2: signature = unpacked[3]
                if protocolVariant == 3: signature = unpacked[4]
                tohash = message[0:-67]
                hash = hashlib.sha256(tohash).digest()
                self.log("hash      : " + hash.encode('hex'))
                self.log("public key: " + self.vk.to_bytes().encode('hex'))
                self.vk.verify(signature, hash)
            self.send_kv("verify", protocolVariant)
        except Exception as e:
            self.send_kv("error", e.message)
