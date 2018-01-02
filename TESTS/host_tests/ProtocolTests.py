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
        unpacked = msgpack.unpackb(message)
        signature = unpacked[4]
        tohash = message[0:-67]
        hash = hashlib.sha256(tohash).digest()
        self.log("hash      : " + hash.encode('hex'))
        self.log("public key: " + self.vk.to_bytes().encode('hex'))
        try:
            self.vk.verify(signature, hash)
            self.send_kv("verify", "OK")
        except Exception as e:
            self.send_kv("error", e.message)
