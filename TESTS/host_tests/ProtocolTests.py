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
        message = value.decode('base64')
        unpacked = msgpack.unpackb(message)
        print unpacked
        signature = unpacked[4]
        try:
            tohash = message[0:-67]
            hash = hashlib.sha256(tohash).digest()
            self.log("hash      : " + hash.encode('hex'))
            self.log("public key: " + self.vk.to_bytes().encode('hex'))
            self.vk.verify(signature, hash)
            self.send_kv("verify", "OK")
        except Exception as e:
            self.send_kv("error", e.message)
