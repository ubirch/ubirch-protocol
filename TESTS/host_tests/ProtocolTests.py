import base64
import ed25519
import hashlib
import msgpack
from mbed_host_tests import BaseHostTest, event_callback
from time import sleep


class CryptoProtocolTests(BaseHostTest):

    def unpackMessage(self, message):
        payload = b''
        signature = b''
        last_signature = b''
        unpacked = msgpack.unpackb(message)
        variant = unpacked[0] & 0x000F
        uuid = unpacked[1]
        if variant == 1 or variant == 2:
            type = unpacked[2]
            payload = unpacked[3]
        if variant == 2:
            signature = unpacked[4]
        if variant == 3:
            last_signature = unpacked[2]
            type = unpacked[3]
            payload = unpacked[4]
            signature = unpacked[5]
        return variant, uuid, last_signature, type, payload, signature

    def verifySignature(self, message, signature):
        tohash = message[0:-66]
        hash = hashlib.sha512(tohash).digest()
        self.log("hash      : " + hash.encode('hex'))
        self.log("public key: " + self.vk.to_bytes().encode('hex'))
        self.log("signature : " + signature.encode('hex'))
        self.vk.verify(signature, hash)

    @event_callback("publicKey")
    def __importKey(self, key, value, timestamp):
        self.vk = ed25519.VerifyingKey(value, encoding="base64")

    @event_callback("checkMessage")
    def __checkMessage(self, key, value, timestamp):
        message = base64.b64decode(value.split(";", 1)[0])
        self.log("msg: "+ message.encode('hex'))
        try:
            variant, uuid, last_signature, type, payload, signature = self.unpackMessage(message)
            if type == 1:
                self.vk = ed25519.VerifyingKey(payload['pubKey'])
            if variant == 2 or variant == 3:
                self.verifySignature(message, signature)
            # sometimes the python script is too fast, looks like the DUT is
            # not ready to accept the response then :(
            sleep(1)
            self.send_kv("variant", variant)
            self.send_kv("uuid", uuid)
            if type == 0: self.send_kv("payload", payload)
            if variant == 3: self.send_kv("last signature", last_signature)

        except Exception as e:
            self.send_kv("error", e.message)