import base64
import ed25519
import hashlib
import msgpack
from mbed_host_tests import BaseHostTest, event_callback
from time import sleep


class CryptoProtocolTests(BaseHostTest):

    def __unpackMessage(self, message):
        _payload = b''
        _signature = b''
        _last_signature = b''
        unpacked = msgpack.unpackb(message)
        _variant = unpacked[0] & 0x000F
        _uuid = unpacked[1]
        if _variant == 1 or _variant == 2:
            _type = unpacked[2]
            _payload = unpacked[3]
        if _variant == 2:
            _signature = unpacked[4]
        if _variant == 3:
            _last_signature = unpacked[2]
            _type = unpacked[3]
            _payload = unpacked[4]
            _signature = unpacked[5]
        return _variant, _uuid, _last_signature, _type, _payload, _signature

    def __verifySignature(self, message, signature):
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
            variant, uuid, last_signature, type, payload, signature = self.__unpackMessage(message)
            if type == 1:
                self.vk = ed25519.VerifyingKey(payload['pubKey'])
            if variant == 2 or variant == 3:
                self.__verifySignature(message, signature)
            # sometimes the python script is too fast, looks like the DUT is
            # not ready to accept the response then :(
            sleep(1)
            self.send_kv("variant", variant)
            self.send_kv("uuid", uuid)
            if type == 0: self.send_kv("payload", payload)
            # if variant == 3: self.send_kv("last signature", last_signature.encode('hex'))

        except Exception as e:
            self.send_kv("error", e.message)