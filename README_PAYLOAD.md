# Payload types

1. [0x00: binary or unknown payload type](#binary-or-unknown-payload-type)
2. [0x01: key registration message](#key-registration-message)
3. [0x03: msgpack object payload type](#msgpack-payload-type)
4. [0x32: ubirch standard sensor message](#ubirch-standard-sensor-message)
5. [0x53: generic sensor message](#generic-sensor-message)
6. [0x54: trackle message packet](#trackle-message-packet)
7. [0x55: ubirch/trackle message response](#ubirch-trackle-message-response)


| Payload Type | Description |
|--------------|-------------|
| `0x00` (`00`)| binary, or unknown payload type |
| `0x01` (`01`)| key registration message |
| `0x32` (`50`)| ubirch standard sensor message (msgpack) |
| `0x53` (`83`)| generic sensor message (json type key/value map) |
| `0x54` (`84`)| trackle message packet |
| `0x55` (`85`)| ubirch/trackle message response |


## binary or unknown payload type
todo
## key registration message
todo
## ubirch standard sensor message

The ubirch standard message payload is based on the 
[msgpack array format](https://github.com/msgpack/msgpack/blob/master/spec.md#array-format-family)
and can have multiple implementations, like listed below:
 
- single-timestamp, single-value
```
array[timestamp,value]
```
- single-timestamp, multiple-values(m)
```
array[timestamp,value(1),value(2),...,value(m)]
```
- multiple(n) single-timestamp, single-value
```
array(n)[array[timestamp(1),value(1)],array[timestamp(2),value(2)]...array[timestamp(n),value(n)]]
```
- multiple(n) single-timestamp, multiple-values(m)
```
array(n)[array[timestamp(1),value(1,1),value(1,2),...,value(1,m)],array[timestamp(2),value(2,1),value(2,2),...,value(2,m)],..,array[timestamp(n),value(n,1),value(n,2),...,value(n,m)]]
```
**note**: 
- timestamp (dezimal number) is the [unix time stamp](https://en.wikipedia.org/wiki/Unix_time), which can be used as is (seconds), 
but also can have a precision of milliseconds (seconds * 1000 + milliseconds)
- value can be any number

## generic sensor message
todo
## trackle message packet

```
+=========+======+==================+======+=========+-------------+
| VERSION | UUID |  PREV-SIGNATURE  | TYPE | PAYLOAD |  SIGNATURE  |
+=========+======+==================+======+=========+-------------+
```
Version is: 0001|0011 => 1.3 (signed message with chained signatures)  https://github.com/ubirch/ubirch-protocol/blob/master/README.md#field-types
Type is: 0x54 (84)  https://github.com/ubirch/ubirch-protocol/blob/master/README.md#payload-type

trackle message payload:
```
  [ // <msgpack.array[5]
    "v1.0.2-PROD-20180326103205 (v5.6.6)", // <msgpack.raw> Version String
    5, // <msgpack.uint32> wakeup cycles, increased once per measuring interval
    3, // <msgpack.unit32> device status (3 = ready)
    { // <msgpack.map[5]> (size = number of measurements)
      1643329410: 3565, // <msgpack.int32>, <msgpack.int16> timestamp, temperature in °C * 100
      1643329470: 3600, // <msgpack.int32>, <msgpack.int16> timestamp, temperature in °C * 100
      1643329530: 3625, // <msgpack.int32>, <msgpack.int16> timestamp, temperature in °C * 100
      1643329590: 3646, // <msgpack.int32>, <msgpack.int16> timestamp, temperature in °C * 100
      1643329650: 3662 // <msgpack.int32>, <msgpack.int16> timestamp, temperature in °C * 100
    },
    { // <msgpack.map[4] device configuration
      "min": 3500,  // <msgpack.raw>, <msgpack.int>
      "max": 4200,  // <msgpack.raw>, <msgpack.int>
      "i": 60000,  // <msgpack.raw>, <msgpack.int>
      "il": 1800000  // <msgpack.raw>, <msgpack.int>
    }
  ]
```

## ubirch trackle message response
```
+=========+======+==================+======+=========+-------------+
| VERSION | UUID |  PREV-SIGNATURE  | TYPE | PAYLOAD |  SIGNATURE  |
+=========+======+==================+======+=========+-------------+
```
Version is: 0001|0011 => 1.3 (signed message with chained signatures)  https://github.com/ubirch/ubirch-protocol/blob/master/README.md#field-types
Type is: 0x55 (85) https://github.com/ubirch/ubirch-protocol/blob/master/README.md#payload-type

The ubirch message response payload is based on the 
[msgpack map format](https://github.com/msgpack/msgpack/blob/master/spec.md#map-format-family),
and can have one or more key value pairs, like listed below:

- single key value pair
```
map{"key": value}
```
- multiple (n) key value pairs
```
map{"key(1)": value(1),"key(2)": value(2),...,"key(n)": value(n)}
```
