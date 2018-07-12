# ulc-crypto-utils

Provides a simple interface to node-sodium cryptographic functions, as used by the ULC Project.

```JavaScript
const crypto = require('ulc-crypto-utils')

// Module has a constructor that takes in a 32-byte hex key as required by node-sodium for generic hashing
crypto('64f152869ca2d473e4ba64ab53f49ccdb2edae22da192c126850970e788af347')

// Returns a random 256-bit hex string
crypto.randomBits()

// Returns the hash of the input
crypto.hash(input)

// Generates and returns {publicKey, secretKey} as hex strings
crypto.generateKeypair()

// Returns a signature obtained by signing the input (a hash) with the sk
crypto.sign(input, sk)

// Returns true if the input was signed by the owner of the pk
crypto.verify(input, sig, pk)
```

## Install

`npm install ULCproject/ulc-crypto-utils`

## Use

```JavaScript
const crypto = require('ulc-crypto-utils')
crypto('64f152869ca2d473e4ba64ab53f49ccdb2edae22da192c126850970e788af347')

let msg = crypto.hash('Hello world!')
console.log(msg)
```
