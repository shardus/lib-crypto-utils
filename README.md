# crypto-utils

Provides a simple interface to cryptographic functions.

```JavaScript
// Returns a random 256 bit hex string
randomBits()

// Returns the hash of the obj
hash(obj)

// Generates and retuns {publicKey, secretKey} as hex strings
generateKeypair()

// Returns a signature obtained by signing the obj with the sk
sign(obj, sk)

// Returns true if the object was signed by the owner of the pk
verify(obj, sig, pk)
```

## Install

`npm install asyed94/crypto-utils`
