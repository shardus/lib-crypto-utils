const sodium = require('sodium').api
const stringify = require('json-stable-stringify')

let HASH_KEY

// Returns 32-bytes random hex string, otherwise the number of bytes can be specified as an integer
function randomBytes (bytes = 32) {
  if (!Number.isInteger(bytes) || bytes <= 0) {
    throw new TypeError('Bytes must be given as integer greater than zero.')
  }
  let buf = Buffer.allocUnsafe(bytes)
  sodium.randombytes_buf(buf)
  return buf.toString('hex')
}

// Returns the Blake2b hash of the input string or Buffer, default output type is hex
function hash (input, fmt = 'hex') {
  if (!HASH_KEY) {
    throw new Error('Hash key must be passed to module constructor.')
  }
  let buf
  if (Buffer.isBuffer(input)) {
    buf = input
  } else {
    if (typeof input !== 'string') {
      throw new TypeError('Input must be a string or buffer.')
    }
    buf = Buffer.from(input, 'utf8')
  }
  let digest = sodium.crypto_generichash_blake2b(32, buf, HASH_KEY)
  let output
  switch (fmt) {
    case 'buffer':
      output = digest
      break
    case 'hex':
      output = digest.toString('hex')
      break
    default:
      throw Error('Invalid type for output format.')
  }
  return output
}

// Returns the hash of the provided object as a hex string, takes an optional second parameter to hash an object with the "sign" field
function hashObj (obj, removeSign = false) {
  if (typeof obj !== 'object') {
    throw TypeError('Input must be an object.')
  }
  function performHash (obj) {
    let input = stringify(obj)
    let hashed = hash(input)
    return hashed
  }
  if (removeSign) {
    if (!obj.sign) {
      throw Error('Object must contain a sign field if removeSign is flagged true.')
    }
    let signObj = obj.sign
    delete obj.sign
    let hashed = performHash(obj)
    obj.sign = signObj
    return hashed
  } else {
    return performHash(obj)
  }
}

// Generates and retuns {publicKey, secretKey} as hex strings
function generateKeypair () {
  let {publicKey: pk, secretKey: sk} = sodium.crypto_sign_keypair()
  return {
    publicKey: pk.toString('hex'),
    secretKey: sk.toString('hex')
  }
}

// Returns a signature obtained by signing the input hash (hex string or buffer) with the sk string
function sign (input, sk) {
  let inputBuf
  let skBuf
  if (typeof input !== 'string') {
    if (Buffer.isBuffer(input)) {
      inputBuf = input
    } else {
      throw new TypeError('Input must be a hex string or buffer.')
    }
  } else {
    try {
      inputBuf = Buffer.from(input, 'hex')
    } catch (e) {
      throw new TypeError('Input string must be in hex format.')
    }
  }
  if (typeof sk !== 'string') {
    if (Buffer.isBuffer(sk)) {
      skBuf = sk
    } else {
      throw new TypeError('Secret key must be a hex string or buffer.')
    }
  } else {
    try {
      skBuf = Buffer.from(sk, 'hex')
    } catch (e) {
      throw new TypeError('Secret key string must be in hex format')
    }
  }
  let sig
  try {
    sig = sodium.crypto_sign(inputBuf, skBuf).toString('hex')
  } catch (e) {
    throw new Error('Failed to sign input with provided secret key.')
  }
  return sig
}

/*
  Attaches a sign field to the input object, containing a signed version
  of the hash of the object, along with the public key of the signer
*/
function signObj (obj, sk, pk) {
  if (typeof obj !== 'object') {
    throw new TypeError('Input must be an object.')
  }
  if (typeof sk !== 'string') {
    throw new TypeError('Secret key must be a string.')
  }
  if (typeof pk !== 'string') {
    throw new TypeError('Public key must be a string.')
  }
  let objStr = stringify(obj)
  let hashed = hash(objStr, 'buffer')
  let sig = sign(hashed, sk)
  obj.sign = { owner: pk, sig }
}

// Returns true if the hash of the input was signed by the owner of the pk
function verify (msg, sig, pk) {
  if (typeof msg !== 'string') {
    throw new TypeError('Message to compare must be a string.')
  }
  let sigBuf
  if (typeof sig !== 'string') {
    if (Buffer.isBuffer(sig)) {
      sigBuf = sig
    } else {
      throw new TypeError('Signature must be a hex string.')
    }
  } else {
    try {
      sigBuf = Buffer.from(sig, 'hex')
    } catch (e) {
      throw new TypeError('Signature must be a hex string.')
    }
  }
  if (typeof pk !== 'string') {
    throw new TypeError('Public key must be a hex string.')
  }
  let pkBuf
  try {
    pkBuf = Buffer.from(pk, 'hex')
  } catch (e) {
    throw new TypeError('Public key must be a hex string.')
  }
  try {
    let verified = sodium.crypto_sign_open(sigBuf, pkBuf).toString('hex')
    return verified === msg
  } catch (e) {
    throw new Error('Unable to verify provided signature with provided public key.')
  }
}

// Returns true if the hash of the object minus the sign field matches the signed message in the sign field
function verifyObj (obj) {
  if (typeof obj !== 'object') {
    throw new TypeError('Input must be an object.')
  }
  if (!obj.sign || !obj.sign.owner || !obj.sign.sig) {
    throw new Error('Object must contain a sign field with the following data: { owner, sig }')
  }
  if (typeof obj.sign.owner !== 'string') {
    throw new TypeError('Owner must be a public key represented as a hex string.')
  }
  if (typeof obj.sign.sig !== 'string') {
    throw new TypeError('Signature must be a valid signature represented as a hex string.')
  }
  let objHash = hashObj(obj, true)
  return verify(objHash, obj.sign.sig, obj.sign.owner)
}

function init (key) {
  if (!key) {
    throw new Error('Hash key must be passed to module constructor.')
  }
  try {
    HASH_KEY = Buffer.from(key, 'hex')
    if (HASH_KEY.length !== 32) {
      throw new TypeError()
    }
  } catch (e) {
    throw new TypeError('Hash key must be a 32-byte string.')
  }
}

exports = module.exports = init

exports.stringify = stringify
exports.randomBytes = randomBytes
exports.hash = hash
exports.hashObj = hashObj
exports.generateKeypair = generateKeypair
exports.sign = sign
exports.signObj = signObj
exports.verify = verify
exports.verifyObj = verifyObj
