const sodium = require('sodium-native')
const stringify = require('fast-stable-stringify')

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
  let digest = Buffer.allocUnsafe(32)
  sodium.crypto_generichash(digest, buf, HASH_KEY)
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
function hashObj (obj, removeSign = false, removeTag = false) {
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
  } else if (removeTag) {
    if (!obj.tag) {
      throw Error('Object must contain a tag field if removeTag is flagged true.')
    }
    let tagObj = obj.tag
    delete obj.tag
    let hashed = performHash(obj)
    obj.tag = tagObj
    return hashed
  } else {
    return performHash(obj)
  }
}

// Generates and retuns {publicKey, secretKey} as hex strings
function generateKeypair () {
  let publicKey = Buffer.allocUnsafe(sodium.crypto_sign_PUBLICKEYBYTES)
  let secretKey = Buffer.allocUnsafe(sodium.crypto_sign_SECRETKEYBYTES)
  sodium.crypto_sign_keypair(publicKey, secretKey)
  return {
    publicKey: publicKey.toString('hex'),
    secretKey: secretKey.toString('hex')
  }
}

// Returns a curve sk represented as a hex string when given an sk
function convertSkToCurve (sk) {
  const skBuf = _ensureBuffer(sk)
  const curveSkBuf = Buffer.allocUnsafe(sodium.crypto_box_SECRETKEYBYTES)
  try {
    sodium.crypto_sign_ed25519_sk_to_curve25519(curveSkBuf, skBuf)
  } catch (e) {
    throw new Error('Could not convert given secret key to curve secret key.')
  }
  return curveSkBuf.toString('hex')
}

// Returns a curve pk represented as a hex string when given a pk
function convertPkToCurve (pk) {
  const pkBuf = _ensureBuffer(pk)
  const curvePkBuf = Buffer.allocUnsafe(sodium.crypto_box_PUBLICKEYBYTES)
  try {
    sodium.crypto_sign_ed25519_pk_to_curve25519(curvePkBuf, pkBuf)
  } catch (e) {
    throw new Error('Could not convert given public key to curve public key.')
  }
  return curvePkBuf.toString('hex')
}

// Returns a tag obtained by encrypting the input hash (hex string or buffer) with a key produced from the given sk and pk
function encrypt (input, curveSk, curvePk) {
  const inputBuf = _ensureBuffer(input)
  const curveSkBuf = _ensureBuffer(curveSk, 'Secret key')
  const curvePkBuf = _ensureBuffer(curvePk, 'Public key')
  const ciphertext = Buffer.allocUnsafe(inputBuf.length + sodium.crypto_box_MACBYTES)
  const nonce = Buffer.allocUnsafe(sodium.crypto_box_NONCEBYTES)
  sodium.randombytes_buf(nonce)
  sodium.crypto_box_easy(ciphertext, inputBuf, nonce, curvePkBuf, curveSkBuf)
  const tag = [ciphertext.toString('hex'), nonce.toString('hex')]
  return JSON.stringify(tag)
}

/**
 * Attaches a tag field to the input object, containg an encrypted version
 * of the hash of the object, along with the curve25519 public key of the encrypter
 */
function encryptObj (obj, curveSk, curvePk, recipientCurvePk) {
  if (typeof obj !== 'object') {
    throw new TypeError('Input must be an object.')
  }
  // If it's an array, we don't want to try to sign it
  if (obj.length !== undefined) {
    throw new TypeError('Input cannot be an array.')
  }
  if (typeof curveSk !== 'string') {
    throw new TypeError('Secret key must be a string.')
  }
  if (typeof curvePk !== 'string') {
    throw new TypeError('Public key must be a string.')
  }
  const objStr = stringify(obj)
  const hashed = hash(objStr, 'buffer')
  const tag = encrypt(hashed, curveSk, recipientCurvePk)
  obj.tag = { owner: curvePk, value: tag }
}

// Returns true if the hash of the input was encypted by the owner of the pk
function decrypt (msg, tag, curveSk, curvePk) {
  tag = JSON.parse(tag)
  const ciphertext = _ensureBuffer(tag[0], 'Tag ciphertext')
  const nonce = _ensureBuffer(tag[1], 'Tag nonce')
  const secretKey = _ensureBuffer(curveSk, 'Secret key')
  const publicKey = _ensureBuffer(curvePk, 'Public key')
  const message = Buffer.allocUnsafe(ciphertext.length - sodium.crypto_box_MACBYTES)
  const isValid = sodium.crypto_box_open_easy(message, ciphertext, nonce, publicKey, secretKey)
  const isMatch = msg === message.toString('hex')
  return isValid && isMatch
}

/**
 * Returns true if the hash of the object minus the tag field matches the encrypted message in the tag field
 */
function decryptObj (obj, curveSk) {
  if (typeof obj !== 'object') {
    throw new TypeError('Input must be an object.')
  }
  if (!obj.tag || !obj.tag.owner || !obj.tag.value) {
    throw new Error('Object must contain a tag field with the following data: { owner, value }')
  }
  if (typeof obj.tag.owner !== 'string') {
    throw new TypeError('Owner must be a public key represented as a hex string.')
  }
  if (typeof obj.tag.value !== 'string') {
    throw new TypeError('Value must be a valid , 2 element array represented as a JSON string.')
  }
  const objHash = hashObj(obj, false, true)
  return decrypt(objHash, obj.tag.value, curveSk, obj.tag.owner)
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
  let sig = Buffer.allocUnsafe(inputBuf.length + sodium.crypto_sign_BYTES)
  try {
    sodium.crypto_sign(sig, inputBuf, skBuf)
  } catch (e) {
    throw new Error('Failed to sign input with provided secret key.')
  }
  return sig.toString('hex')
}

/*
  Attaches a sign field to the input object, containing a signed version
  of the hash of the object, along with the public key of the signer
*/
function signObj (obj, sk, pk) {
  if (typeof obj !== 'object') {
    throw new TypeError('Input must be an object.')
  }
  // If it's an array, we don't want to try to sign it
  if (obj.length !== undefined) {
    throw new TypeError('Input cannot be an array.')
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
    let opened = Buffer.allocUnsafe(sigBuf.length - sodium.crypto_sign_BYTES)
    sodium.crypto_sign_open(opened, sigBuf, pkBuf)
    let verified = opened.toString('hex')
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

function _ensureBuffer (input, name = 'Input') {
  if (typeof input !== 'string') {
    if (Buffer.isBuffer(input)) {
      return input
    } else {
      throw new TypeError(`${name} must be a hex string or buffer.`)
    }
  } else {
    try {
      return Buffer.from(input, 'hex')
    } catch (e) {
      throw new TypeError(`${name} string must be in hex format.`)
    }
  }
}

exports = module.exports = init

exports.stringify = stringify
exports.randomBytes = randomBytes
exports.hash = hash
exports.hashObj = hashObj
exports.generateKeypair = generateKeypair
exports.convertSkToCurve = convertSkToCurve
exports.convertPkToCurve = convertPkToCurve
exports.encrypt = encrypt
exports.encryptObj = encryptObj
exports.decrypt = decrypt
exports.decryptObj = decryptObj
exports.sign = sign
exports.signObj = signObj
exports.verify = verify
exports.verifyObj = verifyObj
