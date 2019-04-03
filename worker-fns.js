const sodium = require('sodium-native')
const workerpool = require('workerpool')
const xor = require('buffer-xor/inplace')

// Returns an authentication tag obtained by encrypting the hash of the message string with a key produced from the given sk and pk
function tag (message, curveSk, curvePk) {
  const messageBuf = Buffer.from(message, 'utf8')

  const nonceBuf = Buffer.allocUnsafe(sodium.crypto_auth_BYTES)
  sodium.randombytes_buf(nonceBuf)
  const nonce = nonceBuf.toString('hex')
  const keyBuf = _generateSharedKey(curveSk, curvePk, nonce)

  const tagBuf = Buffer.allocUnsafe(sodium.crypto_auth_BYTES)
  sodium.crypto_auth(tagBuf, messageBuf, keyBuf)

  const tag = tagBuf.toString('hex')
  return tag + nonce
}

// Returns true if tag is a valid authentication tag for message string
function authenticate (message, tag, curveSk, curvePk) {
  const nonce = tag.substring(sodium.crypto_auth_BYTES * 2)
  tag = tag.substring(0, sodium.crypto_auth_BYTES * 2)
  const tagBuf = _ensureBuffer(tag, 'Tag')

  const keyBuf = _generateSharedKey(curveSk, curvePk, nonce)

  const messageBuf = Buffer.from(message, 'utf8')
  return sodium.crypto_auth_verify(tagBuf, messageBuf, keyBuf)
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

function _generateSharedKey (curveSk, curvePk, nonce) {
  const curveSkBuf = _ensureBuffer(curveSk)
  const curvePkBuf = _ensureBuffer(curvePk)
  const nonceBuf = _ensureBuffer(nonce)

  const keyBuf = Buffer.allocUnsafe(sodium.crypto_scalarmult_BYTES)
  sodium.crypto_scalarmult(keyBuf, curveSkBuf, curvePkBuf)

  xor(keyBuf, nonceBuf)
  return keyBuf
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

workerpool.worker({
  tag: tag,
  authenticate: authenticate,
  sign: sign,
  verify: verify
})
