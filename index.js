const sodium = require('sodium').api
const stringify = require('json-stable-stringify')
let crypto
try {
  crypto = require('crypto')
} catch (e) {
  console.log('FATAL: Node compiled without crypto support.')
  process.exit()
}

// Returns a random 256-bit hex string
function randomBits () {
  return crypto.randomBytes(32).toString('hex')
}

// Returns the SHA256 hash of the input
function hash (input) {
  if (typeof input !== 'string') input = stringify(input)
  let hash = crypto.createHash('sha256')
  hash.update(input)
  return hash.digest('hex')
}

// Generates and retuns {publicKey, secretKey} as hex strings
function generateKeypair () {
  let {publicKey: pk, secretKey: sk} = sodium.crypto_sign_keypair()
  return {
    publicKey: pk.toString('hex'),
    secretKey: sk.toString('hex')
  }
}

// Returns a signature obtained by signing the hash of the input with the sk
function sign (input, sk) {
  if (typeof input !== 'string') input = stringify(input)
  let inputhashBuf = Buffer.from(hash(input), 'hex')
  let skBuf = Buffer.from(sk, 'hex')
  let sig = sodium.crypto_sign(inputhashBuf, skBuf).toString('hex')
  return sig
}

// Returns true if the hash of the input was signed by the owner of the pk
function verify (input, sig, pk) {
  try {
    let sigBuf = Buffer.from(sig, 'hex')
    let pkBuf = Buffer.from(pk, 'hex')
    let sighash = sodium.crypto_sign_open(sigBuf, pkBuf).toString('hex')
    if (typeof input !== 'string') input = stringify(input)
    let inputhash = hash(input)
    return sighash === inputhash
  } catch (e) {
    return false
  }
}

exports.randomBits = randomBits
exports.hash = hash
exports.generateKeypair = generateKeypair
exports.sign = sign
exports.verify = verify
