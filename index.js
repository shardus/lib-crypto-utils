const sodium = require('sodium').api
const stringify = require('json-stable-stringify')
let crypto
try {
  crypto = require('crypto')
} catch (e) {
  console.log('FATAL: Node compiled without crypto support.')
  process.exit()
}

// Returns a random 256 bit hex string
function randomBits () {
  return crypto.randomBytes(32).toString('hex')
}

// Returns the hash of the obj
function hash (obj) {
  let hash = crypto.createHash('sha256')
  hash.update(stringify(obj))
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

// Returns a signature obtained by signing the obj with the sk
function sign (obj, sk) {
  let objhashBuf = Buffer.from(hash(stringify(obj)), 'hex')
  let skBuf = Buffer.from(sk, 'hex')
  let sig = sodium.crypto_sign(objhashBuf, skBuf).toString('hex')
  return sig
}

// Returns true if the object was signed by the owner of the pk
function verify (obj, sig, pk) {
  let sigBuf = Buffer.from(sig, 'hex')
  let pkBuf = Buffer.from(pk, 'hex')
  let sighash = sodium.crypto_sign_open(sigBuf, pkBuf).toString('hex')
  let objhash = hash(stringify(obj))
  return sighash === objhash
}

exports.randomBits = randomBits
exports.hash = hash
exports.generateKeypair = generateKeypair
exports.sign = sign
exports.verify = verify
