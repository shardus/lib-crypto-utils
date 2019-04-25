const { join } = require('path')
const sodium = require('sodium').api
const stringify = require('fast-stable-stringify')
const FastPool = require('fast-pool')
const xor = require('buffer-xor')

const utf8Encoder = new TextEncoder()

let FAST_POOL
let HASH_KEY

const fastified = {
  // function sign (msg: ArrayBuffer, sk: ArrayBuffer) : ArrayBuffer {},
  sign (msg, sk) {
    const msgBuf = Buffer.from(msg)
    const skBuf = Buffer.from(sk)
    const sigBuf = sodium.crypto_sign(msgBuf, skBuf)
    return sigBuf.buffer
  },
  // function verify (sig: ArrayBuffer, pk: ArrayBuffer) : ArrayBuffer {},
  verify (sig, pk) {
    const sigBuf = Buffer.from(sig)
    const pkBuf = Buffer.from(pk)
    let openedBuf = sodium.crypto_sign_open(sigBuf, pkBuf)
    if (!openedBuf) openedBuf = new Uint8Array()
    return openedBuf.buffer
  }
}

FastPool.registerFunctions([
  fastified.sign,
  fastified.verify
])

function init (key, { threads = 0 } = {}) {
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

  if (_exists(threads) && threads > 0) {
    if (typeof threads !== 'number') throw new TypeError('Threads must be a number >= 0.')
    const opts = { threads }
    FAST_POOL = new FastPool(join(__dirname, 'index.js'), opts)
  }
}

// function hash (msg: string) : string {}
// Returns the Blake2b hash of the input string or Buffer, default output type is hex
function hash (msg) {
  const msgBuf = _ensureBuffer(msg, 'Msg')
  const hashBuf = sodium.crypto_hash_sha256(msgBuf, HASH_KEY)
  return hashBuf.toString('hex')
}
// function sign (msg: string, sk: string) : Promise<string> {}
// Returns a signature obtained by signing the input hash (hex string or buffer) with the sk string
function sign (msg, sk) {
  return new Promise((resolve, reject) => {
    const msgArr = utf8Encoder.encode(msg).buffer
    const skArr = Uint8Array.from(Buffer.from(sk, 'hex')).buffer
    if (FAST_POOL) {
      FAST_POOL.run(0, [msgArr, skArr], _generateCallback(resolve, reject, result => Buffer.from(result).toString('hex')))
    } else {
      try {
        const sig = Buffer.from(fastified.sign(msgArr, skArr)).toString('hex')
        resolve(sig)
      } catch (e) {
        reject(e)
      }
    }
  })
}
// function verify (msg: string, sig: string, pk: string) : Promise<boolean> {}
// Returns true if the hash of the input was signed by the owner of the pk
function verify (msg, sig, pk) {
  return new Promise((resolve, reject) => {
    const sigArr = Uint8Array.from(Buffer.from(sig, 'hex')).buffer
    const pkArr = Uint8Array.from(Buffer.from(pk, 'hex')).buffer
    function gotResult (result) {
      const opened = Buffer.from(result).toString('utf8')
      resolve(opened === msg)
    }
    if (FAST_POOL) {
      FAST_POOL.run(1, [sigArr, pkArr], (err, result) => {
        if (err) {
          reject(err)
        } else {
          gotResult(result)
        }
      })
    } else {
      try { gotResult(fastified.verify(sigArr, pkArr)) } catch (e) { reject(e) }
    }
  })
}
// function tag (msg: string, sharedKey: string): string {}
// Returns an authentication tag obtained by encrypting the hash of the message string with a key produced from the given sk and pk
function tag (msg, sharedKey) {
  const messageBuf = Buffer.from(msg, 'utf8')

  const nonceBuf = Buffer.allocUnsafe(sodium.crypto_auth_BYTES)
  sodium.randombytes_buf(nonceBuf)
  const nonce = nonceBuf.toString('hex')
  const keyBuf = _getAuthKey(sharedKey, nonce)

  const tagBuf = sodium.crypto_auth(messageBuf, keyBuf)

  const tag = tagBuf.toString('hex')
  return tag + nonce
}
// function authenticate (msg: string, tag: string, sharedkey: string) : boolean {}
// Returns true if tag is a valid authentication tag for message string
function authenticate (msg, tag, sharedKey) {
  const nonce = tag.substring(sodium.crypto_auth_BYTES * 2)
  tag = tag.substring(0, sodium.crypto_auth_BYTES * 2)
  const tagBuf = _ensureBuffer(tag, 'Tag')

  const keyBuf = _getAuthKey(sharedKey, nonce)

  const messageBuf = Buffer.from(msg, 'utf8')
  return sodium.crypto_auth_verify(tagBuf, messageBuf, keyBuf) === 0
}

// function hashObj (obj: object, removeSign: boolean, removeTag: boolean) : string {
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
// async function signObj (obj: object, sk: string, pk: string) : Promise<void> {}
/* Attaches a sign field to the input object, containing a signed version
 * of the hash of the object, along with the public key of the signer
 */
async function signObj (obj, sk, pk) {
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
  let hashed = hash(objStr)
  let sig = await sign(hashed, sk)
  obj.sign = { owner: pk, sig }
}
// async function verifyObj (obj: object) : Promise<boolean> {}
// Returns true if the hash of the object minus the sign field matches the signed message in the sign field
async function verifyObj (obj) {
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
// function tagObj (obj: object, sharedKey: string) : void {}
// Attaches a tag field to the input object, containg an authentication tag for the obj
function tagObj (obj, sharedKey) {
  if (typeof obj !== 'object') {
    throw new TypeError('Input must be an object.')
  }
  // If it's an array, we don't want to try to sign it
  if (obj.length !== undefined) {
    throw new TypeError('Input cannot be an array.')
  }
  if (typeof sharedKey !== 'string' && !Buffer.isBuffer(sharedKey)) {
    throw new TypeError('Shared key must be a hex string or hex buffer.')
  }
  const objStr = stringify(obj)
  obj.tag = tag(objStr, sharedKey)
}
// function authenticateObj (obj: object, sharedKey: string) : boolean {}
// Returns true if the authentication tag is a valid tag for the object minus the tag field
function authenticateObj (obj, sharedKey) {
  if (typeof obj !== 'object') {
    throw new TypeError('Input must be an object.')
  }
  if (!obj.tag) {
    throw new Error('Object must contain a tag field')
  }
  const tag = obj.tag
  delete obj.tag
  const objStr = stringify(obj)
  obj.tag = tag
  return authenticate(objStr, tag, sharedKey)
}

// function randomBytes (bytes: number) : string {}
// Returns 32-bytes random hex string, otherwise the number of bytes can be specified as an integer
function randomBytes (bytes = 32) {
  if (!Number.isInteger(bytes) || bytes <= 0) {
    throw new TypeError('Bytes must be given as integer greater than zero.')
  }
  const buf = Buffer.allocUnsafe(bytes)
  sodium.randombytes_buf(buf)
  return buf.toString('hex')
}
// function generateKeypair () : { publicKey: string, secretKey: string } {}
// Generates and retuns {publicKey, secretKey} as hex strings
function generateKeypair () {
  const keypair = sodium.crypto_sign_keypair()
  keypair.secretKey = keypair.secretKey.toString('hex')
  keypair.publicKey = keypair.publicKey.toString('hex')
  return keypair
}
// function convertSkToCurve (sk: string) : string {}
// Returns a curve sk represented as a hex string when given an sk
function convertSkToCurve (sk) {
  const skBuf = _ensureBuffer(sk)
  let curveSkBuf
  try {
    curveSkBuf = sodium.crypto_sign_ed25519_sk_to_curve25519(skBuf)
  } catch (e) {
    throw new Error('Could not convert given secret key to curve secret key.')
  }
  return curveSkBuf.toString('hex')
}
// function convertPkToCurve (pk: string) : string {}
// Returns a curve pk represented as a hex string when given a pk
function convertPkToCurve (pk) {
  const pkBuf = _ensureBuffer(pk)
  let curvePkBuf
  try {
    curvePkBuf = sodium.crypto_sign_ed25519_pk_to_curve25519(pkBuf)
  } catch (e) {
    throw new Error('Could not convert given public key to curve public key.')
  }
  return curvePkBuf.toString('hex')
}
// function generateSharedKey (curveSk: string, curvePk: string) : string {}
// Computes and returns a sharedKey from the given curveSk and curvePk
function generateSharedKey (curveSk, curvePk) {
  const curveSkBuf = _ensureBuffer(curveSk)
  const curvePkBuf = _ensureBuffer(curvePk)
  let keyBuf
  keyBuf = sodium.crypto_scalarmult(curveSkBuf, curvePkBuf)
  return keyBuf.toString('hex')
}
// function cleanup (callback: () => {}) : void  {}
// Terminates existing threads
function cleanup (callback = () => {}) {
  if (FAST_POOL) FAST_POOL.cleanup(callback)
}

function _generateCallback (resolve, reject, transformation) {
  return function handler (err, result) {
    if (err) {
      reject(err)
    } else {
      resolve(transformation(result))
    }
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
function _getAuthKey (sharedKey, nonce) {
  const sharedKeyBuf = _ensureBuffer(sharedKey)
  const nonceBuf = _ensureBuffer(nonce)
  const resultBuf = xor(sharedKeyBuf, nonceBuf)
  return resultBuf
}
function _exists (thing) {
  return (typeof thing !== 'undefined' && thing !== null)
}

exports = module.exports = init

exports.hash = hash
exports.sign = sign
exports.verify = verify
exports.tag = tag
exports.authenticate = authenticate

exports.hashObj = hashObj
exports.signObj = signObj
exports.verifyObj = verifyObj
exports.tagObj = tagObj
exports.authenticateObj = authenticateObj

exports.randomBytes = randomBytes
exports.generateKeypair = generateKeypair
exports.convertSkToCurve = convertSkToCurve
exports.convertPkToCurve = convertPkToCurve
exports.generateSharedKey = generateSharedKey
exports.cleanup = cleanup
