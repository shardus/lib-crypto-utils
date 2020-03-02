"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const sodium = require('sodium-native');
const stringify = require('fast-stable-stringify');
const xor = require('buffer-xor');
/**
 * The key used for initializing the cryptographic hashing algorithms
 */
let HASH_KEY;
/**
 * Returns 32-bytes random hex string, otherwise the number of bytes can be specified as an integer
 * @param bytes
 */
function randomBytes(bytes = 32) {
    if (!Number.isInteger(bytes) || bytes <= 0) {
        throw new TypeError('Bytes must be given as integer greater than zero.');
    }
    const buf = Buffer.allocUnsafe(bytes);
    sodium.randombytes_buf(buf);
    return buf.toString('hex');
}
exports.randomBytes = randomBytes;
/**
 * Returns the Blake2b hash of the input string or Buffer, default output type is hex
 * @param input
 * @param fmt
 */
function hash(input, fmt = 'hex') {
    if (!HASH_KEY) {
        throw new Error('Hash key must be passed to module constructor.');
    }
    let buf;
    if (Buffer.isBuffer(input)) {
        buf = input;
    }
    else {
        if (typeof input !== 'string') {
            throw new TypeError('Input must be a string or buffer.');
        }
        buf = Buffer.from(input, 'utf8');
    }
    const digest = Buffer.allocUnsafe(32);
    sodium.crypto_generichash(digest, buf, HASH_KEY);
    let output;
    switch (fmt) {
        case 'buffer':
            output = digest;
            break;
        case 'hex':
            output = digest.toString('hex');
            break;
        default:
            throw Error('Invalid type for output format.');
    }
    return output;
}
exports.hash = hash;
/**
 * Returns the hash of the provided object as a hex string, takes an optional second parameter to hash an object with the "sign" field
 * @param obj
 * @param removeSign
 * @param removeTag
 */
function hashObj(obj, removeSign = false, removeTag = false) {
    if (typeof obj !== 'object') {
        throw TypeError('Input must be an object.');
    }
    function performHash(obj) {
        const input = stringify(obj);
        const hashed = hash(input);
        return hashed;
    }
    if (removeSign) {
        if (!obj.sign) {
            throw Error('Object must contain a sign field if removeSign is flagged true.');
        }
        const signObj = obj.sign;
        delete obj.sign;
        const hashed = performHash(obj);
        obj.sign = signObj;
        return hashed;
    }
    else if (removeTag) {
        if (!obj.tag) {
            throw Error('Object must contain a tag field if removeTag is flagged true.');
        }
        const tagObj = obj.tag;
        delete obj.tag;
        const hashed = performHash(obj);
        obj.tag = tagObj;
        return hashed;
    }
    else {
        return performHash(obj);
    }
}
exports.hashObj = hashObj;
/**
 * Generates and retuns { publicKey, secretKey } as hex strings
 */
function generateKeypair() {
    const publicKey = Buffer.allocUnsafe(sodium.crypto_sign_PUBLICKEYBYTES);
    const secretKey = Buffer.allocUnsafe(sodium.crypto_sign_SECRETKEYBYTES);
    sodium.crypto_sign_keypair(publicKey, secretKey);
    return {
        publicKey: publicKey.toString('hex'),
        secretKey: secretKey.toString('hex')
    };
}
exports.generateKeypair = generateKeypair;
/**
 * Returns a curve sk represented as a hex string when given an sk
 * @param sk
 */
function convertSkToCurve(sk) {
    const skBuf = _ensureBuffer(sk);
    const curveSkBuf = Buffer.allocUnsafe(sodium.crypto_box_SECRETKEYBYTES);
    try {
        sodium.crypto_sign_ed25519_sk_to_curve25519(curveSkBuf, skBuf);
    }
    catch (e) {
        throw new Error('Could not convert given secret key to curve secret key.');
    }
    return curveSkBuf.toString('hex');
}
exports.convertSkToCurve = convertSkToCurve;
/**
 * Returns a curve pk represented as a hex string when given a pk
 * @param pk
 */
function convertPkToCurve(pk) {
    const pkBuf = _ensureBuffer(pk);
    const curvePkBuf = Buffer.allocUnsafe(sodium.crypto_box_PUBLICKEYBYTES);
    try {
        sodium.crypto_sign_ed25519_pk_to_curve25519(curvePkBuf, pkBuf);
    }
    catch (e) {
        throw new Error('Could not convert given public key to curve public key.');
    }
    return curvePkBuf.toString('hex');
}
exports.convertPkToCurve = convertPkToCurve;
/**
 * Returns a payload obtained by encrypting and tagging the message string with a key produced from the given sk and pk
 * @param message
 * @param curveSk
 * @param curvePk
 */
function encrypt(message, curveSk, curvePk) {
    const messageBuf = Buffer.from(message, 'utf8');
    const curveSkBuf = _ensureBuffer(curveSk, 'Secret key');
    const curvePkBuf = _ensureBuffer(curvePk, 'Public key');
    const ciphertext = Buffer.allocUnsafe(messageBuf.length + sodium.crypto_box_MACBYTES);
    const nonce = Buffer.allocUnsafe(sodium.crypto_box_NONCEBYTES);
    sodium.randombytes_buf(nonce);
    sodium.crypto_box_easy(ciphertext, messageBuf, nonce, curvePkBuf, curveSkBuf);
    const payload = [ciphertext.toString('hex'), nonce.toString('hex')];
    return JSON.stringify(payload);
}
exports.encrypt = encrypt;
/**
 * Returns the message string obtained by decrypting the payload with the given sk and pk and authenticating the attached tag
 * @param payload
 * @param curveSk
 * @param curvePk
 */
function decrypt(payload, curveSk, curvePk) {
    payload = JSON.parse(payload);
    const ciphertext = _ensureBuffer(payload[0], 'Tag ciphertext');
    const nonce = _ensureBuffer(payload[1], 'Tag nonce');
    const secretKey = _ensureBuffer(curveSk, 'Secret key');
    const publicKey = _ensureBuffer(curvePk, 'Public key');
    const message = Buffer.allocUnsafe(ciphertext.length - sodium.crypto_box_MACBYTES);
    const isValid = sodium.crypto_box_open_easy(message, ciphertext, nonce, publicKey, secretKey);
    return { isValid, message: message.toString('utf8') };
}
exports.decrypt = decrypt;
/**
 * Returns an authentication tag obtained by encrypting the hash of the message string with a key produced from the given sk and pk
 * @param message
 * @param sharedKey
 */
function tag(message, sharedKey) {
    const messageBuf = Buffer.from(message, 'utf8');
    const nonceBuf = Buffer.allocUnsafe(sodium.crypto_auth_BYTES);
    sodium.randombytes_buf(nonceBuf);
    const nonce = nonceBuf.toString('hex');
    const keyBuf = _getAuthKey(sharedKey, nonce);
    const tagBuf = Buffer.allocUnsafe(sodium.crypto_auth_BYTES);
    sodium.crypto_auth(tagBuf, messageBuf, keyBuf);
    const tag = tagBuf.toString('hex');
    return tag + nonce;
}
exports.tag = tag;
/**
 * Attaches a tag field to the input object, containg an authentication tag for the obj
 * @param obj
 * @param sharedKey
 */
function tagObj(obj, sharedKey) {
    if (typeof obj !== 'object') {
        throw new TypeError('Input must be an object.');
    }
    // If it's an array, we don't want to try to sign it
    if (Array.isArray(obj)) {
        throw new TypeError('Input cannot be an array.');
    }
    if (typeof sharedKey !== 'string' && !Buffer.isBuffer(sharedKey)) {
        throw new TypeError('Shared key must be a hex string or hex buffer.');
    }
    const objStr = stringify(obj);
    obj.tag = tag(objStr, sharedKey);
}
exports.tagObj = tagObj;
/**
 * Returns true if tag is a valid authentication tag for message string
 * @param message
 * @param tag
 * @param sharedKey
 */
function authenticate(message, tag, sharedKey) {
    const nonce = tag.substring(sodium.crypto_auth_BYTES * 2);
    tag = tag.substring(0, sodium.crypto_auth_BYTES * 2);
    const tagBuf = _ensureBuffer(tag, 'Tag');
    const keyBuf = _getAuthKey(sharedKey, nonce);
    const messageBuf = Buffer.from(message, 'utf8');
    return sodium.crypto_auth_verify(tagBuf, messageBuf, keyBuf);
}
exports.authenticate = authenticate;
/**
 * Returns true if the authentication tag is a valid tag for the object minus the tag field
 * @param obj
 * @param sharedKey
 */
function authenticateObj(obj, sharedKey) {
    if (typeof obj !== 'object') {
        throw new TypeError('Input must be an object.');
    }
    if (!obj.tag) {
        throw new Error('Object must contain a tag field');
    }
    const tag = obj.tag;
    delete obj.tag;
    const objStr = stringify(obj);
    obj.tag = tag;
    return authenticate(objStr, tag, sharedKey);
}
exports.authenticateObj = authenticateObj;
/**
 * Returns a signature obtained by signing the input hash (hex string or buffer) with the sk string
 * @param input
 * @param sk
 */
function sign(input, sk) {
    let inputBuf;
    let skBuf;
    if (typeof input !== 'string') {
        if (Buffer.isBuffer(input)) {
            inputBuf = input;
        }
        else {
            throw new TypeError('Input must be a hex string or buffer.');
        }
    }
    else {
        try {
            inputBuf = Buffer.from(input, 'hex');
        }
        catch (e) {
            throw new TypeError('Input string must be in hex format.');
        }
    }
    if (typeof sk !== 'string') {
        if (Buffer.isBuffer(sk)) {
            skBuf = sk;
        }
        else {
            throw new TypeError('Secret key must be a hex string or buffer.');
        }
    }
    else {
        try {
            skBuf = Buffer.from(sk, 'hex');
        }
        catch (e) {
            throw new TypeError('Secret key string must be in hex format');
        }
    }
    const sig = Buffer.allocUnsafe(inputBuf.length + sodium.crypto_sign_BYTES);
    try {
        sodium.crypto_sign(sig, inputBuf, skBuf);
    }
    catch (e) {
        throw new Error('Failed to sign input with provided secret key.');
    }
    return sig.toString('hex');
}
exports.sign = sign;
/**
 * Attaches a sign field to the input object, containing a signed version of the hash of the object,
 * along with the public key of the signer
 * @param obj
 * @param sk
 * @param pk
 */
function signObj(obj, sk, pk) {
    if (typeof obj !== 'object') {
        throw new TypeError('Input must be an object.');
    }
    // If it's an array, we don't want to try to sign it
    if (obj.length !== undefined) {
        throw new TypeError('Input cannot be an array.');
    }
    if (typeof sk !== 'string') {
        throw new TypeError('Secret key must be a string.');
    }
    if (typeof pk !== 'string') {
        throw new TypeError('Public key must be a string.');
    }
    const objStr = stringify(obj);
    const hashed = hash(objStr, 'buffer');
    const sig = sign(hashed, sk);
    obj.sign = { owner: pk, sig };
}
exports.signObj = signObj;
/**
 * Returns true if the hash of the input was signed by the owner of the pk
 * @param msg
 * @param sig
 * @param pk
 */
function verify(msg, sig, pk) {
    if (typeof msg !== 'string') {
        throw new TypeError('Message to compare must be a string.');
    }
    let sigBuf;
    if (typeof sig !== 'string') {
        if (Buffer.isBuffer(sig)) {
            sigBuf = sig;
        }
        else {
            throw new TypeError('Signature must be a hex string.');
        }
    }
    else {
        try {
            sigBuf = Buffer.from(sig, 'hex');
        }
        catch (e) {
            throw new TypeError('Signature must be a hex string.');
        }
    }
    if (typeof pk !== 'string') {
        throw new TypeError('Public key must be a hex string.');
    }
    let pkBuf;
    try {
        pkBuf = Buffer.from(pk, 'hex');
    }
    catch (e) {
        throw new TypeError('Public key must be a hex string.');
    }
    try {
        const opened = Buffer.allocUnsafe(sigBuf.length - sodium.crypto_sign_BYTES);
        sodium.crypto_sign_open(opened, sigBuf, pkBuf);
        const verified = opened.toString('hex');
        return verified === msg;
    }
    catch (e) {
        throw new Error('Unable to verify provided signature with provided public key.');
    }
}
exports.verify = verify;
/**
 * Returns true if the hash of the object minus the sign field matches the signed message in the sign field
 * @param obj
 */
function verifyObj(obj) {
    if (typeof obj !== 'object') {
        throw new TypeError('Input must be an object.');
    }
    if (!obj.sign || !obj.sign.owner || !obj.sign.sig) {
        throw new Error('Object must contain a sign field with the following data: { owner, sig }');
    }
    if (typeof obj.sign.owner !== 'string') {
        throw new TypeError('Owner must be a public key represented as a hex string.');
    }
    if (typeof obj.sign.sig !== 'string') {
        throw new TypeError('Signature must be a valid signature represented as a hex string.');
    }
    const objHash = hashObj(obj, true);
    return verify(objHash, obj.sign.sig, obj.sign.owner);
}
exports.verifyObj = verifyObj;
/**
 * This function initialized the cryptographic hashing functions
 * @param key The HASH_KEY for initializing the cryptographic hashing functions
 */
function init(key) {
    if (!key) {
        throw new Error('Hash key must be passed to module constructor.');
    }
    try {
        HASH_KEY = Buffer.from(key, 'hex');
        if (HASH_KEY.length !== 32) {
            throw new TypeError();
        }
    }
    catch (e) {
        throw new TypeError('Hash key must be a 32-byte string.');
    }
}
exports.init = init;
/**
 * Ensures that the input data given is in the form of a buffer, or converted to one if not
 * @param input The input data to be checked for or converted to a buffer
 * @param name The name given to the data to be ensured
 */
function _ensureBuffer(input, name = 'Input') {
    if (typeof input !== 'string') {
        if (Buffer.isBuffer(input)) {
            return input;
        }
        else {
            throw new TypeError(`${name} must be a hex string or buffer.`);
        }
    }
    else {
        try {
            return Buffer.from(input, 'hex');
        }
        catch (e) {
            throw new TypeError(`${name} string must be in hex format.`);
        }
    }
}
exports._ensureBuffer = _ensureBuffer;
/**
 *
 * @param curveSk
 * @param curvePk
 */
function generateSharedKey(curveSk, curvePk) {
    const curveSkBuf = _ensureBuffer(curveSk);
    const curvePkBuf = _ensureBuffer(curvePk);
    const keyBuf = Buffer.allocUnsafe(sodium.crypto_scalarmult_BYTES);
    sodium.crypto_scalarmult(keyBuf, curveSkBuf, curvePkBuf);
    return keyBuf;
}
exports.generateSharedKey = generateSharedKey;
/**
 * Returns the auth key for the provided sharedKey
 * @param sharedKey
 * @param nonce
 */
function _getAuthKey(sharedKey, nonce) {
    const sharedKeyBuf = _ensureBuffer(sharedKey);
    const nonceBuf = _ensureBuffer(nonce);
    const resultBuf = xor(sharedKeyBuf, nonceBuf);
    return resultBuf;
}
exports._getAuthKey = _getAuthKey;
//# sourceMappingURL=index.js.map