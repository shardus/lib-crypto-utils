/// <reference types="node" />
declare type hexstring = string;
declare type publicKey = hexstring;
declare type secretKey = hexstring;
declare type curvePublicKey = hexstring;
declare type curveSecretKey = hexstring;
declare type sharedKey = hexstring;
interface Keypair {
    publicKey: publicKey;
    secretKey: secretKey;
}
interface Signature {
    owner: publicKey;
    sig: hexstring;
}
interface LooseObject {
    [index: string]: any;
}
interface TaggedObject extends LooseObject {
    tag: hexstring;
}
interface SignedObject extends LooseObject {
    sign: Signature;
}
/**
 * Returns 32-bytes random hex string, otherwise the number of bytes can be specified as an integer
 * @param bytes
 */
export declare function randomBytes(bytes?: number): hexstring;
/**
 * Returns the Blake2b hash of the input string or Buffer, default output type is hex
 * @param input
 * @param fmt
 */
export declare function hash(input: string, fmt?: string): hexstring;
/**
 * Returns the hash of the provided object as a hex string, takes an optional second parameter to hash an object with the "sign" field
 * @param obj
 * @param removeSign
 * @param removeTag
 */
export declare function hashObj(obj: SignedObject, removeSign?: boolean, removeTag?: boolean): hexstring;
/**
 * Generates and retuns { publicKey, secretKey } as hex strings
 */
export declare function generateKeypair(): Keypair;
/**
 * Returns a curve sk represented as a hex string when given an sk
 * @param sk
 */
export declare function convertSkToCurve(sk: secretKey): curveSecretKey;
/**
 * Returns a curve pk represented as a hex string when given a pk
 * @param pk
 */
export declare function convertPkToCurve(pk: publicKey): curvePublicKey;
/**
 * Returns a payload obtained by encrypting and tagging the message string with a key produced from the given sk and pk
 * @param message
 * @param curveSk
 * @param curvePk
 */
export declare function encrypt(message: string, curveSk: curveSecretKey, curvePk: curvePublicKey): string;
/**
 * Returns the message string obtained by decrypting the payload with the given sk and pk and authenticating the attached tag
 * @param payload
 * @param curveSk
 * @param curvePk
 */
export declare function decrypt(payload: any, curveSk: curveSecretKey, curvePk: curvePublicKey): {
    isValid: any;
    message: string;
};
/**
 * Returns an authentication tag obtained by encrypting the hash of the message string with a key produced from the given sk and pk
 * @param message
 * @param sharedKey
 */
export declare function tag(message: string, sharedKey: sharedKey): string;
/**
 * Attaches a tag field to the input object, containg an authentication tag for the obj
 * @param obj
 * @param sharedKey
 */
export declare function tagObj(obj: TaggedObject, sharedKey: sharedKey): void;
/**
 * Returns true if tag is a valid authentication tag for message string
 * @param message
 * @param tag
 * @param sharedKey
 */
export declare function authenticate(message: string, tag: string, sharedKey: sharedKey): boolean;
/**
 * Returns true if the authentication tag is a valid tag for the object minus the tag field
 * @param obj
 * @param sharedKey
 */
export declare function authenticateObj(obj: TaggedObject, sharedKey: sharedKey): boolean;
/**
 * Returns a signature obtained by signing the input hash (hex string or buffer) with the sk string
 * @param input
 * @param sk
 */
export declare function sign(input: hexstring | Buffer, sk: secretKey): string;
/**
 * Attaches a sign field to the input object, containing a signed version of the hash of the object,
 * along with the public key of the signer
 * @param obj
 * @param sk
 * @param pk
 */
export declare function signObj(obj: SignedObject, sk: secretKey, pk: publicKey): void;
/**
 * Returns true if the hash of the input was signed by the owner of the pk
 * @param msg
 * @param sig
 * @param pk
 */
export declare function verify(msg: string, sig: hexstring, pk: publicKey): boolean;
/**
 * Returns true if the hash of the object minus the sign field matches the signed message in the sign field
 * @param obj
 */
export declare function verifyObj(obj: SignedObject): boolean;
/**
 * This function initialized the cryptographic hashing functions
 * @param key The HASH_KEY for initializing the cryptographic hashing functions
 */
export declare function init(key: hexstring): void;
/**
 * Ensures that the input data given is in the form of a buffer, or converted to one if not
 * @param input The input data to be checked for or converted to a buffer
 * @param name The name given to the data to be ensured
 */
export declare function _ensureBuffer(input: string | Buffer, name?: string): Buffer;
/**
 *
 * @param curveSk
 * @param curvePk
 */
export declare function generateSharedKey(curveSk: curveSecretKey, curvePk: curvePublicKey): Buffer;
/**
 * Returns the auth key for the provided sharedKey
 * @param sharedKey
 * @param nonce
 */
export declare function _getAuthKey(sharedKey: sharedKey, nonce: string | Buffer): Buffer;
export {};
