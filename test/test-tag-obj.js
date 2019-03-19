const crypto = require('../index.js')

const nonce = crypto.randomBytes()
crypto(nonce)

const bob = {}
;({ publicKey: bob.pk, secretKey: bob.sk } = crypto.generateKeypair())
bob.curvePk = crypto.convertPkToCurve(bob.pk)
bob.curveSk = crypto.convertSkToCurve(bob.sk)

const alice = {}
;({ publicKey: alice.pk, secretKey: alice.sk } = crypto.generateKeypair())
alice.curvePk = crypto.convertPkToCurve(alice.pk)
alice.curveSk = crypto.convertSkToCurve(alice.sk)

function tryEncrypting () {
  console.log('Bob encrypting object...')
  const obj = { thing1: 1, thing2: 2 }
  crypto.tagObj(obj, bob.curveSk, bob.curvePk, alice.curvePk)
  console.log(obj)
  console.log('Alice decrypting object...')
  console.log(crypto.verifyTag(obj, alice.curveSk))
}

tryEncrypting()
