const crypto = require('../index.js')

const nonce = crypto.randomBytes()
crypto(nonce, { threads: 1 })

const NUM = 50000

function signVerifyTest () {
  const { publicKey: pk, secretKey: sk } = crypto.generateKeypair()

  const objs = new Array(NUM).fill().map(() => { return { a: 1, b: 2 } })

  console.log(`Signing ${NUM} objs...`)
  return Promise.all(objs.map(obj => crypto.signObj(obj, sk, pk)))
    .then(() => {
      console.log('Signing done.')
      console.log(objs[objs.length - 1])
      console.log(`Verifying ${NUM} objs...`)
      return Promise.all(objs.map(obj => crypto.verifyObj(obj)))
    })
    .then(results => {
      console.log('Verifying done.')
      console.log(results[results.length - 1])
    })
}

function tagAuthenticateTest () {
  const bob = {}
  ;({ publicKey: bob.pk, secretKey: bob.sk } = crypto.generateKeypair())
  bob.curvePk = crypto.convertPkToCurve(bob.pk)
  bob.curveSk = crypto.convertSkToCurve(bob.sk)

  const alice = {}
  ;({ publicKey: alice.pk, secretKey: alice.sk } = crypto.generateKeypair())
  alice.curvePk = crypto.convertPkToCurve(alice.pk)
  alice.curveSk = crypto.convertSkToCurve(alice.sk)

  const objs = new Array(NUM).fill().map(() => { return { a: 1, b: 2 } })

  console.log(`Tagging ${NUM} objs...`)
  return Promise.all(objs.map(obj => crypto.tagObj(obj, bob.curveSk, alice.curvePk)))
    .then(() => {
      console.log('Tagging done.')
      console.log(objs[objs.length - 1])
      console.log(`Authenticating ${NUM} objs...`)
      return Promise.all(objs.map(obj => crypto.authenticateObj(obj, alice.curveSk, bob.curvePk)))
    })
    .then((results) => {
      console.log('Authenticating done.')
      console.log(results[results.length - 1])
    })
}

function main () {
  signVerifyTest()
    .then(() => tagAuthenticateTest())
    .then(() => {
      crypto.cleanup()
      process.exit()
    })

  let n = 1
  setInterval(() => doUnrelatedThing(n++), 1000)
}
main()

function doUnrelatedThing (n) {
  console.log(`Did unrelated thing ${n}`)
}
