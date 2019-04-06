const crypto = require('../index.js')

const nonce = crypto.randomBytes()
crypto(nonce, { threads: 'auto' })

const NUM = 50000

function signVerifyTest () {
  const { publicKey: pk, secretKey: sk } = crypto.generateKeypair()

  const objSchema = `{"payload":{"cycleChain":[{"activated":[],"active":1,"counter":0,"desired":100,"duration":15,"joined":["d0ecxc3b25"],"lost":[],"marker":"2a42x73e68","previous":"0000x00000","removed":[],"returned":[],"start":1554480179},{"activated":["2ee7xc0c56"],"active":1,"counter":1,"desired":100,"duration":15,"joined":["0a02x21713","1d58x1492f","4e54x1b96b","6a1ex85230"],"lost":[],"marker":"8c98x20ed5","previous":"2a42x73e68","removed":[],"returned":[],"start":1554480194}],"cycleMarkerCerts":[{"marker":"2a42x73e68","signer":"0000x00000"},{"marker":"8c98x20ed5","sign":{"owner":"d0ecxc3b25","sig":"0338xxa36a4"},"signer":"2ee7xc0c56"}]},"sender":"2ee7xc0c56","sign":{"owner":"d0ecxc3b25","sig":"eb22xxb9ff0"},"tracker":"key_6e0bxe3b83_1554480210313_4"}`
  // const objSchema = `{ "a": 1, "b": 2 }`
  const objs = new Array(NUM).fill().map(() => { return JSON.parse(objSchema) })

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

  alice.sharedKey = crypto.generateSharedKey(alice.curveSk, bob.curvePk)
  bob.sharedKey = crypto.generateSharedKey(bob.curveSk, alice.curvePk)

  const objSchema = `{"payload":{"cycleChain":[{"activated":[],"active":1,"counter":0,"desired":100,"duration":15,"joined":["d0ecxc3b25"],"lost":[],"marker":"2a42x73e68","previous":"0000x00000","removed":[],"returned":[],"start":1554480179},{"activated":["2ee7xc0c56"],"active":1,"counter":1,"desired":100,"duration":15,"joined":["0a02x21713","1d58x1492f","4e54x1b96b","6a1ex85230"],"lost":[],"marker":"8c98x20ed5","previous":"2a42x73e68","removed":[],"returned":[],"start":1554480194}],"cycleMarkerCerts":[{"marker":"2a42x73e68","signer":"0000x00000"},{"marker":"8c98x20ed5","sign":{"owner":"d0ecxc3b25","sig":"0338xxa36a4"},"signer":"2ee7xc0c56"}]},"sender":"2ee7xc0c56","sign":{"owner":"d0ecxc3b25","sig":"eb22xxb9ff0"},"tracker":"key_6e0bxe3b83_1554480210313_4"}`
  const objs = new Array(NUM).fill().map(() => { return JSON.parse(objSchema) })

  console.log(`Tagging ${NUM} objs...`)
  return Promise.all(objs.map(obj => crypto.tagObj(obj, bob.sharedKey)))
    .then(() => {
      console.log('Tagging done.')
      console.log(objs[objs.length - 1])
      console.log(`Authenticating ${NUM} objs...`)
      return Promise.all(objs.map(obj => crypto.authenticateObj(obj, alice.sharedKey)))
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
