# bitcoinjs-message

## Examples (Note about Electrum support at the bottom)

``` javascript
var bitcoin = require('bitcoinjs-lib') // v4.x.x
var bitcoinMessage = require('@runonflux/bitcoinjs-message')
```

> sign(message, privateKey, compressed[, network.messagePrefix, sigOptions])
> - If you pass the sigOptions arg instead of messagePrefix it will dynamically replace.
> - sigOptions contains two attributes
>   - `segwitType` should be one of `'p2sh(p2wpkh)'` or `'p2wpkh'`
>   - `extraEntropy` will be used to create non-deterministic signatures using the RFC6979 extra entropy parameter. R value reuse is not an issue.

Sign a Bitcoin message
``` javascript
var keyPair = bitcoin.ECPair.fromWIF('L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1')
var privateKey = keyPair.privateKey
var message = 'This is an example of a signed message.'

var signature = bitcoinMessage.sign(message, privateKey, keyPair.compressed)
console.log(signature.toString('base64'))
// => 'H9L5yLFjti0QTHhPyFrZCT1V/MMnBtXKmoiKDZ78NDBjERki6ZTQZdSMCtkgoNmp17By9ItJr8o7ChX0XxY91nk='
```

To produce non-deterministic signatures you can pass an extra option to sign()
``` javascript
var { randomBytes } = require('crypto')
var keyPair = bitcoin.ECPair.fromWIF('L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1')
var privateKey = keyPair.privateKey
var message = 'This is an example of a signed message.'

var signature = bitcoinMessage.sign(message, privateKey, keyPair.compressed, { extraEntropy: randomBytes(32) })
console.log(signature.toString('base64'))
// => different (but valid) signature each time
```

Sign a Bitcoin message (with segwit addresses)
``` javascript
// P2SH(P2WPKH) address 'p2sh(p2wpkh)'
var signature = bitcoinMessage.sign(message, privateKey, keyPair.compressed, { segwitType: 'p2sh(p2wpkh)' })
console.log(signature.toString('base64'))
// => 'I9L5yLFjti0QTHhPyFrZCT1V/MMnBtXKmoiKDZ78NDBjERki6ZTQZdSMCtkgoNmp17By9ItJr8o7ChX0XxY91nk='

// P2WPKH address 'p2wpkh'
var signature = bitcoinMessage.sign(message, privateKey, keyPair.compressed, { segwitType: 'p2wpkh' })
console.log(signature.toString('base64'))
// => 'J9L5yLFjti0QTHhPyFrZCT1V/MMnBtXKmoiKDZ78NDBjERki6ZTQZdSMCtkgoNmp17By9ItJr8o7ChX0XxY91nk='
```

Sign a Bitcoin message using a Signer interface.
``` javascript
var keyPair = bitcoin.ECPair.fromWIF('L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1')
var privateKey = keyPair.privateKey
var message = 'This is an example of a signed message.'

var secp256k1 = require('secp256k1')
// Notice we are using the privateKey var from the outer scope inside the sign function.
var signer = { sign: (hash, extraData) => secp256k1.sign(hash, privateKey, { data: extraData }) }

var signature = bitcoinMessage.sign(message, signer, keyPair.compressed)
console.log(signature.toString('base64'))
// => 'H9L5yLFjti0QTHhPyFrZCT1V/MMnBtXKmoiKDZ78NDBjERki6ZTQZdSMCtkgoNmp17By9ItJr8o7ChX0XxY91nk='
```

> signAsync(message, privateKey, compressed[, network.messagePrefix, sigOptions])
> Same as sign, except returns a promise, and can accept a SignerAsync interface instead of privateKey

Sign a Bitcoin message asynchronously
``` javascript
var keyPair = bitcoin.ECPair.fromWIF('L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1')
var privateKey = keyPair.privateKey
var message = 'This is an example of a signed message.'

bitcoinMessage.signAsync(message, privateKey, keyPair.compressed).then(signature => {
  console.log(signature.toString('base64'))
})
// => 'H9L5yLFjti0QTHhPyFrZCT1V/MMnBtXKmoiKDZ78NDBjERki6ZTQZdSMCtkgoNmp17By9ItJr8o7ChX0XxY91nk='
```

Sign a Bitcoin message asynchronously using SignerAsync interface
``` javascript
var keyPair = bitcoin.ECPair.fromWIF('L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1')
var privateKey = keyPair.privateKey
var message = 'This is an example of a signed message.'

var secp256k1 = require('secp256k1')
// Note that a Signer will also work
var signerAsync = { sign: (hash, extraData) => Promise.resolve(secp256k1.sign(hash, privateKey, { data: extraData })) }
var signer = { sign: (hash, extraData) => secp256k1.sign(hash, privateKey, { data: extraData }) }

bitcoinMessage.signAsync(message, signerAsync, keyPair.compressed).then(signature => {
  console.log(signature.toString('base64'))
})
// => 'H9L5yLFjti0QTHhPyFrZCT1V/MMnBtXKmoiKDZ78NDBjERki6ZTQZdSMCtkgoNmp17By9ItJr8o7ChX0XxY91nk='
bitcoinMessage.signAsync(message, signer, keyPair.compressed).then(signature => {
  console.log(signature.toString('base64'))
})
// => 'H9L5yLFjti0QTHhPyFrZCT1V/MMnBtXKmoiKDZ78NDBjERki6ZTQZdSMCtkgoNmp17By9ItJr8o7ChX0XxY91nk='
```

> verify(message, address, signature[, network.messagePrefix, checkSegwitAlways, pubKeyHash, scriptHash])

Verify a Bitcoin message
``` javascript
var address = '1F3sAm6ZtwLAUnj7d38pGFxtP3RVEvtsbV'

console.log(bitcoinMessage.verify(message, address, signature))
// => true

// Bind the address version to the network and to the signature type
// (recommended whenever the network is known):
console.log(bitcoinMessage.verify(message, address, signature, null, false, '00', '05'))
// => true
```

`pubKeyHash` / `scriptHash` are the hex P2PKH / P2SH version prefixes of the
address's network (e.g. `'00'`/`'05'` for Bitcoin, `'1cb8'`/`'1cbd'` for Flux).
When `pubKeyHash` is given, a legacy (P2PKH) signature only verifies against an
address with exactly that prefix, and a P2SH-P2WPKH signature never verifies
against it; `scriptHash` binds P2SH-P2WPKH signatures the same way. Without
them the version prefix is assumed to be one byte and is not checked (legacy
behaviour). P2WPKH signatures only match version-0, 20-byte witness programs.

## About Electrum segwit signature support

- For Signing: Use the non-segwit compressed signing parameters for both segwit types (p2sh-p2wpkh and p2wpkh)
- For Verifying: Pass the checkSegwitAlways argument as true. (messagePrefix should be set to null to default to Bitcoin messagePrefix)

## LICENSE [MIT](LICENSE)
