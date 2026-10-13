// Regression tests for the 2026-10 security review (UTXO-9): verify() must
// bind the address version prefix / witness version to the signature type
// whenever the caller tells it the network's prefixes.
const test = require('tape').test
const bs58check = require('bs58check')
const bech32 = require('bech32')
const createHash = require('create-hash')
const bitcoin = require('bitcoinjs-lib')
const message = require('../')

function sha256 (b) {
  return createHash('sha256').update(b).digest()
}
function hash160 (buffer) {
  return createHash('ripemd160').update(sha256(buffer)).digest()
}
function segwitRedeemHash (publicKeyHash) {
  return hash160(Buffer.concat([Buffer.from('0014', 'hex'), publicKeyHash]))
}
function base58 (versionHex, hash) {
  return bs58check.encode(Buffer.concat([Buffer.from(versionHex, 'hex'), hash]))
}

const keyPair = bitcoin.ECPair.fromWIF('L3n3e2LggPA5BuhXyBetWGhUfsEBTFe9Y6LhyAhY2mAXkA9jNE56')
const privateKey = keyPair.d.toBuffer(32)
const pkh = hash160(keyPair.getPublicKeyBuffer())
const redeemHash = segwitRedeemHash(pkh)
const msg = 'SSP version binding'

const legacySig = message.sign(msg, privateKey, true)
const p2shP2wpkhSig = message.sign(msg, privateKey, true, { segwitType: 'p2sh(p2wpkh)' })
const p2wpkhSig = message.sign(msg, privateKey, true, { segwitType: 'p2wpkh' })

test('legacy signature: P2PKH address of the stated network verifies', t => {
  t.true(message.verify(msg, base58('00', pkh), legacySig, null, false, '00'))
  t.true(message.verify(msg, base58('6f', pkh), legacySig, null, false, '6f'))
  t.true(message.verify(msg, base58('00', pkh), legacySig, null, false, '00', '05'))
  t.end()
})

test('legacy signature: refused for a P2SH-version address with the same hash160', t => {
  t.false(message.verify(msg, base58('05', pkh), legacySig, null, false, '00'))
  t.false(message.verify(msg, base58('05', pkh), legacySig, null, false, undefined, '05'))
  t.false(message.verify(msg, base58('05', pkh), legacySig, null, false, '00', '05'))
  t.end()
})

test('legacy signature: refused for another network\'s P2PKH version', t => {
  t.false(message.verify(msg, base58('6f', pkh), legacySig, null, false, '00'))
  t.false(message.verify(msg, base58('30', pkh), legacySig, null, false, '00')) // LTC
  t.false(message.verify(msg, base58('00', pkh), legacySig, null, false, '6f'))
  t.end()
})

test('legacy signature: 2-byte (Zcash/Flux) prefixes are bound too', t => {
  t.true(message.verify(msg, base58('1cb8', pkh), legacySig, null, false, '1cb8'))
  t.false(message.verify(msg, base58('1cbd', pkh), legacySig, null, false, '1cb8'))
  t.false(message.verify(msg, base58('1cbd', pkh), legacySig, null, false, undefined, '1cbd'))
  t.true(message.verify(msg, base58('1cbd', redeemHash), p2shP2wpkhSig, null, false, '1cb8', '1cbd'))
  t.false(message.verify(msg, base58('1cb8', redeemHash), p2shP2wpkhSig, null, false, '1cb8', '1cbd'))
  t.end()
})

test('legacy signature without pubKeyHash keeps the backward-compatible behaviour', t => {
  // documented: without a stated network the version byte is not checked
  t.true(message.verify(msg, base58('00', pkh), legacySig))
  t.true(message.verify(msg, base58('05', pkh), legacySig))
  t.end()
})

test('P2SH-P2WPKH signature: bound to the P2SH version', t => {
  t.true(message.verify(msg, base58('05', redeemHash), p2shP2wpkhSig, null, false, '00', '05'))
  t.true(message.verify(msg, base58('05', redeemHash), p2shP2wpkhSig, null, false, '00'))
  // P2PKH version carrying the redeem hash
  t.false(message.verify(msg, base58('00', redeemHash), p2shP2wpkhSig, null, false, '00'))
  t.false(message.verify(msg, base58('00', redeemHash), p2shP2wpkhSig, null, false, undefined, '05'))
  // another network's P2SH version
  t.false(message.verify(msg, base58('c4', redeemHash), p2shP2wpkhSig, null, false, '00', '05'))
  t.end()
})

test('checkSegwitAlways: each base58 form is bound to its own version', t => {
  t.true(message.verify(msg, base58('00', pkh), legacySig, null, true, '00', '05'))
  t.true(message.verify(msg, base58('05', redeemHash), legacySig, null, true, '00', '05'))
  // swapped versions are refused
  t.false(message.verify(msg, base58('05', pkh), legacySig, null, true, '00', '05'))
  t.false(message.verify(msg, base58('00', redeemHash), legacySig, null, true, '00', '05'))
  t.false(message.verify(msg, base58('00', redeemHash), legacySig, null, true, '00'))
  t.end()
})

test('P2WPKH signature: only a version-0, 20-byte witness program matches', t => {
  const v0 = bech32.encode('bc', [0].concat(bech32.toWords(pkh)))
  const v1 = bech32.encode('bc', [1].concat(bech32.toWords(pkh)))
  t.true(message.verify(msg, v0, p2wpkhSig))
  t.false(message.verify(msg, v1, p2wpkhSig))
  // checkSegwitAlways path, same rule
  t.true(message.verify(msg, v0, legacySig, null, true))
  t.false(message.verify(msg, v1, legacySig, null, true))
  t.end()
})

test('wrong payload length never verifies', t => {
  const longer = Buffer.concat([pkh, Buffer.from([0])])
  t.false(message.verify(msg, base58('00', longer), legacySig, null, false, '00'))
  t.false(message.verify(msg, bs58check.encode(Buffer.concat([Buffer.from('00', 'hex'), pkh.slice(0, 19)])), legacySig))
  t.end()
})

test('invalid version parameters throw', t => {
  t.throws(() => message.verify(msg, base58('00', pkh), legacySig, null, false, '0'), /Invalid pubKeyHash/)
  t.throws(() => message.verify(msg, base58('00', pkh), legacySig, null, false, 0), /Invalid pubKeyHash/)
  t.throws(() => message.verify(msg, base58('00', pkh), legacySig, null, false, '00', 'zz'), /Invalid scriptHash/)
  t.throws(() => message.verify(msg, base58('00', pkh), legacySig, null, false, '00', '0505'), /same length/)
  t.throws(() => message.verify(msg, base58('00', pkh), legacySig, null, false, '00', '00'), /must differ/)
  t.end()
})
