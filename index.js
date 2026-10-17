const bs58check = require('bs58check')
const bech32 = require('bech32')
const bufferEquals = require('buffer-equals')
const createHash = require('create-hash')
const secp256k1 = require('secp256k1')
const varuint = require('varuint-bitcoin')

const SEGWIT_TYPES = {
  P2WPKH: 'p2wpkh',
  P2SH_P2WPKH: 'p2sh(p2wpkh)'
}

function sha256 (b) {
  return createHash('sha256')
    .update(b)
    .digest()
}
function hash256 (buffer) {
  return sha256(sha256(buffer))
}
function hash160 (buffer) {
  return createHash('ripemd160')
    .update(sha256(buffer))
    .digest()
}

function encodeSignature (signature, recovery, compressed, segwitType) {
  if (segwitType !== undefined) {
    recovery += 8
    if (segwitType === SEGWIT_TYPES.P2WPKH) recovery += 4
  } else {
    if (compressed) recovery += 4
  }
  return Buffer.concat([Buffer.alloc(1, recovery + 27), signature])
}

function decodeSignature (buffer) {
  if (buffer.length !== 65) throw new Error('Invalid signature length')

  const flagByte = buffer.readUInt8(0) - 27
  if (flagByte > 15 || flagByte < 0) {
    throw new Error('Invalid signature parameter')
  }

  return {
    compressed: !!(flagByte & 12),
    segwitType: !(flagByte & 8)
      ? null
      : !(flagByte & 4)
        ? SEGWIT_TYPES.P2SH_P2WPKH
        : SEGWIT_TYPES.P2WPKH,
    recovery: flagByte & 3,
    signature: buffer.slice(1)
  }
}

function magicHash (message, messagePrefix) {
  messagePrefix = messagePrefix || '\u0018Bitcoin Signed Message:\n'
  if (!Buffer.isBuffer(messagePrefix)) {
    messagePrefix = Buffer.from(messagePrefix, 'utf8')
  }
  if (!Buffer.isBuffer(message)) {
    message = Buffer.from(message, 'utf8')
  }
  const messageVISize = varuint.encodingLength(message.length)
  const buffer = Buffer.allocUnsafe(
    messagePrefix.length + messageVISize + message.length
  )
  messagePrefix.copy(buffer, 0)
  varuint.encode(message.length, buffer, messagePrefix.length)
  message.copy(buffer, messagePrefix.length + messageVISize)
  return hash256(buffer)
}

function prepareSign (
  messagePrefixArg,
  sigOptions
) {
  if (typeof messagePrefixArg === 'object' && sigOptions === undefined) {
    sigOptions = messagePrefixArg
    messagePrefixArg = undefined
  }
  let { segwitType, extraEntropy } = sigOptions || {}
  if (
    segwitType &&
    (typeof segwitType === 'string' || segwitType instanceof String)
  ) {
    segwitType = segwitType.toLowerCase()
  }
  if (
    segwitType &&
    segwitType !== SEGWIT_TYPES.P2SH_P2WPKH &&
    segwitType !== SEGWIT_TYPES.P2WPKH
  ) {
    throw new Error(
      'Unrecognized segwitType: use "' +
        SEGWIT_TYPES.P2SH_P2WPKH +
        '" or "' +
        SEGWIT_TYPES.P2WPKH +
        '"'
    )
  }

  return {
    messagePrefixArg,
    segwitType,
    extraEntropy
  }
}

function isSigner (obj) {
  return obj && typeof obj.sign === 'function'
}

function sign (
  message,
  privateKey,
  compressed,
  messagePrefix,
  sigOptions
) {
  const {
    messagePrefixArg,
    segwitType,
    extraEntropy
  } = prepareSign(messagePrefix, sigOptions)
  const hash = magicHash(message, messagePrefixArg)
  const sigObj = isSigner(privateKey)
    ? privateKey.sign(hash, extraEntropy)
    : secp256k1.sign(hash, privateKey, { data: extraEntropy })
  return encodeSignature(
    sigObj.signature,
    sigObj.recovery,
    compressed,
    segwitType
  )
}

function signAsync (
  message,
  privateKey,
  compressed,
  messagePrefix,
  sigOptions
) {
  let messagePrefixArg, segwitType, extraEntropy
  return Promise.resolve().then(() => {
    ({
      messagePrefixArg,
      segwitType,
      extraEntropy
    } = prepareSign(messagePrefix, sigOptions))
    const hash = magicHash(message, messagePrefixArg)
    return isSigner(privateKey)
      ? privateKey.sign(hash, extraEntropy)
      : secp256k1.sign(hash, privateKey, { data: extraEntropy })
  }).then((sigObj) => {
    return encodeSignature(
      sigObj.signature,
      sigObj.recovery,
      compressed,
      segwitType
    )
  })
}

function segwitRedeemHash (publicKeyHash) {
  const redeemScript = Buffer.concat([
    Buffer.from('0014', 'hex'),
    publicKeyHash
  ])
  return hash160(redeemScript)
}

// Decodes a bech32 segwit address into { version, program }.
// Throws if the address is not bech32.
function decodeBech32 (address) {
  const result = bech32.decode(address)
  return {
    version: result.words[0],
    program: Buffer.from(bech32.fromWords(result.words.slice(1)))
  }
}

// A P2WPKH message signature can only correspond to a version-0, 20-byte
// witness program; any other witness version or program length never matches.
function matchesP2wpkh (decoded, publicKeyHash) {
  return decoded.version === 0 &&
    decoded.program.length === 20 &&
    bufferEquals(publicKeyHash, decoded.program)
}

function parseVersionHex (value, name) {
  if (typeof value !== 'string' || !/^([0-9a-fA-F]{2})+$/.test(value)) {
    throw new Error('Invalid ' + name + ': expected an even-length hex string')
  }
  return Buffer.from(value, 'hex')
}

// Decodes a base58check address into { version, hash }, where the version
// prefix is `versionLength` bytes (1 for Bitcoin-like chains, 2 for
// Zcash/Flux). Returns null when the payload is not exactly a 20-byte hash.
// Throws if the address is not valid base58check.
function decodeBase58 (address, versionLength) {
  const decoded = bs58check.decode(address)
  if (decoded.length !== versionLength + 20) return null
  return {
    version: decoded.slice(0, versionLength),
    hash: decoded.slice(versionLength)
  }
}

// verify(message, address, signature, messagePrefix, checkSegwitAlways, pubKeyHash, scriptHash)
//
// pubKeyHash: hex P2PKH version prefix of the address's network (e.g. '00'
//   Bitcoin, '6f' testnet, '1cb8' Flux/Zcash). When given it is enforced: a
//   legacy (P2PKH) signature only verifies against an address carrying exactly
//   this prefix, and a P2SH-P2WPKH signature never verifies against an address
//   carrying it. When omitted, the prefix is assumed to be 1 byte long and its
//   value is not checked (legacy behaviour, kept for backward compatibility):
//   pass it whenever the network is known.
// scriptHash: optional hex P2SH version prefix (e.g. '05' Bitcoin). When given,
//   a P2SH-P2WPKH signature only verifies against an address carrying exactly
//   this prefix, and a legacy signature never verifies against one carrying it.
function verify (message, address, signature, messagePrefix, checkSegwitAlways, pubKeyHash, scriptHash) {
  const pubKeyHashGiven = pubKeyHash !== undefined && pubKeyHash !== null
  const p2pkhVersion = parseVersionHex(pubKeyHashGiven ? pubKeyHash : '00', 'pubKeyHash')
  const p2shVersion = scriptHash !== undefined && scriptHash !== null
    ? parseVersionHex(scriptHash, 'scriptHash')
    : null
  if (p2shVersion && pubKeyHashGiven) {
    if (p2shVersion.length !== p2pkhVersion.length) {
      throw new Error('pubKeyHash and scriptHash must have the same length')
    }
    if (p2shVersion.equals(p2pkhVersion)) {
      throw new Error('pubKeyHash and scriptHash must differ')
    }
  }
  const versionLength = pubKeyHashGiven || !p2shVersion
    ? p2pkhVersion.length
    : p2shVersion.length

  // is this base58 version prefix acceptable for a legacy (P2PKH) signature?
  function isP2pkhVersion (version) {
    if (pubKeyHashGiven && !version.equals(p2pkhVersion)) return false
    if (p2shVersion && version.equals(p2shVersion)) return false
    return true
  }
  // is this base58 version prefix acceptable for a P2SH-P2WPKH signature?
  function isP2shVersion (version) {
    if (p2shVersion && !version.equals(p2shVersion)) return false
    if (pubKeyHashGiven && version.equals(p2pkhVersion)) return false
    return true
  }

  if (!Buffer.isBuffer(signature)) signature = Buffer.from(signature, 'base64')

  const parsed = decodeSignature(signature)

  if (checkSegwitAlways && !parsed.compressed) {
    throw new Error('checkSegwitAlways can only be used with a compressed pubkey signature flagbyte')
  }

  const hash = magicHash(message, messagePrefix)
  const publicKey = secp256k1.recover(
    hash,
    parsed.signature,
    parsed.recovery,
    parsed.compressed
  )
  const publicKeyHash = hash160(publicKey)

  if (parsed.segwitType) {
    if (parsed.segwitType === SEGWIT_TYPES.P2SH_P2WPKH) {
      const decoded = decodeBase58(address, versionLength)
      if (!decoded || !isP2shVersion(decoded.version)) return false
      return bufferEquals(segwitRedeemHash(publicKeyHash), decoded.hash)
    }
    // parsed.segwitType === SEGWIT_TYPES.P2WPKH
    // must be true since we only return null, P2SH_P2WPKH, or P2WPKH
    // from the decodeSignature function.
    return matchesP2wpkh(decodeBech32(address), publicKeyHash)
  }

  if (checkSegwitAlways) {
    let segwitAddress = null
    try {
      segwitAddress = decodeBech32(address)
    } catch (e) {
      segwitAddress = null
    }
    // if address is bech32 it is not p2sh
    if (segwitAddress) return matchesP2wpkh(segwitAddress, publicKeyHash)

    const decoded = decodeBase58(address, versionLength)
    if (!decoded) return false
    // base58 can be p2pkh or p2sh-p2wpkh, each bound to its own version prefix
    return (
      (isP2pkhVersion(decoded.version) &&
        bufferEquals(publicKeyHash, decoded.hash)) ||
      (isP2shVersion(decoded.version) &&
        bufferEquals(segwitRedeemHash(publicKeyHash), decoded.hash))
    )
  }

  const decoded = decodeBase58(address, versionLength)
  if (!decoded || !isP2pkhVersion(decoded.version)) return false
  return bufferEquals(publicKeyHash, decoded.hash)
}

module.exports = {
  magicHash: magicHash,
  sign: sign,
  signAsync: signAsync,
  verify: verify
}
