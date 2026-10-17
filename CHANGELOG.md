# 2.4.0
Minor release, not a patch: `verify` is stricter, so some inputs that 2.3.x
accepted are now rejected (see __changed__).

__security__ (SSP security review 2026-10, UTXO-9 / DEP-11)
- `verify` takes optional `pubKeyHash` and `scriptHash` hex version prefixes and
  enforces them: a legacy (P2PKH) signature no longer verifies against a P2SH or
  other-network address carrying the same hash160, and a P2SH-P2WPKH signature
  no longer verifies against a P2PKH-version address. Without the prefixes the
  version prefix is still assumed to be one byte and is not checked.
- Raised the `secp256k1` floor to `^3.8.1` (CVE-2024-48930). The lockfile is
  refreshed to match (secp256k1 3.8.1 and its patched transitive dependencies).

__changed__ (behaviour, applies even without the new arguments)
- P2WPKH signatures only match version-0, 20-byte bech32 witness programs.
- Base58 addresses whose payload is not exactly a 20-byte hash never verify.
- Invalid `pubKeyHash`/`scriptHash` arguments throw.

# 2.2.0
__added__
- Signer and SignerAsync interfaces
- sign functions can accept Signer | SignerAsync interfaces in place of privateKey
- Added an async signAsync function (needed if you use SignerAsync interface) that returns a promise.

# 2.1.4
__fixed__
- Fixed TypeScript types

# 2.1.3
__added__
- TypeScript types

# 2.1.2
__added__
- Support for Segwit signatures compatible with Electrum. (See README)

# 2.1.1
__fixed__
- Fix UTF8 handling of message.

# 2.1.0
__added__
- Segwit support for P2WPKH and P2SH-P2WPKH addresses. This is based on Trezor implementation.

# 2.0.0
__breaking__
- `messagePrefix` is now the last parameter for the `sign`, `verify` and `magicHash` functions
- `messagePrefix` is now defaulted to the Bitcoin network message prefix
