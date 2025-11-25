# Nice Wallets - Vanity Address Generator

A Zig program to generate cryptocurrency wallets (Ethereum addresses) with custom prefixes or patterns in mnemonics.

## Features

- Generates BIP39 mnemonic phrases (12 words)
- Derives Ethereum addresses from mnemonics
- Searches for addresses matching a specific pattern
- Optionally searches for patterns in mnemonic words themselves
- Shows progress and generation rate

## Important Note

**Ethereum addresses are hexadecimal** (characters 0-9 and a-f). The pattern "jadi" contains 'j' which is not a valid hex character, so searching for addresses starting with "jadi" will never find a match.

### Options:

1. **Search for hex patterns**: Use valid hex patterns like:
   - `dead`
   - `beef`
   - `cafe`
   - `jadi` (if you map j→a, d→d, i→1, etc.)

2. **Search in mnemonics**: Set `SEARCH_IN_MNEMONIC = true` to find mnemonics containing "jadi" in the word list.

## Building

```bash
zig build
```

## Running

```bash
zig build run
```

Or after building:

```bash
./zig-out/bin/nice-wallets
```

## Customization

Edit `src/main.zig` to change:

- `TARGET_PATTERN`: The pattern to search for
- `SEARCH_IN_MNEMONIC`: Set to `true` to search in mnemonic words instead of addresses

## How It Works

1. Generates random 128-bit entropy
2. Converts entropy to 12-word BIP39 mnemonic
3. Derives seed from mnemonic using hash-based derivation
4. Derives private key from seed
5. Derives public key using secp256k1 (simplified implementation)
6. Computes Ethereum address using Keccak-256
7. Checks if address matches the target pattern
8. Repeats until a match is found

## Security Note

This implementation uses simplified cryptographic functions for demonstration. For production use:
- Use a proper secp256k1 library
- Use proper PBKDF2-SHA512 for seed derivation
- Use proper BIP32/BIP44 key derivation
- Validate private keys are within secp256k1 curve order

## Performance

The time to find a matching address depends on:
- Pattern length (each additional character multiplies search time by ~16)
- Pattern complexity
- CPU performance

For a 4-character hex pattern, expect thousands to millions of attempts.

