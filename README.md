# cool-wallet-address-finder

A Zig program to generate EVM wallet addresses with custom hex patterns by brute-forcing private keys.

## Features

- Generates random valid secp256k1 private keys
- Derives Ethereum addresses from private keys
- Searches for addresses matching a specific hex pattern
- Multi-threaded for fast parallel searching
- Shows progress, generation rate, and estimated time remaining

## Prerequisites

This program requires `libsecp256k1` to be installed on your system since I failed to write it in Zig and rolled back to using C bindings.

### Installing libsecp256k1

**macOS (Homebrew):**
```bash
brew install secp256k1
```

**Linux (Ubuntu/Debian):**
```bash
sudo apt-get install libsecp256k1-dev
```

**Linux (Fedora/RHEL):**
```bash
sudo dnf install secp256k1-devel
```

**From source:**
```bash
git clone https://github.com/bitcoin-core/secp256k1.git
cd secp256k1
./autogen.sh
./configure
make
sudo make install
```

**Note:** If you install from source or use a non-standard location, you may need to update the include and library paths in `build.zig`.

## Important Note

**Ethereum addresses are hexadecimal** (characters 0-9 and a-f). The pattern "jadi" contains 'j' which is not a valid hex character, so searching for addresses starting with "jadi" will never find a match.

The program will automatically convert non-hex characters to hex equivalents (e.g., 'j' → 'a', 'i' → '1') with a warning, but for best results, use valid hex patterns like:
- `dead`
- `beef`
- `cafe`
- `4ad1` (if you map j→4 & i→1 it's Jadi)

## Building

```bash
zig build
```

Or build and run in one step:

```bash
zig build run -- <pattern> [num_threads]
# Example: zig build run -- dead 8
```

## Running

```bash
./zig-out/bin/cool-wallet-address-finder <pattern> [num_threads]
```

### Examples:

```bash
# Search for address starting with '04ad10' using all available CPUs
./zig-out/bin/cool-wallet-address-finder 04ad10

# Search for address starting with 'dead' using 8 CPU cores
./zig-out/bin/cool-wallet-address-finder dead 8

# Search for address starting with 'cafe' using 4 CPU cores
./zig-out/bin/cool-wallet-address-finder cafe 4
```

### Arguments:

- `pattern` (required): The hex pattern to search for in wallet addresses (e.g., '04ad10', 'dead', 'cafe')
- `num_threads` (optional): Number of CPU cores to use. If omitted or set to 0, all available CPUs will be used.

## How It Works

1. Generates random 32-byte private keys that are valid for secp256k1 (less than curve order)
2. Derives public key from private key using libsecp256k1
3. Computes Ethereum address using Keccak-256 hash of the public key
4. Checks if address matches the target pattern
5. Repeats until a match is found

## Output

When a matching address is found, the program outputs:
- **Address**: The Ethereum address in hex format (0x...)
- **Private Key**: The private key in hex format (can be imported into MetaMask or other wallets)
- **Public Key**: The uncompressed public key in hex format

## Security Note

This implementation uses the production-grade `libsecp256k1` library for cryptographic operations. The generated private keys are cryptographically secure random values that are validated to be within the secp256k1 curve order.

**Important:** Keep your private keys secure. Anyone with access to a private key has full control over the associated wallet.

## Restarting and Stopping

You can safely stop the program and start it again at any time — there is no harm or risk of loss, as the search process is random and stateless. Each run is independent and does not build on previous progress.

## About Progress Estimation

The progress percentage displayed is only a general statistical estimate and does not guarantee results. It is possible to exceed 100% progress before finding a match, or to find a valid address on the very first attempt — the process is probabilistic, not deterministic.
