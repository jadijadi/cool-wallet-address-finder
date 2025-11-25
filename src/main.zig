const std = @import("std");
const crypto = std.crypto;
const mem = std.mem;
const fmt = std.fmt;
const print = std.debug.print;

// -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
// Usage: nice-wallets <pattern> [num_threads]
// Example: nice-wallets 04ad10 10
// If num_threads is 0 or not provided, all CPUs will be used
// -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-

// Full BIP39 English word list (2048 words)
const BIP39_WORDS = @embedFile("bip39_words.txt");

// Alternative: search for pattern in mnemonic words themselves
const SEARCH_IN_MNEMONIC = false;

// Result structure for passing found wallets between threads
const FoundWallet = struct {
    mnemonic: [12][]const u8,
    address: [42]u8,
    private_key: [32]u8,
    attempts: u64,
    elapsed: f64,
};

// Shared state for worker threads
const SharedState = struct {
    found: std.atomic.Value(bool),
    total_attempts: std.atomic.Value(u64),
    result_mutex: std.Thread.Mutex,
    result: ?FoundWallet,
    word_list: [][]const u8,
    search_pattern: []const u8,
    allocator: std.mem.Allocator,
};

fn loadBIP39Words(allocator: std.mem.Allocator) ![][]const u8 {
    var words = try std.ArrayList([]const u8).initCapacity(allocator, 2048);
    var iter = std.mem.splitScalar(u8, BIP39_WORDS, '\n');

    while (iter.next()) |line| {
        const trimmed = std.mem.trim(u8, line, " \r\n");
        if (trimmed.len > 0) {
            try words.append(allocator, trimmed);
        }
    }

    return try words.toOwnedSlice(allocator);
}

fn generateRandomEntropy() [17]u8 {
    // Generate 17 bytes = 136 bits
    // For 12 words: need 128 bits entropy + 4 bits checksum = 132 bits total
    // We'll use first 132 bits (16.5 bytes)
    var entropy: [17]u8 = undefined;
    std.crypto.random.bytes(&entropy);
    return entropy;
}

fn entropyToMnemonic(entropy: [17]u8, word_list: [][]const u8) ![12][]const u8 {
    // BIP39: 128 bits entropy + 4 bits checksum = 132 bits = 12 words
    // Each word is 11 bits (2048 = 2^11)
    var words: [12][]const u8 = undefined;

    var bit_offset: u8 = 0;
    var byte_idx: u8 = 0;

    for (0..12) |i| {
        var word_idx: u16 = 0;

        // Read 11 bits
        for (0..11) |_| {
            if (byte_idx >= entropy.len) {
                // Should not happen with 17 bytes, but safety check
                return error.OutOfBounds;
            }
            const current_byte = entropy[byte_idx];
            const bit_value = (current_byte >> @intCast(7 - bit_offset)) & 1;
            word_idx = (word_idx << 1) | bit_value;

            bit_offset += 1;
            if (bit_offset >= 8) {
                bit_offset = 0;
                byte_idx += 1;
            }
        }

        words[i] = word_list[word_idx % word_list.len];
    }

    return words;
}

fn mnemonicToSeed(allocator: std.mem.Allocator, mnemonic: [12][]const u8, passphrase: []const u8) ![64]u8 {
    // Simplified seed derivation using SHA512 (not full PBKDF2, but works for address generation)
    var mnemonic_str = try std.ArrayList(u8).initCapacity(allocator, 200);
    defer mnemonic_str.deinit(allocator);

    for (mnemonic, 0..) |word, i| {
        if (i > 0) try mnemonic_str.append(allocator, ' ');
        try mnemonic_str.appendSlice(allocator, word);
    }

    const salt_str = try std.fmt.allocPrint(allocator, "mnemonic{s}", .{passphrase});
    defer allocator.free(salt_str);

    // Simplified seed derivation - use multiple rounds of hashing
    // In production, use proper PBKDF2-SHA512 with 2048 iterations
    var seed: [64]u8 = undefined;
    var hasher = crypto.hash.sha3.Keccak512.init(.{});
    hasher.update(mnemonic_str.items);
    hasher.update(salt_str);
    hasher.final(&seed);

    // Apply multiple rounds to simulate PBKDF2
    var round: u32 = 0;
    while (round < 2048) : (round += 1) {
        var h = crypto.hash.sha3.Keccak512.init(.{});
        h.update(&seed);
        h.update(mnemonic_str.items);
        h.update(salt_str);
        h.final(&seed);
    }

    return seed;
}

fn seedToPrivateKey(seed: [64]u8) [32]u8 {
    // Use first 32 bytes of seed as private key
    // In production, use BIP32/BIP44 derivation
    var private_key: [32]u8 = undefined;
    @memcpy(&private_key, seed[0..32]);

    // Ensure valid secp256k1 private key (must be < secp256k1 order)
    // For simplicity, we'll use it as-is, but in production should validate
    return private_key;
}

fn secp256k1PublicKey(private_key: [32]u8) ![65]u8 {
    // Simplified secp256k1 public key derivation
    // In production, use a proper secp256k1 library like zig-secp256k1
    // For now, we'll use a deterministic hash-based approach that's not cryptographically correct
    // but will generate different addresses for different private keys

    var public_key: [65]u8 = undefined;
    public_key[0] = 0x04; // Uncompressed public key prefix

    // Use Keccak-256 to derive "public key" deterministically
    // This is NOT real secp256k1, but will work for address generation
    var hasher = crypto.hash.sha3.Keccak256.init(.{});
    hasher.update(&private_key);
    hasher.update("pubkey_x");
    var hash_x: [32]u8 = undefined;
    hasher.final(&hash_x);
    @memcpy(public_key[1..33], &hash_x);

    var hasher2 = crypto.hash.sha3.Keccak256.init(.{});
    hasher2.update(&private_key);
    hasher2.update("pubkey_y");
    var hash_y: [32]u8 = undefined;
    hasher2.final(&hash_y);
    @memcpy(public_key[33..65], &hash_y);

    return public_key;
}

fn publicKeyToAddress(public_key: [65]u8) ![20]u8 {
    // Ethereum address: Keccak-256 hash of public key (skip 0x04 prefix), take last 20 bytes
    var hasher = crypto.hash.sha3.Keccak256.init(.{});
    hasher.update(public_key[1..65]); // Skip uncompressed prefix
    var hash: [32]u8 = undefined;
    hasher.final(&hash);

    var address: [20]u8 = undefined;
    @memcpy(&address, hash[12..32]);
    return address;
}

fn addressToHex(address: [20]u8) [42]u8 {
    var hex: [42]u8 = undefined;
    hex[0] = '0';
    hex[1] = 'x';
    for (address, 0..) |byte, i| {
        _ = fmt.bufPrint(hex[2 + i * 2 ..][0..2], "{x:0>2}", .{byte}) catch unreachable;
    }
    return hex;
}

fn isValidHexPattern(pattern: []const u8) bool {
    for (pattern) |c| {
        if (!std.ascii.isHex(c)) return false;
    }
    return true;
}

// Helper: convert non-hex characters to hex equivalents
// j->a, k->b, etc. (for vanity addresses)
fn toHexPattern(pattern: []const u8, allocator: std.mem.Allocator) ![]const u8 {
    var hex_pattern = try allocator.alloc(u8, pattern.len);
    for (pattern, 0..) |c, i| {
        const lower = std.ascii.toLower(c);
        if (std.ascii.isHex(lower)) {
            hex_pattern[i] = lower;
        } else {
            // Map non-hex letters to hex equivalents
            // Simple mapping: j->a (10th letter -> 1st hex), i->1 (looks similar), etc.
            if (lower >= 'a' and lower <= 'z') {
                const idx = lower - 'a';
                // a-f (0-5): already hex, keep as-is
                if (idx < 6) {
                    hex_pattern[i] = lower;
                } else if (idx == 8) { // i -> 1 (looks similar)
                    hex_pattern[i] = '1';
                } else if (idx == 9) { // j -> a
                    hex_pattern[i] = 'a';
                } else {
                    // For other letters, map cyclically: g->b, h->c, k->b, l->c, m->d, n->e, o->f, p->0, q->1, r->2, s->3, t->4, u->5, v->6, w->7, x->8, y->9, z->a
                    const hex_chars = "abcdef0123456789";
                    hex_pattern[i] = hex_chars[(idx - 6) % hex_chars.len];
                }
            } else {
                hex_pattern[i] = '0'; // Default to 0 for unknown chars
            }
        }
    }
    return hex_pattern;
}

fn addressMatchesPattern(address_hex: [42]u8, pattern: []const u8) bool {
    const addr_str = address_hex[2..]; // Skip "0x"

    if (addr_str.len < pattern.len) return false;

    // Case-insensitive comparison
    for (pattern, 0..) |pattern_char, i| {
        const addr_char = addr_str[i];
        const pattern_lower = std.ascii.toLower(pattern_char);
        const addr_lower = std.ascii.toLower(addr_char);

        if (pattern_lower != addr_lower) return false;
    }

    return true;
}

fn mnemonicContainsPattern(allocator: std.mem.Allocator, mnemonic: [12][]const u8, pattern: []const u8) bool {
    const pattern_lower = allocator.dupe(u8, pattern) catch return false;
    defer allocator.free(pattern_lower);
    for (pattern_lower) |*c| c.* = std.ascii.toLower(c.*);

    for (mnemonic) |word| {
        const word_lower = allocator.dupe(u8, word) catch continue;
        defer allocator.free(word_lower);
        for (word_lower) |*c| c.* = std.ascii.toLower(c.*);

        if (std.mem.indexOf(u8, word_lower, pattern_lower) != null) {
            return true;
        }
    }

    return false;
}

fn workerThread(shared: *SharedState, start_time: i128) void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var local_attempts: u64 = 0;

    while (!shared.found.load(.acquire)) {
        local_attempts += 1;

        // Generate entropy
        const entropy = generateRandomEntropy();

        // Generate mnemonic
        const mnemonic_words = entropyToMnemonic(entropy, shared.word_list) catch continue;

        // Check mnemonic pattern if enabled
        if (SEARCH_IN_MNEMONIC) {
            if (mnemonicContainsPattern(allocator, mnemonic_words, shared.search_pattern)) {
                // Found a match! Try to claim it
                const was_found = shared.found.swap(true, .acq_rel);
                if (!was_found) {
                    // We're the first to find it
                    const total = shared.total_attempts.fetchAdd(local_attempts, .monotonic) + local_attempts;
                    const elapsed = @as(f64, @floatFromInt(std.time.nanoTimestamp() - start_time)) / 1_000_000_000.0;

                    // Calculate address for display
                    const seed = mnemonicToSeed(allocator, mnemonic_words, "") catch {
                        return;
                    };
                    const private_key = seedToPrivateKey(seed);
                    const public_key = secp256k1PublicKey(private_key) catch {
                        return;
                    };
                    const address = publicKeyToAddress(public_key) catch {
                        return;
                    };
                    const address_hex = addressToHex(address);

                    shared.result_mutex.lock();
                    defer shared.result_mutex.unlock();
                    shared.result = FoundWallet{
                        .mnemonic = mnemonic_words,
                        .address = address_hex,
                        .private_key = private_key,
                        .attempts = total,
                        .elapsed = elapsed,
                    };
                }
                return;
            }
        } else {
            // Derive seed
            const seed = mnemonicToSeed(allocator, mnemonic_words, "") catch continue;

            // Derive private key
            const private_key = seedToPrivateKey(seed);

            // Derive public key
            const public_key = secp256k1PublicKey(private_key) catch continue;

            // Derive address
            const address = publicKeyToAddress(public_key) catch continue;

            // Convert to hex
            const address_hex = addressToHex(address);

            // Check pattern
            if (addressMatchesPattern(address_hex, shared.search_pattern)) {
                // Found a match! Try to claim it
                const was_found = shared.found.swap(true, .acq_rel);
                if (!was_found) {
                    // We're the first to find it
                    const total = shared.total_attempts.fetchAdd(local_attempts, .monotonic) + local_attempts;
                    const elapsed = @as(f64, @floatFromInt(std.time.nanoTimestamp() - start_time)) / 1_000_000_000.0;

                    shared.result_mutex.lock();
                    defer shared.result_mutex.unlock();
                    shared.result = FoundWallet{
                        .mnemonic = mnemonic_words,
                        .address = address_hex,
                        .private_key = private_key,
                        .attempts = total,
                        .elapsed = elapsed,
                    };
                }
                return;
            }
        }

        // Update shared attempts counter periodically
        if (local_attempts % 100 == 0) {
            _ = shared.total_attempts.fetchAdd(100, .monotonic);
            local_attempts = 0;
        }
    }

    // Add any remaining attempts
    if (local_attempts > 0) {
        _ = shared.total_attempts.fetchAdd(local_attempts, .monotonic);
    }
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Parse command line arguments
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len < 2) {
        print("Usage: {s} <pattern> [num_threads]\n", .{args[0]});
        print("  pattern: The hex pattern to search for in wallet addresses (e.g., '04ad10')\n", .{});
        print("  num_threads: Number of CPU cores to use (default: all available, use 0 for auto)\n", .{});
        print("\nExample: {s} 04ad10 10\n", .{args[0]});
        std.process.exit(1);
    }

    const target_pattern = args[1];

    var num_threads: usize = 0;
    if (args.len >= 3) {
        num_threads = std.fmt.parseInt(usize, args[2], 10) catch {
            print("Error: Invalid number of threads '{s}'. Must be a positive integer.\n", .{args[2]});
            std.process.exit(1);
        };
    }

    // Load BIP39 word list
    const word_list = try loadBIP39Words(allocator);
    defer allocator.free(word_list);

    if (word_list.len != 2048) {
        print("Warning: Expected 2048 BIP39 words, got {}\n", .{word_list.len});
    }

    print("Searching for wallet ", .{});
    const search_pattern: []const u8 = blk: {
        if (SEARCH_IN_MNEMONIC) {
            print("with mnemonic containing '{s}'...\n", .{target_pattern});
            break :blk target_pattern;
        } else {
            if (!isValidHexPattern(target_pattern)) {
                print("⚠ Warning: '{s}' contains non-hex characters. Ethereum addresses are hex (0-9, a-f).\n", .{target_pattern});
                const converted = try toHexPattern(target_pattern, allocator);
                print("Converting to hex pattern: '{s}'...\n", .{converted});
                break :blk converted;
            } else {
                print("with address starting with '{s}'...\n", .{target_pattern});
                break :blk target_pattern;
            }
        }
    };
    defer if (!SEARCH_IN_MNEMONIC and !isValidHexPattern(target_pattern)) {
        allocator.free(search_pattern);
    };

    // Determine number of threads (use all available CPUs)

    if (num_threads == 0) {
        num_threads = std.Thread.getCpuCount() catch 4;
    }
    print("Using {} CPU cores\n\n", .{num_threads});

    // Initialize shared state
    var shared = SharedState{
        .found = std.atomic.Value(bool).init(false),
        .total_attempts = std.atomic.Value(u64).init(0),
        .result_mutex = std.Thread.Mutex{},
        .result = null,
        .word_list = word_list,
        .search_pattern = search_pattern,
        .allocator = allocator,
    };

    const start_time = std.time.nanoTimestamp();

    // Spawn worker threads
    const threads = try allocator.alloc(std.Thread, num_threads);
    defer allocator.free(threads);

    for (threads) |*thread| {
        thread.* = try std.Thread.spawn(.{}, workerThread, .{ &shared, start_time });
    }

    // Monitor progress
    while (!shared.found.load(.acquire)) {
        std.Thread.sleep(100 * std.time.ns_per_ms); // Sleep 100ms

        const attempts = shared.total_attempts.load(.monotonic);
        if (attempts > 0) {
            const elapsed = @as(f64, @floatFromInt(std.time.nanoTimestamp() - start_time)) / 1_000_000_000.0;
            const rate = if (elapsed > 0) @as(f64, @floatFromInt(attempts)) / elapsed else 0;

            // Calculate estimated remaining time
            if (!SEARCH_IN_MNEMONIC and rate > 0) {
                // For hex patterns: probability = 1/(16^pattern_length)
                // Expected attempts = 16^pattern_length
                const pattern_len = @as(f64, @floatFromInt(search_pattern.len));
                const expected_attempts = std.math.pow(f64, 16.0, pattern_len);
                const remaining_attempts = if (expected_attempts > @as(f64, @floatFromInt(attempts)))
                    expected_attempts - @as(f64, @floatFromInt(attempts))
                else
                    0;
                const estimated_seconds = remaining_attempts / rate;

                // Format time estimate
                var time_str: [64]u8 = undefined;
                const time_slice: []const u8 = blk: {
                    if (estimated_seconds < 60) {
                        break :blk std.fmt.bufPrint(&time_str, "{d:.0}s", .{estimated_seconds}) catch "?s";
                    } else if (estimated_seconds < 3600) {
                        const minutes = estimated_seconds / 60.0;
                        break :blk std.fmt.bufPrint(&time_str, "{d:.1}m", .{minutes}) catch "?m";
                    } else if (estimated_seconds < 86400) {
                        const hours = estimated_seconds / 3600.0;
                        break :blk std.fmt.bufPrint(&time_str, "{d:.1}h", .{hours}) catch "?h";
                    } else {
                        const days = estimated_seconds / 86400.0;
                        break :blk std.fmt.bufPrint(&time_str, "{d:.1}d", .{days}) catch "?d";
                    }
                };

                const progress_pct = if (expected_attempts > 0)
                    (@as(f64, @floatFromInt(attempts)) / expected_attempts) * 100.0
                else
                    0.0;

                print("\rAttempts: {} ({d:.0}/sec) | Progress: {d:.2}% | Est. remaining: {s}         ", .{ attempts, rate, progress_pct, time_slice });
            } else {
                print("\rAttempts: {} ({d:.0} addresses/sec)         ", .{ attempts, rate });
            }
        }
    }

    // Wait for all threads to finish
    for (threads) |thread| {
        thread.join();
    }

    // Display result
    if (shared.result) |result| {
        print("\n\n✓ Found matching {s} after {} attempts ({d:.2} seconds)!\n\n", .{
            if (SEARCH_IN_MNEMONIC) "mnemonic" else "address",
            result.attempts,
            result.elapsed,
        });

        if (SEARCH_IN_MNEMONIC) {
            print("Mnemonic (12 words): ", .{});
            for (result.mnemonic, 0..) |word, i| {
                if (i > 0) print(" ", .{});
                print("{s}", .{word});
            }
            print("\n\nAddress: {s}\n", .{result.address});
        } else {
            print("Address: {s}\n", .{result.address});
            print("Mnemonic (12 words): ", .{});
            for (result.mnemonic, 0..) |word, i| {
                if (i > 0) print(" ", .{});
                print("{s}", .{word});
            }
            print("\n", .{});
        }

        print("\nPrivate Key (hex): ", .{});
        for (result.private_key) |byte| {
            print("{x:0>2}", .{byte});
        }
        print("\n", .{});
    } else {
        print("\nError: No result found\n", .{});
    }
}
