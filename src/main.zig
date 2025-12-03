const std = @import("std");
const crypto = std.crypto;
const fmt = std.fmt;
const print = std.debug.print;
const secp256k1 = @import("secp256k1.zig");

// -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
// Usage: cool-wallet-address-finder <pattern> [num_threads]
// Example: cool-wallet-address-finder 04ad10 10
// If num_threads is 0 or not provided, all CPUs will be used
// -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-

const FoundWallet = struct {
    address: [42]u8,
    private_key: [32]u8,
    public_key: [65]u8,
    attempts: u64,
    elapsed: f64,
};

const SharedState = struct {
    found: std.atomic.Value(bool),
    total_attempts: std.atomic.Value(u64),
    result_mutex: std.Thread.Mutex,
    result: ?FoundWallet,
    search_pattern: []const u8,
};

// secp256k1 curve order: n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
const SECP256K1_ORDER: [32]u8 = [32]u8{
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
    0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
    0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
};

// Use libsecp256k1 for proper secp256k1 operations
var secp256k1_ctx: ?*secp256k1.secp256k1_context = null;

fn getSecp256k1Context() !*secp256k1.secp256k1_context {
    if (secp256k1_ctx == null) {
        secp256k1_ctx = secp256k1.createContext() orelse return error.ContextCreationFailed;
    }
    return secp256k1_ctx.?;
}

fn secp256k1PublicKey(private_key: [32]u8) ![65]u8 {
    // Use libsecp256k1 for proper secp256k1 public key derivation
    const ctx = try getSecp256k1Context();
    return secp256k1.publicKeyFromPrivate(ctx, private_key);
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

fn generateValidPrivateKey() [32]u8 {
    // Generate a valid secp256k1 private key (must be < curve order)
    while (true) {
        var private_key: [32]u8 = undefined;
        std.crypto.random.bytes(&private_key);

        // Check if key is valid (< curve order)
        var i: usize = 0;
        while (i < 32) : (i += 1) {
            if (private_key[i] < SECP256K1_ORDER[i]) {
                return private_key; // Valid key
            } else if (private_key[i] > SECP256K1_ORDER[i]) {
                break; // Invalid, regenerate
            }
        }
        // If we get here and i == 32, key equals order (invalid) - regenerate
    }
}

fn workerThread(shared: *SharedState, start_time: i128) void {
    var local_attempts: u64 = 0;

    while (!shared.found.load(.acquire)) {
        local_attempts += 1;

        // Generate random private key
        const private_key = generateValidPrivateKey();

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
                    .address = address_hex,
                    .private_key = private_key,
                    .public_key = public_key,
                    .attempts = total,
                    .elapsed = elapsed,
                };
            }
            return;
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
        num_threads = fmt.parseInt(usize, args[2], 10) catch {
            print("Error: Invalid number of threads '{s}'. Must be a positive integer.\n", .{args[2]});
            std.process.exit(1);
        };
    }

    print("Searching for wallet ", .{});
    const search_pattern: []const u8 = blk: {
        if (!isValidHexPattern(target_pattern)) {
            print("⚠ Warning: '{s}' contains non-hex characters. Ethereum addresses are hex (0-9, a-f).\n", .{target_pattern});
            const converted = try toHexPattern(target_pattern, allocator);
            print("Converting to hex pattern: '{s}'...\n", .{converted});
            break :blk converted;
        } else {
            print("with address starting with '{s}'...\n", .{target_pattern});
            break :blk target_pattern;
        }
    };
    defer if (!isValidHexPattern(target_pattern)) {
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
        .search_pattern = search_pattern,
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
            if (rate > 0) {
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
                        break :blk fmt.bufPrint(&time_str, "{d:.0}s", .{estimated_seconds}) catch "?s";
                    } else if (estimated_seconds < 3600) {
                        const minutes = estimated_seconds / 60.0;
                        break :blk fmt.bufPrint(&time_str, "{d:.1}m", .{minutes}) catch "?m";
                    } else if (estimated_seconds < 86400) {
                        const hours = estimated_seconds / 3600.0;
                        break :blk fmt.bufPrint(&time_str, "{d:.1}h", .{hours}) catch "?h";
                    } else {
                        const days = estimated_seconds / 86400.0;
                        break :blk fmt.bufPrint(&time_str, "{d:.1}d", .{days}) catch "?d";
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
        print("\n\n✓ Found matching address after {} attempts ({d:.2} seconds)!\n\n", .{
            result.attempts,
            result.elapsed,
        });

        print("Address: {s}\n\n", .{result.address});

        print("Private Key (hex): ", .{});
        for (result.private_key) |byte| {
            print("{x:0>2}", .{byte});
        }
        print("\n\n", .{});

        print("Public Key (hex, uncompressed): ", .{});
        for (result.public_key) |byte| {
            print("{x:0>2}", .{byte});
        }
        print("\n", .{});
    } else {
        print("\nError: No result found\n", .{});
    }
}
