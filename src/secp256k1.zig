// C bindings for libsecp256k1

pub const secp256k1_context = opaque {};
pub const secp256k1_pubkey = extern struct {
    data: [64]u8,
};

pub extern "c" fn secp256k1_context_create(flags: c_uint) ?*secp256k1_context;
pub extern "c" fn secp256k1_context_destroy(ctx: *secp256k1_context) void;
pub extern "c" fn secp256k1_ec_pubkey_create(
    ctx: *secp256k1_context,
    pubkey: *secp256k1_pubkey,
    seckey: [*c]const u8,
) c_int;

pub extern "c" fn secp256k1_ec_pubkey_serialize(
    ctx: *secp256k1_context,
    output: [*c]u8,
    outputlen: [*c]usize,
    pubkey: *const secp256k1_pubkey,
    flags: c_uint,
) c_int;

pub const SECP256K1_FLAGS_TYPE_CONTEXT: c_uint = 1 << 0;
pub const SECP256K1_CONTEXT_NONE: c_uint = SECP256K1_FLAGS_TYPE_CONTEXT;
pub const SECP256K1_FLAGS_TYPE_COMPRESSION: c_uint = 1 << 1;
pub const SECP256K1_EC_UNCOMPRESSED: c_uint = SECP256K1_FLAGS_TYPE_COMPRESSION;

pub fn createContext() ?*secp256k1_context {
    return secp256k1_context_create(SECP256K1_CONTEXT_NONE);
}

pub fn publicKeyFromPrivate(ctx: *secp256k1_context, private_key: [32]u8) ![65]u8 {
    var pubkey: secp256k1_pubkey = undefined;

    if (secp256k1_ec_pubkey_create(ctx, &pubkey, &private_key) == 0) {
        return error.InvalidPrivateKey;
    }

    var output: [65]u8 = undefined;
    var outputlen: usize = 65;

    if (secp256k1_ec_pubkey_serialize(ctx, &output, &outputlen, &pubkey, SECP256K1_EC_UNCOMPRESSED) == 0) {
        return error.SerializationFailed;
    }

    return output;
}
