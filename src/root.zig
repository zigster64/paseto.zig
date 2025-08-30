const std = @import("std");
const crypto = std.crypto;
const json = std.json;
const mem = std.mem;
const ArrayList = std.ArrayList;
const Allocator = std.mem.Allocator;

const PasetoError = error{
    InvalidKeySize,
    EncryptionFailed,
    JsonSerializationFailed,
};

/// Generates a PASETO v4.local token from a payload and secret key
/// payload: any type that can be serialized to JSON
/// secret_key: exactly 32 bytes for ChaCha20-Poly1305 encryption
pub fn encode(
    arena: Allocator,
    payload: anytype,
    secret_key: []const u8,
) ![]u8 {
    // Validate secret key size
    if (secret_key.len != 32) {
        return PasetoError.InvalidKeySize;
    }

    // Convert payload to JSON
    const json_payload = try std.fmt.allocPrint(
        arena,
        "{f}", // The format specifier for a formatter is now just "{}"
        .{std.json.fmt(payload, .{})},
    );
    std.debug.print("encoded json payload {s}\n", .{json_payload});

    // Generate random 32-byte nonce for ChaCha20-Poly1305
    var nonce: [32]u8 = undefined;
    crypto.random.bytes(&nonce);

    // Create the pre-auth encoding: "v4.local." + nonce + ciphertext
    const header = "v4.local.";

    // Calculate ciphertext length (plaintext + 16 byte auth tag)
    const ciphertext_len = json_payload.len + crypto.aead.chacha_poly.ChaCha20Poly1305.tag_length;

    // Encrypt the JSON payload
    var ciphertext = try arena.alloc(u8, ciphertext_len);

    // Use the nonce as additional authenticated data for PASETO v4
    crypto.aead.chacha_poly.ChaCha20Poly1305.encrypt(
        ciphertext[0..json_payload.len],
        ciphertext[json_payload.len..][0..crypto.aead.chacha_poly.ChaCha20Poly1305.tag_length],
        json_payload,
        &nonce,
        nonce[0..crypto.aead.chacha_poly.ChaCha20Poly1305.nonce_length].*,
        secret_key[0..32].*,
    );

    // Combine nonce + ciphertext for base64 encoding
    var payload_to_encode = try arena.alloc(u8, nonce.len + ciphertext_len);
    @memcpy(payload_to_encode[0..nonce.len], &nonce);
    @memcpy(payload_to_encode[nonce.len..], ciphertext);

    // Base64 encode (nonce + ciphertext)
    const encoded_len = std.base64.url_safe_no_pad.Encoder.calcSize(payload_to_encode.len);

    // Allocate final token buffer with exact size needed
    const token_len = header.len + encoded_len;
    var token = try arena.alloc(u8, token_len);

    // Copy header
    @memcpy(token[0..header.len], header);

    // Encode the payload directly into the token buffer
    const encoded_payload = token[header.len..];
    _ = std.base64.url_safe_no_pad.Encoder.encode(encoded_payload, payload_to_encode);

    return token;
}

/// Decodes a PASETO v4.local token as JSON, and then parses the
/// JSON payload into the given comptime struct.
/// Returns an instance of that type
pub fn decode(
    arena: Allocator,
    token: []const u8,
    secret_key: []const u8,
    comptime T: type,
) !T {
    // Validate secret key size
    if (secret_key.len != 32) {
        return PasetoError.InvalidKeySize;
    }

    // Check for proper PASETO v4.local header
    const header = "v4.local.";
    if (token.len <= header.len or !mem.startsWith(u8, token, header)) {
        return error.InvalidToken;
    }

    // Extract the base64-encoded payload
    const encoded_payload = token[header.len..];

    // Decode base64 payload
    const max_decoded_len = std.base64.url_safe_no_pad.Decoder.calcSizeForSlice(encoded_payload) catch {
        return error.InvalidBase64;
    };
    var decoded_payload = try arena.alloc(u8, max_decoded_len);
    std.base64.url_safe_no_pad.Decoder.decode(decoded_payload, encoded_payload) catch {
        return error.InvalidBase64;
    };

    // Validate minimum size (32-byte nonce + at least 16-byte auth tag)
    const min_size = 32 + crypto.aead.chacha_poly.ChaCha20Poly1305.tag_length;
    if (decoded_payload.len < min_size) {
        return error.InvalidTokenSize;
    }

    // Extract nonce (first 32 bytes)
    const nonce = decoded_payload[0..32];

    // Extract ciphertext + auth tag (remaining bytes)
    const ciphertext_with_tag = decoded_payload[32..];

    // Validate ciphertext has at least the auth tag
    if (ciphertext_with_tag.len < crypto.aead.chacha_poly.ChaCha20Poly1305.tag_length) {
        return error.InvalidCiphertextSize;
    }

    // Calculate plaintext length (ciphertext - auth tag)
    const plaintext_len = ciphertext_with_tag.len - crypto.aead.chacha_poly.ChaCha20Poly1305.tag_length;

    // Allocate buffer for decrypted JSON
    const plaintext = try arena.alloc(u8, plaintext_len);

    // Split ciphertext and auth tag
    const ciphertext = ciphertext_with_tag[0..plaintext_len];
    const auth_tag = ciphertext_with_tag[plaintext_len..][0..crypto.aead.chacha_poly.ChaCha20Poly1305.tag_length];

    // Decrypt the payload
    crypto.aead.chacha_poly.ChaCha20Poly1305.decrypt(
        plaintext,
        ciphertext,
        auth_tag.*,
        nonce, // Use nonce as additional authenticated data
        nonce[0..crypto.aead.chacha_poly.ChaCha20Poly1305.nonce_length].*,
        secret_key[0..32].*,
    ) catch {
        return error.DecryptionFailed;
    };
    std.debug.print("decoded plaintext: {s}\n", .{plaintext});

    // Parse JSON into the specified type
    // Using parseFromSliceLeaky since we want the strings to be allocated and owned
    const parsed_value = json.parseFromSliceLeaky(T, arena, plaintext, .{}) catch {
        return error.JsonParsingFailed;
    };

    return parsed_value;
}
