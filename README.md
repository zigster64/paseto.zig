# paseto.zig

A Zig implementation of Paseto token encode / decode as an alternative to JWT

This implementation is assumed to be used in a web backend, therefore : 
- Implements local v4 only
- Takes an arena allocator (which your handler should provide), which makes MM much simpler
  and allows for the JSON decoder to use the parseFromSliceLeaky variant

Tested and works with http.zig 0.15.1

# Install


# Test

`zig build run` will run a local test of encoding a struct into JSON, encoding it into 
a paseto token, then decoding it, then printing it.

# Encode - Create a local token with encrypted payload

```
/// Generates a PASETO v4.local token from a payload and secret key
/// payload: any type that can be serialized to JSON
/// secret_key: exactly 32 bytes for ChaCha20-Poly1305 encryption
pub fn encode(
    arena: Allocator,
    payload: anytype,
    secret_key: []const u8,
) ![]u8
```

# Decode - Validate a token and extract its payload

```
/// Decodes a PASETO v4.local token as JSON, and then parses the
/// JSON payload into the given comptime struct. 
/// Returns an instance of that type
pub fn decode(
    arena: Allocator,
    token: []const u8,
    secret_key: []const u8,
    comptime T: type,
) !T
```
