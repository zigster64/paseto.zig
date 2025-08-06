const std = @import("std");
const paseto = @import("paseto");

const User = struct {
    email: []const u8,
    session: []const u8 = "",
    lvl: []const u8,
    exp: i64 = 0,
    iat: i64 = 0,

    pub fn format(self: User, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
        _ = fmt;
        _ = options;
        try writer.print(
            \\  email: {s}
            \\  session: {s}
            \\  level: {s}
            \\  exp: {}
            \\  iat: {}
        , .{ self.email, self.session, self.lvl, self.exp, self.iat });
    }
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();

    var arena = std.heap.ArenaAllocator.init(gpa.allocator());
    defer arena.deinit();
    const allocator = arena.allocator();

    // Set us up the bomb
    const secret = "this is my secret key that is 32";

    // encode us a token
    const token = try paseto.encode(
        allocator,
        User{
            .email = "jake@email.com",
            .session = "60399da8-29e3-4eae-b8b6-4c0b6c682f31",
            .lvl = "conscript",
            .exp = std.time.timestamp() + 86400,
            .iat = std.time.timestamp(),
        },
        secret,
    );
    defer allocator.free(token);
    std.debug.print("Encoded : {s}\n", .{token});

    // decode us the token
    const user: User = try paseto.decode(allocator, token, secret, User);

    std.debug.print("Decoded User: {s}\n", .{user});
}
