//! Freestanding root for the lossless Amsterdam raw-SSZ decoder object.
//!
//! This object is intentionally separate from the checksum sink. The caller
//! supplies input that remains live until it has called the sink, then invokes
//! `zesu_raw_decode` exactly once per zkVM heap. The decoded value is stored in
//! static storage and made available only through `zesu_raw_result`.
//!
//! ABI:
//!   zesu_decode_raw(ptr, len) -> 1 on success, 0 on rejection/allocation error
//!   zesu_raw_result()         -> opaque pointer or null
//!   zesu_raw_error()          -> stable diagnostic code for a failed decode

const std = @import("std");
const raw = @import("ssz_raw");

extern fn zesu_raw_alloc(bytes: usize, alignment: usize) callconv(.c) ?[*]u8;

pub const DecodeStatus = enum(u32) {
    not_run = 0,
    ok = 1,
    invalid_ssz = 2,
    unknown_fork = 3,
    out_of_memory = 4,
    already_decoded = 5,
};

var stored_result: ?raw.RawStatelessInput = null;
var last_status: DecodeStatus = .not_run;
var allocator_state: u8 = 0;
var attempted: bool = false;

const allocator_vtable = std.mem.Allocator.VTable{
    .alloc = allocatorAlloc,
    .resize = allocatorResize,
    .remap = allocatorRemap,
    .free = allocatorFree,
};

fn allocatorAlloc(
    context: *anyopaque,
    len: usize,
    alignment: std.mem.Alignment,
    return_address: usize,
) ?[*]u8 {
    _ = context;
    _ = return_address;
    return zesu_raw_alloc(len, @as(usize, 1) << @intFromEnum(alignment));
}

fn allocatorResize(
    context: *anyopaque,
    memory: []u8,
    alignment: std.mem.Alignment,
    new_len: usize,
    return_address: usize,
) bool {
    _ = context;
    _ = memory;
    _ = alignment;
    _ = new_len;
    _ = return_address;
    return false;
}

fn allocatorRemap(
    context: *anyopaque,
    memory: []u8,
    alignment: std.mem.Alignment,
    new_len: usize,
    return_address: usize,
) ?[*]u8 {
    _ = context;
    _ = memory;
    _ = alignment;
    _ = new_len;
    _ = return_address;
    return null;
}

fn allocatorFree(
    context: *anyopaque,
    memory: []u8,
    alignment: std.mem.Alignment,
    return_address: usize,
) void {
    _ = context;
    _ = memory;
    _ = alignment;
    _ = return_address;
    // The decoder runs once against the host-provided bump heap. Its result is
    // intentionally retained for the sink, so individual frees are no-ops.
}

fn allocator() std.mem.Allocator {
    return .{ .ptr = &allocator_state, .vtable = &allocator_vtable };
}

/// Never-inline, exported boundary for the measured decoder object.
///
/// The input bytes are borrowed: the caller must retain them until after the
/// separate sink object has consumed `zesu_raw_result()`. One successful or
/// failed call is allowed per heap reset; this avoids making allocator lifetime
/// part of the parser's semantics.
pub noinline fn zesu_decode_raw(input: [*]const u8, input_len: usize) callconv(.c) i32 {
    if (attempted) {
        last_status = .already_decoded;
        return 0;
    }
    attempted = true;

    const input_bytes = input[0..input_len];
    stored_result = raw.decode(allocator(), input_bytes) catch |err| {
        last_status = switch (err) {
            error.InvalidSsz => .invalid_ssz,
            error.UnknownFork => .unknown_fork,
            error.OutOfMemory => .out_of_memory,
        };
        return 0;
    };
    last_status = .ok;
    return 1;
}

comptime {
    @export(&zesu_decode_raw, .{ .name = "zesu_decode_raw" });
}

/// Opaque, exported-lifetime result accessor consumed by `raw_sink.zig`.
pub export fn zesu_raw_result() callconv(.c) ?*const raw.RawStatelessInput {
    if (stored_result) |*result| return result;
    return null;
}

pub export fn zesu_raw_error() callconv(.c) u32 {
    return @intFromEnum(last_status);
}
