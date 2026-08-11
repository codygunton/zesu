//! Minimal zkVM entrypoint for the SSZ decoder only.
//!
//! Input is exactly one SSZ-encoded `StatelessInput`, supplied by `read_input`. Output is a stable
//! decode observation: byte 0 is success (0/1), followed on success by ten little-endian u64 fields.
//! This observation is intentionally not a replacement SSZ encoding; it keeps decoded values live
//! for differential evidence while the binary proof relates the full in-memory result to EVM-Sail.

const std = @import("std");
const ssz_decode = @import("ssz_decode");
const zkvm_io = @import("zkvm_io");
const zesu_allocator = @import("zesu_allocator");

extern fn zkvm_exit(code: i32) noreturn;

pub fn panic(_: []const u8, _: ?*std.builtin.StackTrace, _: ?usize) noreturn {
    zkvm_exit(1);
}

fn put(out: []u8, index: usize, value: u64) void {
    std.mem.writeInt(u64, out[1 + index * 8 ..][0..8], value, .little);
}

export fn main() void {
    var input_ptr: [*]const u8 = undefined;
    var input_size: usize = 0;
    zkvm_io.read_input(&input_ptr, &input_size);

    const decoded = ssz_decode.decode(zesu_allocator.get(), input_ptr[0..input_size]) catch {
        zkvm_io.write_output(&.{0});
        zkvm_exit(0);
    };

    const payload = decoded.new_payload_request.execution_payload;
    var out: [81]u8 = .{0} ** 81;
    out[0] = 1;
    put(&out, 0, decoded.chain_config.chain_id);
    put(&out, 1, decoded.chain_config.active_fork_idx);
    put(&out, 2, payload.block_number);
    put(&out, 3, payload.timestamp);
    put(&out, 4, payload.transactions.len);
    put(&out, 5, payload.withdrawals.len);
    put(&out, 6, decoded.witness.nodes.len);
    put(&out, 7, decoded.witness.codes.len);
    put(&out, 8, decoded.witness.headers.len);
    put(&out, 9, decoded.public_keys.len);
    zkvm_io.write_output(&out);
    zkvm_exit(0);
}
