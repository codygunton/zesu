//! Minimal zkVM entrypoint for the SSZ decoder only.
//!
//! Input is exactly one SSZ-encoded `StatelessInput`, supplied by `read_input`. Output is the
//! versioned, injective observation defined by `ssz_decode_observation`.

const std = @import("std");
const ssz_decode = @import("ssz_decode");
const observation = @import("ssz_decode_observation");
const zkvm_io = @import("zkvm_io");
const zesu_allocator = @import("zesu_allocator");

extern fn zkvm_exit(code: i32) noreturn;

pub fn panic(_: []const u8, _: ?*std.builtin.StackTrace, _: ?usize) noreturn {
    zkvm_exit(1);
}

export fn main() void {
    var input_ptr: [*]const u8 = undefined;
    var input_size: usize = 0;
    zkvm_io.read_input(&input_ptr, &input_size);

    const decoded = ssz_decode.decode(zesu_allocator.get(), input_ptr[0..input_size]) catch {
        observation.writeFailure();
        zkvm_exit(0);
    };

    observation.writeSuccess(decoded);
    zkvm_exit(0);
}
