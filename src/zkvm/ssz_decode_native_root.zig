//! Native source oracle for the SSZ-only proof endpoint.

const std = @import("std");
const observation = @import("ssz_decode_observation");
const ssz_decode = @import("ssz_decode");
const zesu_allocator = @import("zesu_allocator");
const zkvm_io = @import("zkvm_io");

pub fn main() !void {
    const allocator = std.heap.page_allocator;
    zesu_allocator.set(allocator);
    var input_ptr: [*]const u8 = undefined;
    var input_size: usize = 0;
    zkvm_io.read_input(&input_ptr, &input_size);
    const encoded = input_ptr[0..input_size];
    const decoded = ssz_decode.decode(allocator, encoded) catch {
        observation.writeFailure();
        return;
    };
    observation.writeSuccess(decoded);
}
