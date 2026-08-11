//! Native source oracle for the SSZ-only proof endpoint.

const std = @import("std");
const observation = @import("ssz_decode_observation");
const ssz_decode = @import("ssz_decode");
const zesu_allocator = @import("zesu_allocator");
const zkvm_io = @import("zkvm_io");

pub fn main() !void {
    const allocator = std.heap.page_allocator;
    zesu_allocator.set(allocator);
    const encoded = try zkvm_io.read_input(allocator);
    const decoded = ssz_decode.decode(allocator, encoded) catch {
        observation.writeFailure();
        return;
    };
    observation.writeSuccess(decoded);
}
