//! Freestanding bump allocator owned by the raw-SSZ measurement adapter.
//!
//! It is compiled into its own object so ownership analysis can classify the
//! heap implementation separately from the raw decoder. The decoder consumes
//! this ABI only through its `std.mem.Allocator` vtable wrapper.

extern var ZKVM_HEAP_POS: usize;
extern var ZKVM_HEAP_TOP: usize;

/// Allocate `bytes` from the host-provided bump heap with a power-of-two byte
/// alignment. Returns null on an invalid alignment or exhausted heap.
pub export fn zesu_raw_alloc(bytes: usize, alignment: usize) callconv(.c) ?[*]u8 {
    if (alignment == 0) return null;
    if ((alignment & (alignment - 1)) != 0) return null;
    if (ZKVM_HEAP_POS > ZKVM_HEAP_TOP) return null;

    const misalignment = ZKVM_HEAP_POS & (alignment - 1);
    const padding = if (misalignment == 0) 0 else alignment - misalignment;
    if (padding > ZKVM_HEAP_TOP - ZKVM_HEAP_POS) return null;

    const aligned_position = ZKVM_HEAP_POS + padding;
    if (bytes > ZKVM_HEAP_TOP - aligned_position) return null;

    const pointer: [*]u8 = @ptrFromInt(aligned_position);
    ZKVM_HEAP_POS = aligned_position + bytes;
    return pointer;
}
