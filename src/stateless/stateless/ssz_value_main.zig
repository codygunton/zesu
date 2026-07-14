//! Native-only `ssz-value-v1` renderer for the lossless Amsterdam SSZ decoder.
//!
//! This executable deliberately imports only `ssz_raw`.  It is a differential
//! adapter, not part of the freestanding RV64 parser measurement: it may use
//! host file IO and formatting, but it never enters the measured decoder/sink
//! object graph.

const std = @import("std");
const raw = @import("ssz_raw");

const Writer = std.Io.Writer;
const max_input_bytes: usize = @as(usize, std.math.maxInt(u32)) + 4;

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const args = try init.minimal.args.toSlice(init.arena.allocator());

    if (args.len > 2) {
        std.debug.print("usage: zesu-ssz-value [raw-ssz-file|-]\n", .{});
        std.process.exit(64);
    }

    const input = readInput(init.io, allocator, args) catch |err| {
        std.debug.print("error\tinput:{s}\n", .{@errorName(err)});
        std.process.exit(2);
    };
    defer allocator.free(input);

    var value = raw.decode(allocator, input) catch |err| {
        std.debug.print("error\t{s}\n", .{@errorName(err)});
        std.process.exit(1);
    };
    defer value.deinit(allocator);

    var stdout_buffer: [4096]u8 = undefined;
    var stdout = std.Io.File.stdout().writer(init.io, &stdout_buffer);
    renderValue(&stdout.interface, &value) catch |err| {
        std.debug.print("error\toutput:{s}\n", .{@errorName(err)});
        std.process.exit(2);
    };
    stdout.interface.flush() catch |err| {
        std.debug.print("error\toutput:{s}\n", .{@errorName(err)});
        std.process.exit(2);
    };
}

fn readInput(
    io: std.Io,
    allocator: std.mem.Allocator,
    args: []const [:0]const u8,
) ![]u8 {
    if (args.len == 1 or std.mem.eql(u8, args[1], "-")) {
        var reader_buffer: [4096]u8 = undefined;
        var reader = std.Io.File.stdin().reader(io, &reader_buffer);
        return reader.interface.allocRemaining(allocator, .limited(max_input_bytes));
    }
    return std.Io.Dir.cwd().readFileAlloc(io, args[1], allocator, .limited(max_input_bytes));
}

fn renderValue(writer: *Writer, value: *const raw.RawStatelessInput) !void {
    try writer.writeAll("version\tssz-value-v1\n");
    try renderNewPayloadRequest(writer, &value.new_payload_request);
    try renderWitness(writer, &value.witness);
    try renderChainConfig(writer, &value.chain_config);
    try emitFixedBytesList(writer, "public_keys", value.public_keys);
}

fn renderNewPayloadRequest(writer: *Writer, value: *const raw.RawNewPayloadRequest) !void {
    try renderExecutionPayload(writer, &value.execution_payload);
    try emitFixedBytesList(
        writer,
        "new_payload_request.versioned_hashes",
        value.versioned_hashes,
    );
    try emitBytes(
        writer,
        "new_payload_request.parent_beacon_block_root",
        value.parent_beacon_block_root[0..],
    );
    try renderExecutionRequests(writer, &value.execution_requests);
}

fn renderExecutionPayload(writer: *Writer, value: *const raw.RawExecutionPayload) !void {
    try emitBytes(writer, "new_payload_request.execution_payload.parent_hash", value.parent_hash[0..]);
    try emitBytes(writer, "new_payload_request.execution_payload.fee_recipient", value.fee_recipient[0..]);
    try emitBytes(writer, "new_payload_request.execution_payload.state_root", value.state_root[0..]);
    try emitBytes(writer, "new_payload_request.execution_payload.receipts_root", value.receipts_root[0..]);
    try emitBytes(writer, "new_payload_request.execution_payload.logs_bloom", value.logs_bloom[0..]);
    try emitBytes(writer, "new_payload_request.execution_payload.prev_randao", value.prev_randao[0..]);
    try emitScalar(writer, "new_payload_request.execution_payload.block_number", value.block_number);
    try emitScalar(writer, "new_payload_request.execution_payload.gas_limit", value.gas_limit);
    try emitScalar(writer, "new_payload_request.execution_payload.gas_used", value.gas_used);
    try emitScalar(writer, "new_payload_request.execution_payload.timestamp", value.timestamp);
    try emitBytes(writer, "new_payload_request.execution_payload.extra_data", value.extra_data);
    try emitScalar(writer, "new_payload_request.execution_payload.base_fee_per_gas", value.base_fee_per_gas);
    try emitBytes(writer, "new_payload_request.execution_payload.block_hash", value.block_hash[0..]);
    try emitByteSliceList(writer, "new_payload_request.execution_payload.transactions", value.transactions);
    try renderWithdrawals(writer, value.withdrawals);
    try emitScalar(writer, "new_payload_request.execution_payload.blob_gas_used", value.blob_gas_used);
    try emitScalar(writer, "new_payload_request.execution_payload.excess_blob_gas", value.excess_blob_gas);
    try emitBytes(writer, "new_payload_request.execution_payload.block_access_list", value.block_access_list);
    try emitScalar(writer, "new_payload_request.execution_payload.slot_number", value.slot_number);
}

fn renderWithdrawals(writer: *Writer, values: []const raw.RawWithdrawal) !void {
    const base = "new_payload_request.execution_payload.withdrawals";
    try emitCount(writer, base, values.len);
    for (values, 0..) |value, index| {
        try emitIndexedScalar(writer, base, index, ".index", value.index);
        try emitIndexedScalar(writer, base, index, ".validator_index", value.validator_index);
        try emitIndexedBytes(writer, base, index, ".address", value.address[0..]);
        try emitIndexedScalar(writer, base, index, ".amount", value.amount);
    }
}

fn renderExecutionRequests(writer: *Writer, value: *const raw.RawExecutionRequests) !void {
    try renderDepositRequests(writer, value.deposits);
    try renderWithdrawalRequests(writer, value.withdrawals);
    try renderConsolidationRequests(writer, value.consolidations);
}

fn renderDepositRequests(writer: *Writer, values: []const raw.RawDepositRequest) !void {
    const base = "new_payload_request.execution_requests.deposits";
    try emitCount(writer, base, values.len);
    for (values, 0..) |value, index| {
        try emitIndexedBytes(writer, base, index, ".pubkey", value.pubkey[0..]);
        try emitIndexedBytes(writer, base, index, ".withdrawal_credentials", value.withdrawal_credentials[0..]);
        try emitIndexedScalar(writer, base, index, ".amount", value.amount);
        try emitIndexedBytes(writer, base, index, ".signature", value.signature[0..]);
        try emitIndexedScalar(writer, base, index, ".index", value.index);
    }
}

fn renderWithdrawalRequests(writer: *Writer, values: []const raw.RawWithdrawalRequest) !void {
    const base = "new_payload_request.execution_requests.withdrawals";
    try emitCount(writer, base, values.len);
    for (values, 0..) |value, index| {
        try emitIndexedBytes(writer, base, index, ".source_address", value.source_address[0..]);
        try emitIndexedBytes(writer, base, index, ".validator_pubkey", value.validator_pubkey[0..]);
        try emitIndexedScalar(writer, base, index, ".amount", value.amount);
    }
}

fn renderConsolidationRequests(writer: *Writer, values: []const raw.RawConsolidationRequest) !void {
    const base = "new_payload_request.execution_requests.consolidations";
    try emitCount(writer, base, values.len);
    for (values, 0..) |value, index| {
        try emitIndexedBytes(writer, base, index, ".source_address", value.source_address[0..]);
        try emitIndexedBytes(writer, base, index, ".source_pubkey", value.source_pubkey[0..]);
        try emitIndexedBytes(writer, base, index, ".target_pubkey", value.target_pubkey[0..]);
    }
}

fn renderWitness(writer: *Writer, value: *const raw.RawExecutionWitness) !void {
    try emitByteSliceList(writer, "witness.state", value.state);
    try emitByteSliceList(writer, "witness.codes", value.codes);
    try emitByteSliceList(writer, "witness.headers", value.headers);
}

fn renderChainConfig(writer: *Writer, value: *const raw.RawChainConfig) !void {
    try emitScalar(writer, "chain_config.chain_id", value.chain_id);
    try emitScalar(writer, "chain_config.active_fork.fork", value.active_fork.fork);
    try emitOptionScalar(
        writer,
        "chain_config.active_fork.activation.block_number",
        value.active_fork.activation.block_number,
    );
    try emitOptionScalar(
        writer,
        "chain_config.active_fork.activation.timestamp",
        value.active_fork.activation.timestamp,
    );
    try emitOptionBlobSchedule(
        writer,
        "chain_config.active_fork.blob_schedule",
        value.active_fork.blob_schedule,
    );
}

fn emitByteSliceList(writer: *Writer, base: []const u8, values: []const []const u8) !void {
    try emitCount(writer, base, values.len);
    for (values, 0..) |value, index| try emitIndexedBytes(writer, base, index, "", value);
}

fn emitFixedBytesList(writer: *Writer, base: []const u8, values: anytype) !void {
    try emitCount(writer, base, values.len);
    for (values, 0..) |value, index| try emitIndexedBytes(writer, base, index, "", value[0..]);
}

fn emitOptionScalar(writer: *Writer, path: []const u8, value: ?u64) !void {
    if (value) |present| {
        try emitOption(writer, path, "some");
        var buffer: [192]u8 = undefined;
        const value_path = try std.fmt.bufPrint(&buffer, "{s}.value", .{path});
        try emitScalar(writer, value_path, present);
    } else {
        try emitOption(writer, path, "none");
    }
}

fn emitOptionBlobSchedule(writer: *Writer, path: []const u8, value: ?raw.RawBlobSchedule) !void {
    if (value) |present| {
        try emitOption(writer, path, "some");
        var buffer: [192]u8 = undefined;
        try emitScalar(
            writer,
            try std.fmt.bufPrint(&buffer, "{s}.value.target", .{path}),
            present.target,
        );
        try emitScalar(
            writer,
            try std.fmt.bufPrint(&buffer, "{s}.value.max", .{path}),
            present.max,
        );
        try emitScalar(
            writer,
            try std.fmt.bufPrint(&buffer, "{s}.value.base_fee_update_fraction", .{path}),
            present.base_fee_update_fraction,
        );
    } else {
        try emitOption(writer, path, "none");
    }
}

fn emitIndexedBytes(
    writer: *Writer,
    base: []const u8,
    index: usize,
    suffix: []const u8,
    value: []const u8,
) !void {
    var buffer: [192]u8 = undefined;
    const path = try indexedPath(&buffer, base, index, suffix);
    try emitBytes(writer, path, value);
}

fn emitIndexedScalar(
    writer: *Writer,
    base: []const u8,
    index: usize,
    suffix: []const u8,
    value: anytype,
) !void {
    var buffer: [192]u8 = undefined;
    const path = try indexedPath(&buffer, base, index, suffix);
    try emitScalar(writer, path, value);
}

fn indexedPath(buffer: []u8, base: []const u8, index: usize, suffix: []const u8) ![]const u8 {
    return std.fmt.bufPrint(buffer, "{s}[{d}]{s}", .{ base, index, suffix });
}

fn emitScalar(writer: *Writer, path: []const u8, value: anytype) !void {
    try emitPrefix(writer, path, "scalar");
    try writer.print("{d}\n", .{value});
}

fn emitBytes(writer: *Writer, path: []const u8, value: []const u8) !void {
    try emitPrefix(writer, path, "bytes");
    try writer.writeAll("0x");
    for (value) |byte| try writer.print("{x:0>2}", .{byte});
    try writer.writeByte('\n');
}

fn emitCount(writer: *Writer, path: []const u8, count: usize) !void {
    try emitPrefix(writer, path, "count");
    try writer.print("{d}\n", .{count});
}

fn emitOption(writer: *Writer, path: []const u8, value: []const u8) !void {
    try emitPrefix(writer, path, "option");
    try writer.print("{s}\n", .{value});
}

fn emitPrefix(writer: *Writer, path: []const u8, kind: []const u8) !void {
    try writer.print("{s}\t{s}\t", .{ path, kind });
}
