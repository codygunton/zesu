//! Lossless, strict Amsterdam (`SszStatelessInput`) SSZ decoder.
//!
//! This is deliberately independent from Zesu's runtime `input.StatelessInput`:
//! it preserves every SSZ field and never performs RLP decoding or runtime
//! defaulting. Variable byte fields are zero-copy views of the caller's input;
//! descriptor arrays and fixed records are allocated with the supplied allocator.
//!
//! `decode` is raw-first. It accepts an ERE length prefix only after parsing the
//! complete input as raw SSZ fails with `InvalidSsz` and the prefix is exact.

const std = @import("std");

pub const DecodeError = std.mem.Allocator.Error || error{
    InvalidSsz,
    UnknownFork,
};

pub const schema_id = [_]u8{ 0x00, 0x01 };

pub const MAX_EXTRA_DATA_BYTES: usize = 32;
pub const MAX_BYTES_PER_TRANSACTION: usize = 1 << 30;
pub const MAX_TRANSACTIONS_PER_PAYLOAD: usize = 1 << 20;
pub const MAX_WITHDRAWALS_PER_PAYLOAD: usize = 1 << 4;
pub const MAX_BLOB_COMMITMENTS_PER_BLOCK: usize = 4096;
pub const MAX_DEPOSIT_REQUESTS_PER_PAYLOAD: usize = 1 << 13;
pub const MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD: usize = 1 << 4;
pub const MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD: usize = 1 << 1;
pub const MAX_WITNESS_NODES: usize = 1 << 22;
pub const MAX_WITNESS_CODES: usize = 1 << 18;
pub const MAX_WITNESS_HEADERS: usize = 256;
pub const MAX_BYTES_PER_WITNESS_NODE: usize = 1 << 10;
pub const MAX_BYTES_PER_CODE: usize = 1 << 16;
pub const MAX_BYTES_PER_HEADER: usize = 1 << 10;
pub const MAX_PUBLIC_KEYS: usize = 1 << 15;

const TOP_FIXED_SIZE: usize = 16;
const NPR_FIXED_SIZE: usize = 44;
const EXECUTION_PAYLOAD_FIXED_SIZE: usize = 540;
const EXECUTION_REQUESTS_FIXED_SIZE: usize = 12;
const WITNESS_FIXED_SIZE: usize = 12;
const CHAIN_CONFIG_FIXED_SIZE: usize = 12;
const FORK_CONFIG_FIXED_SIZE: usize = 16;
const FORK_ACTIVATION_FIXED_SIZE: usize = 8;
const WITHDRAWAL_SIZE: usize = 44;
const DEPOSIT_REQUEST_SIZE: usize = 192;
const WITHDRAWAL_REQUEST_SIZE: usize = 76;
const CONSOLIDATION_REQUEST_SIZE: usize = 116;
const BLOB_SCHEDULE_SIZE: usize = 24;
pub const PUBLIC_KEY_SIZE: usize = 65;

/// `ProtocolFork` has 21 values at execution-specs Amsterdam pin
/// `bd8c673552d957dbe9c9f3f2656b87201f5ae646`, numbered 0 through 20.
const LAST_PROTOCOL_FORK_INDEX: u64 = 20;

pub const RawWithdrawal = struct {
    index: u64,
    validator_index: u64,
    address: [20]u8,
    amount: u64,
};

pub const RawDepositRequest = struct {
    pubkey: [48]u8,
    withdrawal_credentials: [32]u8,
    amount: u64,
    signature: [96]u8,
    index: u64,
};

pub const RawWithdrawalRequest = struct {
    source_address: [20]u8,
    validator_pubkey: [48]u8,
    amount: u64,
};

pub const RawConsolidationRequest = struct {
    source_address: [20]u8,
    source_pubkey: [48]u8,
    target_pubkey: [48]u8,
};

pub const RawExecutionRequests = struct {
    deposits: []RawDepositRequest,
    withdrawals: []RawWithdrawalRequest,
    consolidations: []RawConsolidationRequest,

    pub fn deinit(self: *RawExecutionRequests, alloc: std.mem.Allocator) void {
        alloc.free(self.deposits);
        alloc.free(self.withdrawals);
        alloc.free(self.consolidations);
        self.* = undefined;
    }
};

pub const RawExecutionPayload = struct {
    parent_hash: [32]u8,
    fee_recipient: [20]u8,
    state_root: [32]u8,
    receipts_root: [32]u8,
    logs_bloom: [256]u8,
    prev_randao: [32]u8,
    block_number: u64,
    gas_limit: u64,
    gas_used: u64,
    timestamp: u64,
    extra_data: []const u8,
    /// The complete little-endian `uint256`, not the runtime's historic `u64` projection.
    base_fee_per_gas: u256,
    block_hash: [32]u8,
    transactions: [][]const u8,
    withdrawals: []RawWithdrawal,
    blob_gas_used: u64,
    excess_blob_gas: u64,
    block_access_list: []const u8,
    slot_number: u64,

    pub fn deinit(self: *RawExecutionPayload, alloc: std.mem.Allocator) void {
        alloc.free(self.transactions);
        alloc.free(self.withdrawals);
        self.* = undefined;
    }
};

pub const RawNewPayloadRequest = struct {
    execution_payload: RawExecutionPayload,
    versioned_hashes: [][32]u8,
    parent_beacon_block_root: [32]u8,
    execution_requests: RawExecutionRequests,

    pub fn deinit(self: *RawNewPayloadRequest, alloc: std.mem.Allocator) void {
        self.execution_payload.deinit(alloc);
        alloc.free(self.versioned_hashes);
        self.execution_requests.deinit(alloc);
        self.* = undefined;
    }
};

pub const RawExecutionWitness = struct {
    state: [][]const u8,
    codes: [][]const u8,
    headers: [][]const u8,

    pub fn deinit(self: *RawExecutionWitness, alloc: std.mem.Allocator) void {
        alloc.free(self.state);
        alloc.free(self.codes);
        alloc.free(self.headers);
        self.* = undefined;
    }
};

pub const RawForkActivation = struct {
    block_number: ?u64,
    timestamp: ?u64,
};

pub const RawBlobSchedule = struct {
    target: u64,
    max: u64,
    base_fee_update_fraction: u64,
};

pub const RawForkConfig = struct {
    /// Exact SSZ enum index. `decode` rejects values not present at the pinned schema.
    fork: u64,
    activation: RawForkActivation,
    blob_schedule: ?RawBlobSchedule,
};

pub const RawChainConfig = struct {
    /// Exact encoded value, including zero.
    chain_id: u64,
    active_fork: RawForkConfig,
};

pub const RawStatelessInput = struct {
    new_payload_request: RawNewPayloadRequest,
    witness: RawExecutionWitness,
    chain_config: RawChainConfig,
    public_keys: [][PUBLIC_KEY_SIZE]u8,

    pub fn deinit(self: *RawStatelessInput, alloc: std.mem.Allocator) void {
        self.new_payload_request.deinit(alloc);
        self.witness.deinit(alloc);
        alloc.free(self.public_keys);
        self.* = undefined;
    }
};

/// Decode a raw Amsterdam V4 SSZ payload. No ERE prefix is considered here.
pub fn decodeRaw(alloc: std.mem.Allocator, data: []const u8) DecodeError!RawStatelessInput {
    try requireU32Length(data);
    if (data.len < schema_id.len or !std.mem.eql(u8, data[0..schema_id.len], &schema_id)) {
        return error.InvalidSsz;
    }

    const body = data[schema_id.len..];
    if (body.len < TOP_FIXED_SIZE) return error.InvalidSsz;
    const offsets = [_]usize{
        try readOffset(body, 0),
        try readOffset(body, 4),
        try readOffset(body, 8),
        try readOffset(body, 12),
    };
    try requireCanonicalOffsets(body, TOP_FIXED_SIZE, &offsets);

    var result: RawStatelessInput = undefined;
    result.new_payload_request = try decodeNewPayloadRequest(alloc, body[offsets[0]..offsets[1]]);
    errdefer result.new_payload_request.deinit(alloc);
    result.witness = try decodeExecutionWitness(alloc, body[offsets[1]..offsets[2]]);
    errdefer result.witness.deinit(alloc);
    result.chain_config = try decodeChainConfig(body[offsets[2]..offsets[3]]);
    result.public_keys = try decodePublicKeys(alloc, body[offsets[3]..]);
    errdefer alloc.free(result.public_keys);
    return result;
}

/// Decode raw SSZ first; only on a structural raw-SSZ failure does an exact ERE
/// prefix get a second interpretation. This prevents a raw payload whose first
/// four bytes happen to equal its length-minus-four from being stripped.
pub fn decode(alloc: std.mem.Allocator, data: []const u8) DecodeError!RawStatelessInput {
    return decodeRaw(alloc, data) catch |err| switch (err) {
        error.InvalidSsz => {
            if (!hasExactErePrefix(data)) return error.InvalidSsz;
            return decodeRaw(alloc, data[4..]);
        },
        else => return err,
    };
}

fn decodeNewPayloadRequest(alloc: std.mem.Allocator, data: []const u8) DecodeError!RawNewPayloadRequest {
    if (data.len < NPR_FIXED_SIZE) return error.InvalidSsz;
    const offsets = [_]usize{
        try readOffset(data, 0),
        try readOffset(data, 4),
        try readOffset(data, 40),
    };
    try requireCanonicalOffsets(data, NPR_FIXED_SIZE, &offsets);

    var result: RawNewPayloadRequest = undefined;
    result.execution_payload = try decodeExecutionPayload(alloc, data[offsets[0]..offsets[1]]);
    errdefer result.execution_payload.deinit(alloc);
    result.versioned_hashes = try decodeVersionedHashes(alloc, data[offsets[1]..offsets[2]]);
    errdefer alloc.free(result.versioned_hashes);
    result.parent_beacon_block_root = try readArray(32, data, 8);
    result.execution_requests = try decodeExecutionRequests(alloc, data[offsets[2]..]);
    errdefer result.execution_requests.deinit(alloc);
    return result;
}

fn decodeExecutionPayload(alloc: std.mem.Allocator, data: []const u8) DecodeError!RawExecutionPayload {
    if (data.len < EXECUTION_PAYLOAD_FIXED_SIZE) return error.InvalidSsz;
    const offsets = [_]usize{
        try readOffset(data, 436),
        try readOffset(data, 504),
        try readOffset(data, 508),
        try readOffset(data, 528),
    };
    try requireCanonicalOffsets(data, EXECUTION_PAYLOAD_FIXED_SIZE, &offsets);

    const extra_data = data[offsets[0]..offsets[1]];
    const block_access_list = data[offsets[3]..];
    if (extra_data.len > MAX_EXTRA_DATA_BYTES or block_access_list.len > MAX_BYTES_PER_TRANSACTION) {
        return error.InvalidSsz;
    }

    var result: RawExecutionPayload = undefined;
    result.parent_hash = try readArray(32, data, 0);
    result.fee_recipient = try readArray(20, data, 32);
    result.state_root = try readArray(32, data, 52);
    result.receipts_root = try readArray(32, data, 84);
    result.logs_bloom = try readArray(256, data, 116);
    result.prev_randao = try readArray(32, data, 372);
    result.block_number = try readU64(data, 404);
    result.gas_limit = try readU64(data, 412);
    result.gas_used = try readU64(data, 420);
    result.timestamp = try readU64(data, 428);
    result.extra_data = extra_data;
    result.base_fee_per_gas = try readU256(data, 440);
    result.block_hash = try readArray(32, data, 472);
    result.transactions = try decodeByteListList(
        alloc,
        data[offsets[1]..offsets[2]],
        MAX_TRANSACTIONS_PER_PAYLOAD,
        MAX_BYTES_PER_TRANSACTION,
    );
    errdefer alloc.free(result.transactions);
    result.withdrawals = try decodeWithdrawals(alloc, data[offsets[2]..offsets[3]]);
    errdefer alloc.free(result.withdrawals);
    result.blob_gas_used = try readU64(data, 512);
    result.excess_blob_gas = try readU64(data, 520);
    result.block_access_list = block_access_list;
    result.slot_number = try readU64(data, 532);
    return result;
}

fn decodeExecutionRequests(alloc: std.mem.Allocator, data: []const u8) DecodeError!RawExecutionRequests {
    if (data.len < EXECUTION_REQUESTS_FIXED_SIZE) return error.InvalidSsz;
    const offsets = [_]usize{
        try readOffset(data, 0),
        try readOffset(data, 4),
        try readOffset(data, 8),
    };
    try requireCanonicalOffsets(data, EXECUTION_REQUESTS_FIXED_SIZE, &offsets);

    var result: RawExecutionRequests = undefined;
    result.deposits = try decodeDepositRequests(alloc, data[offsets[0]..offsets[1]]);
    errdefer alloc.free(result.deposits);
    result.withdrawals = try decodeWithdrawalRequests(alloc, data[offsets[1]..offsets[2]]);
    errdefer alloc.free(result.withdrawals);
    result.consolidations = try decodeConsolidationRequests(alloc, data[offsets[2]..]);
    errdefer alloc.free(result.consolidations);
    return result;
}

fn decodeExecutionWitness(alloc: std.mem.Allocator, data: []const u8) DecodeError!RawExecutionWitness {
    if (data.len < WITNESS_FIXED_SIZE) return error.InvalidSsz;
    const offsets = [_]usize{
        try readOffset(data, 0),
        try readOffset(data, 4),
        try readOffset(data, 8),
    };
    try requireCanonicalOffsets(data, WITNESS_FIXED_SIZE, &offsets);

    var result: RawExecutionWitness = undefined;
    result.state = try decodeByteListList(
        alloc,
        data[offsets[0]..offsets[1]],
        MAX_WITNESS_NODES,
        MAX_BYTES_PER_WITNESS_NODE,
    );
    errdefer alloc.free(result.state);
    result.codes = try decodeByteListList(
        alloc,
        data[offsets[1]..offsets[2]],
        MAX_WITNESS_CODES,
        MAX_BYTES_PER_CODE,
    );
    errdefer alloc.free(result.codes);
    result.headers = try decodeByteListList(
        alloc,
        data[offsets[2]..],
        MAX_WITNESS_HEADERS,
        MAX_BYTES_PER_HEADER,
    );
    errdefer alloc.free(result.headers);
    return result;
}

fn decodeChainConfig(data: []const u8) DecodeError!RawChainConfig {
    if (data.len < CHAIN_CONFIG_FIXED_SIZE) return error.InvalidSsz;
    const active_fork_offset = try readOffset(data, 8);
    try requireCanonicalOffsets(data, CHAIN_CONFIG_FIXED_SIZE, &[_]usize{active_fork_offset});
    return .{
        .chain_id = try readU64(data, 0),
        .active_fork = try decodeForkConfig(data[active_fork_offset..]),
    };
}

fn decodeForkConfig(data: []const u8) DecodeError!RawForkConfig {
    if (data.len < FORK_CONFIG_FIXED_SIZE) return error.InvalidSsz;
    const offsets = [_]usize{
        try readOffset(data, 8),
        try readOffset(data, 12),
    };
    try requireCanonicalOffsets(data, FORK_CONFIG_FIXED_SIZE, &offsets);
    const fork = try readU64(data, 0);
    if (fork > LAST_PROTOCOL_FORK_INDEX) return error.UnknownFork;
    return .{
        .fork = fork,
        .activation = try decodeForkActivation(data[offsets[0]..offsets[1]]),
        .blob_schedule = try decodeOptionalBlobSchedule(data[offsets[1]..]),
    };
}

fn decodeForkActivation(data: []const u8) DecodeError!RawForkActivation {
    if (data.len < FORK_ACTIVATION_FIXED_SIZE) return error.InvalidSsz;
    const offsets = [_]usize{
        try readOffset(data, 0),
        try readOffset(data, 4),
    };
    try requireCanonicalOffsets(data, FORK_ACTIVATION_FIXED_SIZE, &offsets);
    return .{
        .block_number = try decodeOptionalU64(data[offsets[0]..offsets[1]]),
        .timestamp = try decodeOptionalU64(data[offsets[1]..]),
    };
}

fn decodeOptionalU64(data: []const u8) DecodeError!?u64 {
    return switch (data.len) {
        0 => null,
        8 => try readU64(data, 0),
        else => error.InvalidSsz,
    };
}

fn decodeOptionalBlobSchedule(data: []const u8) DecodeError!?RawBlobSchedule {
    return switch (data.len) {
        0 => null,
        BLOB_SCHEDULE_SIZE => .{
            .target = try readU64(data, 0),
            .max = try readU64(data, 8),
            .base_fee_update_fraction = try readU64(data, 16),
        },
        else => error.InvalidSsz,
    };
}

fn decodeVersionedHashes(alloc: std.mem.Allocator, data: []const u8) DecodeError![][32]u8 {
    if (data.len % 32 != 0) return error.InvalidSsz;
    const count = data.len / 32;
    if (count > MAX_BLOB_COMMITMENTS_PER_BLOCK) return error.InvalidSsz;
    const result = try alloc.alloc([32]u8, count);
    errdefer alloc.free(result);
    for (result, 0..) |*entry, index| {
        entry.* = try readArray(32, data, index * 32);
    }
    return result;
}

fn decodeWithdrawals(alloc: std.mem.Allocator, data: []const u8) DecodeError![]RawWithdrawal {
    if (data.len % WITHDRAWAL_SIZE != 0) return error.InvalidSsz;
    const count = data.len / WITHDRAWAL_SIZE;
    if (count > MAX_WITHDRAWALS_PER_PAYLOAD) return error.InvalidSsz;
    const result = try alloc.alloc(RawWithdrawal, count);
    errdefer alloc.free(result);
    for (result, 0..) |*entry, index| {
        const offset = index * WITHDRAWAL_SIZE;
        entry.* = .{
            .index = try readU64(data, offset),
            .validator_index = try readU64(data, offset + 8),
            .address = try readArray(20, data, offset + 16),
            .amount = try readU64(data, offset + 36),
        };
    }
    return result;
}

fn decodeDepositRequests(alloc: std.mem.Allocator, data: []const u8) DecodeError![]RawDepositRequest {
    if (data.len % DEPOSIT_REQUEST_SIZE != 0) return error.InvalidSsz;
    const count = data.len / DEPOSIT_REQUEST_SIZE;
    if (count > MAX_DEPOSIT_REQUESTS_PER_PAYLOAD) return error.InvalidSsz;
    const result = try alloc.alloc(RawDepositRequest, count);
    errdefer alloc.free(result);
    for (result, 0..) |*entry, index| {
        const offset = index * DEPOSIT_REQUEST_SIZE;
        entry.* = .{
            .pubkey = try readArray(48, data, offset),
            .withdrawal_credentials = try readArray(32, data, offset + 48),
            .amount = try readU64(data, offset + 80),
            .signature = try readArray(96, data, offset + 88),
            .index = try readU64(data, offset + 184),
        };
    }
    return result;
}

fn decodeWithdrawalRequests(alloc: std.mem.Allocator, data: []const u8) DecodeError![]RawWithdrawalRequest {
    if (data.len % WITHDRAWAL_REQUEST_SIZE != 0) return error.InvalidSsz;
    const count = data.len / WITHDRAWAL_REQUEST_SIZE;
    if (count > MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD) return error.InvalidSsz;
    const result = try alloc.alloc(RawWithdrawalRequest, count);
    errdefer alloc.free(result);
    for (result, 0..) |*entry, index| {
        const offset = index * WITHDRAWAL_REQUEST_SIZE;
        entry.* = .{
            .source_address = try readArray(20, data, offset),
            .validator_pubkey = try readArray(48, data, offset + 20),
            .amount = try readU64(data, offset + 68),
        };
    }
    return result;
}

fn decodeConsolidationRequests(alloc: std.mem.Allocator, data: []const u8) DecodeError![]RawConsolidationRequest {
    if (data.len % CONSOLIDATION_REQUEST_SIZE != 0) return error.InvalidSsz;
    const count = data.len / CONSOLIDATION_REQUEST_SIZE;
    if (count > MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD) return error.InvalidSsz;
    const result = try alloc.alloc(RawConsolidationRequest, count);
    errdefer alloc.free(result);
    for (result, 0..) |*entry, index| {
        const offset = index * CONSOLIDATION_REQUEST_SIZE;
        entry.* = .{
            .source_address = try readArray(20, data, offset),
            .source_pubkey = try readArray(48, data, offset + 20),
            .target_pubkey = try readArray(48, data, offset + 68),
        };
    }
    return result;
}

fn decodePublicKeys(alloc: std.mem.Allocator, data: []const u8) DecodeError![][PUBLIC_KEY_SIZE]u8 {
    if (data.len % PUBLIC_KEY_SIZE != 0) return error.InvalidSsz;
    const count = data.len / PUBLIC_KEY_SIZE;
    if (count > MAX_PUBLIC_KEYS) return error.InvalidSsz;
    const result = try alloc.alloc([PUBLIC_KEY_SIZE]u8, count);
    errdefer alloc.free(result);
    for (result, 0..) |*entry, index| {
        entry.* = try readArray(PUBLIC_KEY_SIZE, data, index * PUBLIC_KEY_SIZE);
    }
    return result;
}

/// Decode an SSZ `List[ByteList[max_item_bytes], max_items]`.
/// For a nonempty list the first offset must exactly equal the offset table's
/// byte length. Offsets are relative to this list and must be nondecreasing.
fn decodeByteListList(
    alloc: std.mem.Allocator,
    data: []const u8,
    max_items: usize,
    max_item_bytes: usize,
) DecodeError![][]const u8 {
    try requireU32Length(data);
    if (data.len == 0) return alloc.alloc([]const u8, 0);
    if (data.len < 4) return error.InvalidSsz;

    const first_offset = try readOffset(data, 0);
    if (first_offset == 0 or first_offset % 4 != 0 or first_offset > data.len) {
        return error.InvalidSsz;
    }
    const count = first_offset / 4;
    if (count > max_items) return error.InvalidSsz;

    var result = try alloc.alloc([]const u8, count);
    errdefer alloc.free(result);
    var previous: usize = first_offset;
    for (0..count) |index| {
        const start = try readOffset(data, index * 4);
        const end = if (index + 1 < count) try readOffset(data, (index + 1) * 4) else data.len;
        if (start < previous or end < start or end > data.len or end - start > max_item_bytes) {
            return error.InvalidSsz;
        }
        result[index] = data[start..end];
        previous = start;
    }
    return result;
}

fn requireCanonicalOffsets(data: []const u8, fixed_size: usize, offsets: []const usize) DecodeError!void {
    if (data.len < fixed_size or offsets.len == 0 or offsets[0] != fixed_size) {
        return error.InvalidSsz;
    }
    var previous = fixed_size;
    for (offsets) |offset| {
        if (offset < previous or offset > data.len) return error.InvalidSsz;
        previous = offset;
    }
}

fn requireU32Length(data: []const u8) DecodeError!void {
    if (data.len > std.math.maxInt(u32)) return error.InvalidSsz;
}

fn readOffset(data: []const u8, offset: usize) DecodeError!usize {
    return @intCast(try readU32(data, offset));
}

fn readU32(data: []const u8, offset: usize) DecodeError!u32 {
    const bytes = try bytesAt(data, offset, 4);
    const ptr: *const [4]u8 = @ptrCast(bytes.ptr);
    return std.mem.readInt(u32, ptr, .little);
}

fn readU64(data: []const u8, offset: usize) DecodeError!u64 {
    const bytes = try bytesAt(data, offset, 8);
    const ptr: *const [8]u8 = @ptrCast(bytes.ptr);
    return std.mem.readInt(u64, ptr, .little);
}

fn readU256(data: []const u8, offset: usize) DecodeError!u256 {
    const bytes = try bytesAt(data, offset, 32);
    const ptr: *const [32]u8 = @ptrCast(bytes.ptr);
    return std.mem.readInt(u256, ptr, .little);
}

fn readArray(comptime N: usize, data: []const u8, offset: usize) DecodeError![N]u8 {
    var result: [N]u8 = undefined;
    @memcpy(result[0..], try bytesAt(data, offset, N));
    return result;
}

fn bytesAt(data: []const u8, offset: usize, len: usize) DecodeError![]const u8 {
    if (offset > data.len or len > data.len - offset) return error.InvalidSsz;
    return data[offset..][0..len];
}

fn hasExactErePrefix(data: []const u8) bool {
    if (data.len < 4 or data.len - 4 > std.math.maxInt(u32)) return false;
    const declared = std.mem.readInt(u32, data[0..4], .little);
    return declared == data.len - 4;
}

// ── Focused executable checks ────────────────────────────────────────────────

fn putU32(bytes: []u8, offset: usize, value: u32) void {
    std.mem.writeInt(u32, bytes[offset..][0..4], value, .little);
}

fn putU64(bytes: []u8, offset: usize, value: u64) void {
    std.mem.writeInt(u64, bytes[offset..][0..8], value, .little);
}

/// Create a canonical all-empty Amsterdam V4 payload, optionally with a
/// block-access-list byte field of the requested length. The latter makes it
/// possible to exercise the raw/Ere-prefix collision without weakening rules.
fn makeMinimalV4(alloc: std.mem.Allocator, block_access_list_len: usize) DecodeError![]u8 {
    const payload_len = EXECUTION_PAYLOAD_FIXED_SIZE + block_access_list_len;
    const requests_len = EXECUTION_REQUESTS_FIXED_SIZE;
    const npr_len = NPR_FIXED_SIZE + payload_len + requests_len;
    const witness_len = WITNESS_FIXED_SIZE;
    const activation_len = FORK_ACTIVATION_FIXED_SIZE;
    const fork_len = FORK_CONFIG_FIXED_SIZE + activation_len;
    const chain_len = CHAIN_CONFIG_FIXED_SIZE + fork_len;
    const total_len = schema_id.len + TOP_FIXED_SIZE + npr_len + witness_len + chain_len;
    if (total_len > std.math.maxInt(u32)) return error.InvalidSsz;

    var bytes = try alloc.alloc(u8, total_len);
    errdefer alloc.free(bytes);
    @memset(bytes, 0);
    bytes[0] = schema_id[0];
    bytes[1] = schema_id[1];

    const body = schema_id.len;
    const npr_at = body + TOP_FIXED_SIZE;
    const witness_at = npr_at + npr_len;
    const chain_at = witness_at + witness_len;
    const pubkeys_at = chain_at + chain_len;
    putU32(bytes, body, @intCast(npr_at - body));
    putU32(bytes, body + 4, @intCast(witness_at - body));
    putU32(bytes, body + 8, @intCast(chain_at - body));
    putU32(bytes, body + 12, @intCast(pubkeys_at - body));

    const payload_at = npr_at + NPR_FIXED_SIZE;
    const requests_at = payload_at + payload_len;
    putU32(bytes, npr_at, NPR_FIXED_SIZE);
    putU32(bytes, npr_at + 4, @intCast(NPR_FIXED_SIZE + payload_len));
    putU32(bytes, npr_at + 40, @intCast(NPR_FIXED_SIZE + payload_len));
    // Preserve a visibly non-u64 base fee in the valid fixture.
    for (0..32) |index| bytes[payload_at + 440 + index] = @intCast(index + 1);
    putU32(bytes, payload_at + 436, EXECUTION_PAYLOAD_FIXED_SIZE);
    putU32(bytes, payload_at + 504, EXECUTION_PAYLOAD_FIXED_SIZE);
    putU32(bytes, payload_at + 508, EXECUTION_PAYLOAD_FIXED_SIZE);
    putU32(bytes, payload_at + 528, EXECUTION_PAYLOAD_FIXED_SIZE);
    putU64(bytes, payload_at + 532, 77);

    putU32(bytes, requests_at, EXECUTION_REQUESTS_FIXED_SIZE);
    putU32(bytes, requests_at + 4, EXECUTION_REQUESTS_FIXED_SIZE);
    putU32(bytes, requests_at + 8, EXECUTION_REQUESTS_FIXED_SIZE);

    putU32(bytes, witness_at, WITNESS_FIXED_SIZE);
    putU32(bytes, witness_at + 4, WITNESS_FIXED_SIZE);
    putU32(bytes, witness_at + 8, WITNESS_FIXED_SIZE);

    const fork_at = chain_at + CHAIN_CONFIG_FIXED_SIZE;
    const activation_at = fork_at + FORK_CONFIG_FIXED_SIZE;
    putU64(bytes, chain_at, 0); // Chain ID zero must remain zero.
    putU32(bytes, chain_at + 8, CHAIN_CONFIG_FIXED_SIZE);
    putU64(bytes, fork_at, LAST_PROTOCOL_FORK_INDEX);
    putU32(bytes, fork_at + 8, FORK_CONFIG_FIXED_SIZE);
    putU32(bytes, fork_at + 12, FORK_CONFIG_FIXED_SIZE + activation_len);
    putU32(bytes, activation_at, FORK_ACTIVATION_FIXED_SIZE);
    putU32(bytes, activation_at + 4, FORK_ACTIVATION_FIXED_SIZE);
    return bytes;
}

test "raw V4 preserves uint256, chain ID, and empty optionals" {
    const alloc = std.testing.allocator;
    const bytes = try makeMinimalV4(alloc, 0);
    defer alloc.free(bytes);

    var decoded = try decodeRaw(alloc, bytes);
    defer decoded.deinit(alloc);
    try std.testing.expectEqual(@as(u64, 0), decoded.chain_config.chain_id);
    try std.testing.expectEqual(@as(u64, 77), decoded.new_payload_request.execution_payload.slot_number);
    try std.testing.expect(decoded.chain_config.active_fork.activation.block_number == null);
    try std.testing.expect(decoded.chain_config.active_fork.blob_schedule == null);
    try std.testing.expect(decoded.new_payload_request.execution_payload.base_fee_per_gas > std.math.maxInt(u64));
}

test "ERE is accepted only after raw decoding fails" {
    const alloc = std.testing.allocator;
    const raw = try makeMinimalV4(alloc, 0);
    defer alloc.free(raw);
    const ere = try alloc.alloc(u8, raw.len + 4);
    defer alloc.free(ere);
    putU32(ere, 0, @intCast(raw.len));
    @memcpy(ere[4..], raw);

    try std.testing.expectError(error.InvalidSsz, decodeRaw(alloc, ere));
    var decoded = try decode(alloc, ere);
    defer decoded.deinit(alloc);
    try std.testing.expectEqual(@as(u64, 0), decoded.chain_config.chain_id);
}

test "raw/Ere prefix collision remains raw SSZ" {
    const alloc = std.testing.allocator;
    const collision_total_len: usize = 1_048_836;
    const minimal_total_len: usize = 662;
    const raw = try makeMinimalV4(alloc, collision_total_len - minimal_total_len);
    defer alloc.free(raw);
    try std.testing.expectEqual(collision_total_len, raw.len);
    try std.testing.expectEqual(@as(u32, @intCast(raw.len - 4)), std.mem.readInt(u32, raw[0..4], .little));

    var decoded = try decode(alloc, raw);
    defer decoded.deinit(alloc);
    try std.testing.expectEqual(collision_total_len - minimal_total_len, decoded.new_payload_request.execution_payload.block_access_list.len);
}

test "typed requests, optionals, and blob schedule retain every field" {
    const alloc = std.testing.allocator;

    var requests: [EXECUTION_REQUESTS_FIXED_SIZE + DEPOSIT_REQUEST_SIZE + WITHDRAWAL_REQUEST_SIZE + CONSOLIDATION_REQUEST_SIZE]u8 = @splat(0);
    putU32(&requests, 0, EXECUTION_REQUESTS_FIXED_SIZE);
    putU32(&requests, 4, EXECUTION_REQUESTS_FIXED_SIZE + DEPOSIT_REQUEST_SIZE);
    putU32(&requests, 8, EXECUTION_REQUESTS_FIXED_SIZE + DEPOSIT_REQUEST_SIZE + WITHDRAWAL_REQUEST_SIZE);
    requests[12] = 0xaa;
    putU64(&requests, 12 + 80, 9);
    requests[12 + DEPOSIT_REQUEST_SIZE] = 0xbb;
    putU64(&requests, 12 + DEPOSIT_REQUEST_SIZE + 68, 10);
    requests[12 + DEPOSIT_REQUEST_SIZE + WITHDRAWAL_REQUEST_SIZE] = 0xcc;
    var decoded_requests = try decodeExecutionRequests(alloc, &requests);
    defer decoded_requests.deinit(alloc);
    try std.testing.expectEqual(@as(usize, 1), decoded_requests.deposits.len);
    try std.testing.expectEqual(@as(u8, 0xaa), decoded_requests.deposits[0].pubkey[0]);
    try std.testing.expectEqual(@as(u64, 9), decoded_requests.deposits[0].amount);
    try std.testing.expectEqual(@as(u8, 0xbb), decoded_requests.withdrawals[0].source_address[0]);
    try std.testing.expectEqual(@as(u64, 10), decoded_requests.withdrawals[0].amount);
    try std.testing.expectEqual(@as(u8, 0xcc), decoded_requests.consolidations[0].source_address[0]);

    var fork: [FORK_CONFIG_FIXED_SIZE + FORK_ACTIVATION_FIXED_SIZE + 16 + BLOB_SCHEDULE_SIZE]u8 = @splat(0);
    putU64(&fork, 0, LAST_PROTOCOL_FORK_INDEX);
    putU32(&fork, 8, FORK_CONFIG_FIXED_SIZE);
    putU32(&fork, 12, FORK_CONFIG_FIXED_SIZE + FORK_ACTIVATION_FIXED_SIZE + 16);
    const activation_at = FORK_CONFIG_FIXED_SIZE;
    putU32(&fork, activation_at, FORK_ACTIVATION_FIXED_SIZE);
    putU32(&fork, activation_at + 4, FORK_ACTIVATION_FIXED_SIZE + 8);
    putU64(&fork, activation_at + FORK_ACTIVATION_FIXED_SIZE, 11);
    putU64(&fork, activation_at + FORK_ACTIVATION_FIXED_SIZE + 8, 12);
    const blob_at = FORK_CONFIG_FIXED_SIZE + FORK_ACTIVATION_FIXED_SIZE + 16;
    putU64(&fork, blob_at, 13);
    putU64(&fork, blob_at + 8, 14);
    putU64(&fork, blob_at + 16, 15);
    const decoded_fork = try decodeForkConfig(&fork);
    try std.testing.expectEqual(@as(?u64, 11), decoded_fork.activation.block_number);
    try std.testing.expectEqual(@as(?u64, 12), decoded_fork.activation.timestamp);
    try std.testing.expectEqual(@as(u64, 13), decoded_fork.blob_schedule.?.target);
    try std.testing.expectEqual(@as(u64, 15), decoded_fork.blob_schedule.?.base_fee_update_fraction);
}

test "strict offsets and fixed-list bounds reject malformed values" {
    const alloc = std.testing.allocator;
    const raw = try makeMinimalV4(alloc, 0);
    defer alloc.free(raw);
    putU32(raw, schema_id.len + 4, 15);
    try std.testing.expectError(error.InvalidSsz, decodeRaw(alloc, raw));

    var bad_optional: [9]u8 = @splat(0);
    putU32(&bad_optional, 0, FORK_ACTIVATION_FIXED_SIZE);
    putU32(&bad_optional, 4, FORK_ACTIVATION_FIXED_SIZE);
    try std.testing.expectError(error.InvalidSsz, decodeForkActivation(&bad_optional));
}
