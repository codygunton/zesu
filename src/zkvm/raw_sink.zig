//! Separate anti-DCE consumer for the lossless raw-SSZ decoder object.
//!
//! This object intentionally imports only the raw type definitions and obtains
//! the decoder result through an extern accessor. Its checksum is an adapter
//! diagnostic, not parser semantics or differential evidence.

const raw = @import("ssz_raw");

extern fn zesu_raw_result() callconv(.c) ?*const raw.RawStatelessInput;

/// Consume the complete result across an object-file boundary. Returning the
/// accumulator makes every field and every pointed-to byte observable to the
/// caller while keeping this adapter outside the decoder ownership bucket.
pub export fn zesu_raw_sink_checksum() callconv(.c) u64 {
    const result = zesu_raw_result() orelse return 0;
    return checksum(result);
}

pub fn checksum(result: *const raw.RawStatelessInput) u64 {
    var state: u64 = 0x9e37_79b9_7f4a_7c15;

    consumeNewPayloadRequest(&state, &result.new_payload_request);
    consumeWitness(&state, &result.witness);
    consumeChainConfig(&state, &result.chain_config);
    consumePublicKeys(&state, result.public_keys);
    return state;
}

fn mixByte(state: *u64, byte: u8) void {
    // Deliberately simple and non-cryptographic: this only blocks dead-code
    // elimination and provides a value-sensitive smoke-test observable.
    state.* +%= @as(u64, byte) +% 0x9d;
    state.* = (state.* << 7) | (state.* >> 57);
    state.* ^= 0xa076_1d64_78bd_642f;
}

fn consumeU64(state: *u64, value: u64) void {
    for (0..8) |index| {
        const shift: u6 = @intCast(index * 8);
        mixByte(state, @truncate(value >> shift));
    }
}

fn consumeU256(state: *u64, value: u256) void {
    // A bitcast keeps this sink freestanding: scalar shifts on `u256` would
    // otherwise introduce compiler-rt helper calls into the adapter object.
    // RISC-V is little-endian, matching the SSZ integer representation here.
    const bytes: [32]u8 = @bitCast(value);
    consumeBytes(state, bytes[0..]);
}

fn consumeBytes(state: *u64, bytes: []const u8) void {
    consumeU64(state, bytes.len);
    for (bytes) |byte| mixByte(state, byte);
}

fn consumeByteSliceList(state: *u64, values: []const []const u8) void {
    // Length observes the outer list descriptor; each element call observes
    // its descriptor and all referenced bytes.
    consumeU64(state, values.len);
    for (values) |value| consumeBytes(state, value);
}

fn consumeNewPayloadRequest(state: *u64, value: *const raw.RawNewPayloadRequest) void {
    consumeExecutionPayload(state, &value.execution_payload);
    consumeVersionedHashes(state, value.versioned_hashes);
    consumeBytes(state, value.parent_beacon_block_root[0..]);
    consumeExecutionRequests(state, &value.execution_requests);
}

fn consumeExecutionPayload(state: *u64, value: *const raw.RawExecutionPayload) void {
    consumeBytes(state, value.parent_hash[0..]);
    consumeBytes(state, value.fee_recipient[0..]);
    consumeBytes(state, value.state_root[0..]);
    consumeBytes(state, value.receipts_root[0..]);
    consumeBytes(state, value.logs_bloom[0..]);
    consumeBytes(state, value.prev_randao[0..]);
    consumeU64(state, value.block_number);
    consumeU64(state, value.gas_limit);
    consumeU64(state, value.gas_used);
    consumeU64(state, value.timestamp);
    consumeBytes(state, value.extra_data);
    consumeU256(state, value.base_fee_per_gas);
    consumeBytes(state, value.block_hash[0..]);
    consumeByteSliceList(state, value.transactions);
    consumeWithdrawals(state, value.withdrawals);
    consumeU64(state, value.blob_gas_used);
    consumeU64(state, value.excess_blob_gas);
    consumeBytes(state, value.block_access_list);
    consumeU64(state, value.slot_number);
}

fn consumeWithdrawals(state: *u64, values: []const raw.RawWithdrawal) void {
    consumeU64(state, values.len);
    for (values) |value| {
        consumeU64(state, value.index);
        consumeU64(state, value.validator_index);
        consumeBytes(state, value.address[0..]);
        consumeU64(state, value.amount);
    }
}

fn consumeVersionedHashes(state: *u64, values: []const [32]u8) void {
    consumeU64(state, values.len);
    for (values) |value| consumeBytes(state, value[0..]);
}

fn consumeExecutionRequests(state: *u64, value: *const raw.RawExecutionRequests) void {
    consumeDepositRequests(state, value.deposits);
    consumeWithdrawalRequests(state, value.withdrawals);
    consumeConsolidationRequests(state, value.consolidations);
}

fn consumeDepositRequests(state: *u64, values: []const raw.RawDepositRequest) void {
    consumeU64(state, values.len);
    for (values) |value| {
        consumeBytes(state, value.pubkey[0..]);
        consumeBytes(state, value.withdrawal_credentials[0..]);
        consumeU64(state, value.amount);
        consumeBytes(state, value.signature[0..]);
        consumeU64(state, value.index);
    }
}

fn consumeWithdrawalRequests(state: *u64, values: []const raw.RawWithdrawalRequest) void {
    consumeU64(state, values.len);
    for (values) |value| {
        consumeBytes(state, value.source_address[0..]);
        consumeBytes(state, value.validator_pubkey[0..]);
        consumeU64(state, value.amount);
    }
}

fn consumeConsolidationRequests(state: *u64, values: []const raw.RawConsolidationRequest) void {
    consumeU64(state, values.len);
    for (values) |value| {
        consumeBytes(state, value.source_address[0..]);
        consumeBytes(state, value.source_pubkey[0..]);
        consumeBytes(state, value.target_pubkey[0..]);
    }
}

fn consumeWitness(state: *u64, value: *const raw.RawExecutionWitness) void {
    consumeByteSliceList(state, value.state);
    consumeByteSliceList(state, value.codes);
    consumeByteSliceList(state, value.headers);
}

fn consumeChainConfig(state: *u64, value: *const raw.RawChainConfig) void {
    consumeU64(state, value.chain_id);
    consumeU64(state, value.active_fork.fork);
    consumeOptionalU64(state, value.active_fork.activation.block_number);
    consumeOptionalU64(state, value.active_fork.activation.timestamp);
    consumeOptionalBlobSchedule(state, value.active_fork.blob_schedule);
}

fn consumeOptionalU64(state: *u64, value: ?u64) void {
    if (value) |present| {
        mixByte(state, 1);
        consumeU64(state, present);
    } else {
        mixByte(state, 0);
    }
}

fn consumeOptionalBlobSchedule(state: *u64, value: ?raw.RawBlobSchedule) void {
    if (value) |present| {
        mixByte(state, 1);
        consumeU64(state, present.target);
        consumeU64(state, present.max);
        consumeU64(state, present.base_fee_update_fraction);
    } else {
        mixByte(state, 0);
    }
}

fn consumePublicKeys(state: *u64, values: []const [raw.PUBLIC_KEY_SIZE]u8) void {
    consumeU64(state, values.len);
    for (values) |value| consumeBytes(state, value[0..]);
}
