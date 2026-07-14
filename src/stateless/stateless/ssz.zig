//! Manual SSZ decoder for SszStatelessInput (Amsterdam stateless block execution).
//!
//! Implements the schema from stateless_ssz.py without any external SSZ library.
//! All container offsets are relative to the start of each container's byte slice.
//!
//! Container layouts (fixed region sizes):
//!   SszStatelessInput:    16 bytes  [4+4+4+4] all-variable (v0.4.1)
//!   SszNewPayloadRequest: 44 bytes  [4+4+32+4]
//!   SszExecutionPayload: 540 bytes  (see EP_FIXED_SIZE)
//!   SszExecutionWitness:  12 bytes  [4+4+4]
//!   SszWithdrawal:        44 bytes  fixed (8+8+20+8)

const std = @import("std");
const input_mod = @import("input");
const rlp_decode = @import("rlp_decode");
const raw_ssz = @import("ssz_raw.zig");

// ── Primitive reads (little-endian) ──────────────────────────────────────────

inline fn readU32(data: []const u8, off: usize) u32 {
    return std.mem.readInt(u32, data[off..][0..4], .little);
}

inline fn readU64(data: []const u8, off: usize) u64 {
    return std.mem.readInt(u64, data[off..][0..8], .little);
}

// ── Fork enum (glamsterdam-devnet-6 / zkevm@v0.5.0) ──────────────────────────────────

/// ProtocolFork enum values from execution-specs amsterdam stateless.py.
/// Indices are assigned by PROTOCOL_FORKS = tuple(ProtocolFork) and used by
/// SszForkConfig.fork in the SSZ-encoded SszChainConfig. The string returned
/// here matches what zesu's spec resolver (fork.specForBlock) expects.
fn forkNameFromIndex(idx: u64) []const u8 {
    return switch (idx) {
        0 => "Frontier",
        1 => "Homestead",
        2 => "DAOFork",
        3 => "TangerineWhistle",
        4 => "SpuriousDragon",
        5 => "Byzantium",
        // glamsterdam-devnet-6 / zkevm@v0.5.0: PR#2926 removed ConstantinopleFix (merged into
        // StPetersburg at index 6) and BPO3-5; all indices from 7 onwards shift by -1 vs v0.4.1.
        6 => "StPetersburg",
        7 => "Istanbul",
        8 => "MuirGlacier",
        9 => "Berlin",
        10 => "London",
        11 => "ArrowGlacier",
        12 => "GrayGlacier",
        13 => "Paris",
        14 => "Shanghai",
        15 => "Cancun",
        16 => "Prague",
        17 => "Osaka",
        18 => "BPO1",
        19 => "BPO2",
        20 => "Amsterdam",
        else => "",
    };
}

// ── List[ByteList] decoder ────────────────────────────────────────────────────

/// Decode SSZ `List[ByteList[...], N]` from raw bytes.
/// The encoding is: N×4-byte LE offsets followed by concatenated element data.
/// Element i spans [off[i], off[i+1]) with off[N] = data.len.
/// Returns zero-copy slices pointing into `data`.
fn decodeByteListList(alloc: std.mem.Allocator, data: []const u8) ![]const []const u8 {
    if (data.len == 0) return &.{};
    if (data.len < 4) return error.InvalidSsz;

    const first_off = readU32(data, 0);
    // first_off == 4*N (size of the offset table itself)
    if (first_off == 0 or first_off % 4 != 0) return error.InvalidSsz;
    if (first_off > data.len) return error.InvalidSsz;
    const n = first_off / 4;

    const result = try alloc.alloc([]const u8, n);

    for (0..n) |i| {
        const off_i = readU32(data, i * 4);
        const end_i: u32 = if (i + 1 < n) readU32(data, (i + 1) * 4) else blk: {
            if (data.len > std.math.maxInt(u32)) return error.InvalidSsz;
            break :blk @intCast(data.len);
        };
        if (off_i > data.len or end_i > data.len or off_i > end_i) return error.InvalidSsz;
        result[i] = data[off_i..end_i];
    }

    return result;
}

// ── SszWithdrawal decoder ─────────────────────────────────────────────────────

/// SszWithdrawal fixed size: index(8) + validator_index(8) + address(20) + amount(uint64=8) = 44
const WITHDRAWAL_SIZE: usize = 44;

fn decodeWithdrawal(bytes: *const [WITHDRAWAL_SIZE]u8) input_mod.Withdrawal {
    const index = std.mem.readInt(u64, bytes[0..8], .little);
    const validator_index = std.mem.readInt(u64, bytes[8..16], .little);
    var address: [20]u8 = undefined;
    @memcpy(&address, bytes[16..36]);
    const amount = std.mem.readInt(u64, bytes[36..44], .little);
    return .{
        .index = index,
        .validator_index = validator_index,
        .address = address,
        .amount = amount,
    };
}

// ── Top-level decoder ─────────────────────────────────────────────────────────

/// SszExecutionPayload fixed region byte offsets:
///   [0..32]    parent_hash
///   [32..52]   fee_recipient
///   [52..84]   state_root
///   [84..116]  receipts_root
///   [116..372] logs_bloom
///   [372..404] prev_randao
///   [404..412] block_number
///   [412..420] gas_limit
///   [420..428] gas_used
///   [428..436] timestamp
///   [436..440] → extra_data (variable offset)
///   [440..472] base_fee_per_gas (uint256 LE)
///   [472..504] block_hash (ignored)
///   [504..508] → transactions (variable offset)
///   [508..512] → withdrawals (variable offset)
///   [512..520] blob_gas_used
///   [520..528] excess_blob_gas
///   [528..532] → block_access_list (variable offset, ignored)
///   [532..540] slot_number
const EP_FIXED_SIZE: usize = 540;

/// Decode an SSZ-serialized SszStatelessInput into a StatelessInput.
///
/// Supports two input layouts, detected in order:
///
/// 1. Ere-prefixed (4-byte u32 LE length prefix prepended by `Input::with_prefixed_stdin`):
///    stripped when declared length matches remaining bytes, then format re-detected.
///
/// 2. v0.4.1 layout (2-byte big-endian schema_id 0x0001 + 16-byte all-variable container):
///    [0..2]   schema_id (0x0001 BE)
///    [2..6]   offset → new_payload_request
///    [6..10]  offset → witness
///    [10..14] offset → chain_config (SszChainConfig: chain_id + SszForkConfig)
///    [14..18] offset → public_keys (packed ByteVector[65])
fn decodeLegacy(alloc: std.mem.Allocator, data: []const u8) !input_mod.StatelessInput {
    // Strip Ere's 4-byte LE length prefix when present. The first 4 bytes of
    // raw SSZ are always a small offset value, so matching against data.len-4
    // is unambiguous for any real payload.
    const payload = if (data.len >= 4 and
        std.mem.readInt(u32, data[0..4], .little) == data.len - 4)
        data[4..]
    else
        data;

    // Require v0.4.1 schema_id prefix (0x00 0x01 big-endian).
    if (payload.len < 2 or payload[0] != 0x00 or payload[1] != 0x01) return error.InvalidSsz;

    // ── v0.4.1: schema_id prefix + 16-byte all-variable container ────────────
    const body = payload[2..];
    if (body.len < 16) return error.InvalidSsz;
    const off_npr: usize = readU32(body, 0);
    const off_witness: usize = readU32(body, 4);
    const off_chain_config: usize = readU32(body, 8);
    const off_pubkeys: usize = readU32(body, 12);

    if (off_npr != 16 or off_witness > body.len or off_chain_config > body.len or off_pubkeys > body.len) return error.InvalidSsz;
    if (off_npr > off_witness or off_witness > off_chain_config or off_chain_config > off_pubkeys) return error.InvalidSsz;

    const chain_config_data = body[off_chain_config..off_pubkeys];

    // SszChainConfig: chain_id (uint64 LE) + offset → active_fork + SszForkConfig
    //   active_fork[0..8] = fork enum index (ProtocolFork, see forkNameFromIndex)
    if (chain_config_data.len < 12) return error.InvalidSsz;
    const chain_id = readU64(chain_config_data, 0);
    const off_active_fork: usize = readU32(chain_config_data, 8);
    if (off_active_fork + 8 > chain_config_data.len) return error.InvalidSsz;
    const fork_idx: u64 = readU64(chain_config_data, off_active_fork);

    // SszForkConfig: fork uint64 [0..8], activation offset [8..12], blob_schedule offset [12..16].
    // SszForkActivation: block_number list offset [0..4], timestamp list offset [4..8]; each
    // SszOptional list is 0 bytes (None) or 8 bytes (a single uint64). Decode the activation so
    // EIP-8025 chain-config validation can reject a fork not yet active for the target payload.
    var activation_block: ?u64 = null;
    var activation_timestamp: ?u64 = null;
    if (off_active_fork + 16 <= chain_config_data.len) {
        const af = chain_config_data[off_active_fork..];
        const off_activation: usize = readU32(af, 8);
        const off_blob_sched: usize = readU32(af, 12);
        if (off_activation + 8 <= off_blob_sched and off_blob_sched <= af.len) {
            const act = af[off_activation..off_blob_sched];
            const off_bn: usize = readU32(act, 0);
            const off_ts: usize = readU32(act, 4);
            if (off_bn <= off_ts and off_ts <= act.len) {
                if (off_ts - off_bn >= 8) activation_block = readU64(act, off_bn);
                if (act.len - off_ts >= 8) activation_timestamp = readU64(act, off_ts);
            }
        }
    }

    const fork_name_bytes = forkNameFromIndex(fork_idx);
    const npr_data = body[off_npr..off_witness];
    const witness_data = body[off_witness..off_chain_config];
    const pubkeys_data = body[off_pubkeys..];

    // ── SszNewPayloadRequest fixed region (44 bytes) ──────────────────────────
    // [0..4]   offset → execution_payload (variable)
    // [4..8]   offset → versioned_hashes (variable)
    // [8..40]  parent_beacon_block_root: Bytes32 (fixed inline)
    // [40..44] offset → execution_requests (variable)
    if (npr_data.len < 44) return error.InvalidSsz;
    const off_ep: usize = readU32(npr_data, 0);
    const off_vh: usize = readU32(npr_data, 4);
    const off_er: usize = readU32(npr_data, 40);

    var parent_beacon_root: [32]u8 = undefined;
    @memcpy(&parent_beacon_root, npr_data[8..40]);

    if (off_ep < 44 or off_vh > npr_data.len or off_er > npr_data.len) return error.InvalidSsz;
    if (off_ep >= off_vh or off_vh > off_er) return error.InvalidSsz;

    const ep_data = npr_data[off_ep..off_vh];

    // versioned_hashes: List[Bytes32, 4096] — packed 32-byte elements (no offset table)
    const vh_bytes = npr_data[off_vh..off_er];
    if (vh_bytes.len % 32 != 0) return error.InvalidSsz;
    const vh_count = vh_bytes.len / 32;
    const versioned_hashes = try alloc.alloc([32]u8, vh_count);
    for (0..vh_count) |i| @memcpy(&versioned_hashes[i], vh_bytes[i * 32 ..][0..32]);

    // execution_requests: SszExecutionRequests container (3 variable fields, 12-byte fixed region)
    const er_data = npr_data[off_er..];
    if (er_data.len < 12) return error.InvalidSsz;
    const off_deposits: usize = readU32(er_data, 0);
    const off_withdrawals_req: usize = readU32(er_data, 4);
    const off_consolidations: usize = readU32(er_data, 8);
    if (off_deposits != 12) return error.InvalidSsz;
    if (off_deposits > off_withdrawals_req or off_withdrawals_req > off_consolidations or off_consolidations > er_data.len) return error.InvalidSsz;
    const execution_requests: input_mod.ExecutionRequests = .{
        .deposits = er_data[off_deposits..off_withdrawals_req],
        .withdrawals = er_data[off_withdrawals_req..off_consolidations],
        .consolidations = er_data[off_consolidations..],
    };

    // ── SszExecutionPayload fixed region ─────────────────────────────────────────
    // V3 EP (Prague/Osaka): 528B fixed, off_extra_data == 528. No block_access_list or slot_number.
    // V4 EP (Amsterdam+):  540B fixed, off_extra_data == 540. Adds both fields.
    // Detect by the extra_data offset value, which always equals the fixed-region size.
    const EP_V3_FIXED_SIZE: usize = 528;
    if (ep_data.len < EP_V3_FIXED_SIZE) return error.InvalidSsz;

    var parent_hash: [32]u8 = undefined;
    @memcpy(&parent_hash, ep_data[0..32]);

    var fee_recipient: [20]u8 = undefined;
    @memcpy(&fee_recipient, ep_data[32..52]);

    var state_root: [32]u8 = undefined;
    @memcpy(&state_root, ep_data[52..84]);

    var receipts_root: [32]u8 = undefined;
    @memcpy(&receipts_root, ep_data[84..116]);

    var logs_bloom: [256]u8 = undefined;
    @memcpy(&logs_bloom, ep_data[116..372]);

    var prev_randao: [32]u8 = undefined;
    @memcpy(&prev_randao, ep_data[372..404]);

    const block_number: u64 = readU64(ep_data, 404);
    const gas_limit: u64 = readU64(ep_data, 412);
    const gas_used: u64 = readU64(ep_data, 420);
    const timestamp: u64 = readU64(ep_data, 428);

    const off_extra_data: usize = readU32(ep_data, 436);
    // base_fee_per_gas: uint256 LE — low 8 bytes give the u64 value
    const base_fee_per_gas: u64 = readU64(ep_data, 440);
    var block_hash: [32]u8 = undefined;
    @memcpy(&block_hash, ep_data[472..504]);
    // block_hash at [472..504] — not used for execution but needed for SSZ hash_tree_root
    const off_transactions: usize = readU32(ep_data, 504);
    const off_withdrawals: usize = readU32(ep_data, 508);
    const blob_gas_used: u64 = readU64(ep_data, 512);
    const excess_blob_gas: u64 = readU64(ep_data, 520);

    // V4-specific fields (Amsterdam+); use sentinel/null for V3.
    const ep_is_amsterdam = (off_extra_data == EP_FIXED_SIZE);
    const ep_is_v3 = (off_extra_data == EP_V3_FIXED_SIZE);
    if (!ep_is_amsterdam and !ep_is_v3) return error.InvalidSsz;
    if (ep_is_amsterdam and ep_data.len < EP_FIXED_SIZE) return error.InvalidSsz;
    // For V3, sentinel points past all variable data so block_access_list comes out empty.
    const off_block_access_list: usize = if (ep_is_amsterdam) readU32(ep_data, 528) else ep_data.len;
    const slot_number: ?u64 = if (ep_is_amsterdam) readU64(ep_data, 532) else null;

    // Validate variable-field offsets (must be ascending and in range)
    if (off_extra_data > off_transactions or off_transactions > off_withdrawals or
        off_withdrawals > off_block_access_list) return error.InvalidSsz;
    if (off_block_access_list > ep_data.len) return error.InvalidSsz;

    // extra_data: ByteList[32] — raw bytes (not an offset-table list)
    const extra_data = try alloc.dupe(u8, ep_data[off_extra_data..off_transactions]);

    // transactions: List[ByteList, N] — offset-table format
    const txs_raw = try decodeByteListList(alloc, ep_data[off_transactions..off_withdrawals]);
    const transactions = try alloc.alloc(input_mod.Transaction, txs_raw.len);
    for (txs_raw, 0..) |raw_tx, i| {
        transactions[i] = try rlp_decode.decodeSingleTx(alloc, raw_tx);
    }

    // block_access_list: last variable field (V4 only; empty for V3 via sentinel offset).
    const block_access_list = try alloc.dupe(u8, ep_data[off_block_access_list..]);

    // withdrawals: List[SszWithdrawal, N] — packed fixed-size items (no offset table).
    // off_block_access_list acts as the end sentinel for V3 (== ep_data.len).
    const wd_bytes = ep_data[off_withdrawals..off_block_access_list];
    if (wd_bytes.len % WITHDRAWAL_SIZE != 0) return error.InvalidSsz;
    const wcount = wd_bytes.len / WITHDRAWAL_SIZE;
    const withdrawals = try alloc.alloc(input_mod.Withdrawal, wcount);
    for (0..wcount) |i| {
        withdrawals[i] = decodeWithdrawal(wd_bytes[i * WITHDRAWAL_SIZE ..][0..WITHDRAWAL_SIZE]);
    }

    // ── SszExecutionWitness fixed region (12 bytes) ───────────────────────────
    // [0..4]  offset → state (variable)
    // [4..8]  offset → codes (variable)
    // [8..12] offset → headers (variable)
    if (witness_data.len < 12) return error.InvalidSsz;
    const off_state: usize = readU32(witness_data, 0);
    const off_codes: usize = readU32(witness_data, 4);
    const off_headers: usize = readU32(witness_data, 8);

    if (off_state < 12 or off_headers > witness_data.len) return error.InvalidSsz;
    if (off_state > off_codes or off_codes > off_headers) return error.InvalidSsz;

    const nodes = try decodeByteListList(alloc, witness_data[off_state..off_codes]);
    const codes = try decodeByteListList(alloc, witness_data[off_codes..off_headers]);
    const headers = try decodeByteListList(alloc, witness_data[off_headers..]);

    // ── Public keys: List[ByteVector[65], N] (glamsterdam-devnet-6 / zkevm@v0.5.0) ────
    // Pre-recovered secp256k1 public keys, one per transaction in order.
    // SSZ schema is now SszList[ByteVector[PUBLIC_KEY_BYTES=65], MAX_PUBLIC_KEYS],
    // i.e. fixed-size elements → encoded as packed 65-byte chunks (no offset table).
    // Each key is uncompressed (0x04 || X || Y, 65 bytes). transition.zig peels the
    // 0x04 prefix to derive the 64-byte form used for address recovery.
    const PUBKEY_SIZE: usize = 65;
    if (pubkeys_data.len % PUBKEY_SIZE != 0) return error.InvalidSsz;
    const pubkey_count = pubkeys_data.len / PUBKEY_SIZE;
    const public_keys = try alloc.alloc([]const u8, pubkey_count);
    for (0..pubkey_count) |i| {
        public_keys[i] = pubkeys_data[i * PUBKEY_SIZE ..][0..PUBKEY_SIZE];
    }

    // ── Assemble StatelessInput ───────────────────────────────────────────────
    return input_mod.StatelessInput{
        .new_payload_request = .{
            .execution_payload = .{
                .parent_hash = parent_hash,
                .fee_recipient = fee_recipient,
                .state_root = state_root, // POST-execution (for output verification)
                .receipts_root = receipts_root,
                .logs_bloom = logs_bloom,
                .prev_randao = prev_randao,
                .block_number = block_number,
                .gas_limit = gas_limit,
                .gas_used = gas_used,
                .timestamp = timestamp,
                .extra_data = extra_data,
                .base_fee_per_gas = base_fee_per_gas,
                .block_hash = block_hash,
                .transactions = transactions,
                .raw_transactions = txs_raw,
                .withdrawals = withdrawals,
                .blob_gas_used = blob_gas_used,
                .excess_blob_gas = excess_blob_gas,
                .slot_number = slot_number,
                .block_access_list = block_access_list,
            },
            .parent_beacon_block_root = parent_beacon_root,
            .versioned_hashes = versioned_hashes,
            .execution_requests = execution_requests,
        },
        .witness = .{
            .nodes = nodes,
            .codes = codes,
            .headers = headers,
        },
        .chain_config = .{
            .chain_id = if (chain_id != 0) chain_id else 1,
            .fork_name = if (fork_name_bytes.len > 0) fork_name_bytes else null,
            .active_fork_idx = fork_idx,
            .activation_block = activation_block,
            .activation_timestamp = activation_timestamp,
        },
        .public_keys = public_keys,
    };
}

/// Decode a complete Amsterdam V4 SSZ value without runtime projection, RLP
/// conversion, or normalization. This is the semantic parser rooted by the
/// RV64 measurement object and the host-only value differential adapter.
pub fn decodeRaw(
    alloc: std.mem.Allocator,
    data: []const u8,
) raw_ssz.DecodeError!raw_ssz.RawStatelessInput {
    return raw_ssz.decode(alloc, data);
}

/// Decode a production runtime input. V4 always goes through the lossless raw
/// parser first; V3 is retained only as explicitly detected legacy execution
/// compatibility because no matching independent V3 oracle is pinned.
pub fn decode(alloc: std.mem.Allocator, data: []const u8) !input_mod.StatelessInput {
    const raw_value = decodeRaw(alloc, data) catch |err| {
        if (looksLikeLegacyV3(data)) return decodeLegacy(alloc, data);
        return err;
    };
    return adaptToRuntime(alloc, raw_value);
}

fn looksLikeLegacyV3(data: []const u8) bool {
    const payload = legacyPayload(data) orelse return false;
    if (payload.len < 2 or payload[0] != raw_ssz.schema_id[0] or payload[1] != raw_ssz.schema_id[1]) {
        return false;
    }
    const body = payload[2..];
    if (body.len < 16) return false;
    const new_payload_offset = readU32At(body, 0) orelse return false;
    const witness_offset = readU32At(body, 4) orelse return false;
    if (new_payload_offset != 16 or new_payload_offset > witness_offset or witness_offset > body.len) {
        return false;
    }
    const request = body[new_payload_offset..witness_offset];
    if (request.len < 44) return false;
    const payload_offset = readU32At(request, 0) orelse return false;
    const hashes_offset = readU32At(request, 4) orelse return false;
    if (payload_offset > hashes_offset or hashes_offset > request.len) return false;
    const execution_payload = request[payload_offset..hashes_offset];
    return execution_payload.len >= 440 and readU32At(execution_payload, 436) == 528;
}

fn legacyPayload(data: []const u8) ?[]const u8 {
    if (data.len >= 2 and data[0] == raw_ssz.schema_id[0] and data[1] == raw_ssz.schema_id[1]) {
        return data;
    }
    if (data.len >= 6 and readU32At(data, 0) == data.len - 4 and
        data[4] == raw_ssz.schema_id[0] and data[5] == raw_ssz.schema_id[1])
    {
        return data[4..];
    }
    return null;
}

fn readU32At(data: []const u8, offset: usize) ?usize {
    if (offset > data.len or data.len - offset < 4) return null;
    return @intCast(std.mem.readInt(u32, data[offset..][0..4], .little));
}

fn adaptPublicKeys(
    alloc: std.mem.Allocator,
    raw_keys: []const [raw_ssz.PUBLIC_KEY_SIZE]u8,
) ![]const []const u8 {
    const runtime_keys = try alloc.alloc([]const u8, raw_keys.len);
    for (raw_keys, 0..) |*key, index| runtime_keys[index] = key[0..];
    return runtime_keys;
}

fn adaptToRuntime(
    alloc: std.mem.Allocator,
    raw_value: raw_ssz.RawStatelessInput,
) !input_mod.StatelessInput {
    const raw_request = raw_value.new_payload_request;
    const raw_payload = raw_request.execution_payload;
    if (raw_payload.base_fee_per_gas > std.math.maxInt(u64)) return error.BaseFeeOutOfRange;

    const transactions = try alloc.alloc(input_mod.Transaction, raw_payload.transactions.len);
    for (raw_payload.transactions, 0..) |transaction, index| {
        transactions[index] = try rlp_decode.decodeSingleTx(alloc, transaction);
    }

    const withdrawals = try alloc.alloc(input_mod.Withdrawal, raw_payload.withdrawals.len);
    for (raw_payload.withdrawals, 0..) |withdrawal, index| {
        withdrawals[index] = .{
            .index = withdrawal.index,
            .validator_index = withdrawal.validator_index,
            .address = withdrawal.address,
            .amount = withdrawal.amount,
        };
    }

    const public_keys = try adaptPublicKeys(alloc, raw_value.public_keys);

    const raw_transactions: []const []const u8 = raw_payload.transactions;
    const versioned_hashes: []const [32]u8 = raw_request.versioned_hashes;
    const witness_state: []const []const u8 = raw_value.witness.state;
    const witness_codes: []const []const u8 = raw_value.witness.codes;
    const witness_headers: []const []const u8 = raw_value.witness.headers;

    return .{
        .new_payload_request = .{
            .execution_payload = .{
                .parent_hash = raw_payload.parent_hash,
                .fee_recipient = raw_payload.fee_recipient,
                .state_root = raw_payload.state_root,
                .receipts_root = raw_payload.receipts_root,
                .logs_bloom = raw_payload.logs_bloom,
                .prev_randao = raw_payload.prev_randao,
                .block_number = raw_payload.block_number,
                .gas_limit = raw_payload.gas_limit,
                .gas_used = raw_payload.gas_used,
                .timestamp = raw_payload.timestamp,
                .extra_data = try alloc.dupe(u8, raw_payload.extra_data),
                .base_fee_per_gas = @intCast(raw_payload.base_fee_per_gas),
                .block_hash = raw_payload.block_hash,
                .transactions = transactions,
                .raw_transactions = raw_transactions,
                .withdrawals = withdrawals,
                .blob_gas_used = raw_payload.blob_gas_used,
                .excess_blob_gas = raw_payload.excess_blob_gas,
                .slot_number = raw_payload.slot_number,
                .block_access_list = try alloc.dupe(u8, raw_payload.block_access_list),
            },
            .parent_beacon_block_root = raw_request.parent_beacon_block_root,
            .versioned_hashes = versioned_hashes,
            .execution_requests = .{
                .deposits = try encodeDepositRequests(alloc, raw_request.execution_requests.deposits),
                .withdrawals = try encodeWithdrawalRequests(alloc, raw_request.execution_requests.withdrawals),
                .consolidations = try encodeConsolidationRequests(alloc, raw_request.execution_requests.consolidations),
            },
        },
        .witness = .{
            .nodes = witness_state,
            .codes = witness_codes,
            .headers = witness_headers,
        },
        .chain_config = .{
            .chain_id = raw_value.chain_config.chain_id,
            .fork_name = forkNameFromIndex(raw_value.chain_config.active_fork.fork),
            .active_fork_idx = raw_value.chain_config.active_fork.fork,
            .activation_block = raw_value.chain_config.active_fork.activation.block_number,
            .activation_timestamp = raw_value.chain_config.active_fork.activation.timestamp,
            .blob_schedule = if (raw_value.chain_config.active_fork.blob_schedule) |schedule| .{
                .target = schedule.target,
                .max = schedule.max,
                .base_fee_update_fraction = schedule.base_fee_update_fraction,
            } else null,
        },
        .public_keys = public_keys,
    };
}

fn encodeDepositRequests(
    alloc: std.mem.Allocator,
    requests: []const raw_ssz.RawDepositRequest,
) ![]const u8 {
    const record_size = 192;
    const bytes = try alloc.alloc(u8, requests.len * record_size);
    for (requests, 0..) |request, index| {
        const offset = index * record_size;
        @memcpy(bytes[offset..][0..48], request.pubkey[0..]);
        @memcpy(bytes[offset + 48 ..][0..32], request.withdrawal_credentials[0..]);
        std.mem.writeInt(u64, bytes[offset + 80 ..][0..8], request.amount, .little);
        @memcpy(bytes[offset + 88 ..][0..96], request.signature[0..]);
        std.mem.writeInt(u64, bytes[offset + 184 ..][0..8], request.index, .little);
    }
    return bytes;
}

fn encodeWithdrawalRequests(
    alloc: std.mem.Allocator,
    requests: []const raw_ssz.RawWithdrawalRequest,
) ![]const u8 {
    const record_size = 76;
    const bytes = try alloc.alloc(u8, requests.len * record_size);
    for (requests, 0..) |request, index| {
        const offset = index * record_size;
        @memcpy(bytes[offset..][0..20], request.source_address[0..]);
        @memcpy(bytes[offset + 20 ..][0..48], request.validator_pubkey[0..]);
        std.mem.writeInt(u64, bytes[offset + 68 ..][0..8], request.amount, .little);
    }
    return bytes;
}

fn encodeConsolidationRequests(
    alloc: std.mem.Allocator,
    requests: []const raw_ssz.RawConsolidationRequest,
) ![]const u8 {
    const record_size = 116;
    const bytes = try alloc.alloc(u8, requests.len * record_size);
    for (requests, 0..) |request, index| {
        const offset = index * record_size;
        @memcpy(bytes[offset..][0..20], request.source_address[0..]);
        @memcpy(bytes[offset + 20 ..][0..48], request.source_pubkey[0..]);
        @memcpy(bytes[offset + 68 ..][0..48], request.target_pubkey[0..]);
    }
    return bytes;
}

test "runtime public keys borrow raw key storage" {
    const raw_keys = try std.testing.allocator.alloc([raw_ssz.PUBLIC_KEY_SIZE]u8, 2);
    defer std.testing.allocator.free(raw_keys);
    @memset(raw_keys[0][0..], 0x11);
    @memset(raw_keys[1][0..], 0x22);
    raw_keys[0][0] = 0x04;
    raw_keys[1][0] = 0x04;

    const runtime_keys = try adaptPublicKeys(std.testing.allocator, raw_keys);
    defer std.testing.allocator.free(runtime_keys);

    try std.testing.expectEqual(@intFromPtr(&raw_keys[0][0]), @intFromPtr(runtime_keys[0].ptr));
    try std.testing.expectEqual(@intFromPtr(&raw_keys[1][0]), @intFromPtr(runtime_keys[1].ptr));

    raw_keys[0][17] = 0xa5;
    raw_keys[1][42] = 0x5a;
    try std.testing.expectEqual(@as(u8, 0xa5), runtime_keys[0][17]);
    try std.testing.expectEqual(@as(u8, 0x5a), runtime_keys[1][42]);
}
