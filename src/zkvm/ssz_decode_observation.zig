//! Canonical observation of the complete result produced by the SSZ decode endpoint.
//!
//! The stream starts with `ZSSZ`, format version 1, and a success byte. Every variable-length value
//! and list is prefixed by its little-endian u64 length; optionals use a zero/one byte tag. Fixed-size
//! byte arrays and integers have their type-defined width. This makes the stream injective for the
//! current `StatelessInput` representation without introducing a second SSZ implementation.

const std = @import("std");
const input = @import("input");
const zkvm_io = @import("zkvm_io");

const prefix = "ZSSZ" ++ [_]u8{1};

const Encoder = struct {
    fn raw(value: []const u8) void {
        zkvm_io.write_output(value);
    }

    fn int(comptime T: type, value: T) void {
        var encoded: [@sizeOf(T)]u8 = undefined;
        std.mem.writeInt(T, &encoded, value, .little);
        raw(&encoded);
    }

    fn boolean(value: bool) void {
        raw(&.{@intFromBool(value)});
    }

    fn bytes(value: []const u8) void {
        int(u64, value.len);
        raw(value);
    }

    fn optionalU64(value: ?u64) void {
        if (value) |present| {
            boolean(true);
            int(u64, present);
        } else {
            boolean(false);
        }
    }

    fn optionalU128(value: ?u128) void {
        if (value) |present| {
            boolean(true);
            int(u128, present);
        } else {
            boolean(false);
        }
    }

    fn optionalAddress(value: ?[20]u8) void {
        if (value) |present| {
            boolean(true);
            raw(&present);
        } else {
            boolean(false);
        }
    }

    fn accessList(value: []const input.AccessListEntry) void {
        int(u64, value.len);
        for (value) |entry| {
            raw(&entry.address);
            int(u64, entry.storage_keys.len);
            for (entry.storage_keys) |key| raw(&key);
        }
    }

    fn authorizations(value: []const input.AuthorizationTuple) void {
        int(u64, value.len);
        for (value) |authorization| {
            int(u256, authorization.chain_id);
            raw(&authorization.address);
            int(u64, authorization.nonce);
            int(u64, authorization.v);
            int(u256, authorization.r);
            int(u256, authorization.s);
        }
    }

    fn transactions(value: []const input.Transaction) void {
        int(u64, value.len);
        for (value) |transaction| {
            int(u8, transaction.tx_type);
            optionalU64(transaction.chain_id);
            int(u64, transaction.nonce);
            int(u128, transaction.gas_price);
            optionalU128(transaction.gas_priority_fee);
            int(u64, transaction.gas_limit);
            optionalAddress(transaction.to);
            int(u256, transaction.value);
            bytes(transaction.data);
            accessList(transaction.access_list);
            int(u64, transaction.blob_hashes.len);
            for (transaction.blob_hashes) |hash| raw(&hash);
            int(u128, transaction.max_fee_per_blob_gas);
            authorizations(transaction.authorization_list);
            int(u64, transaction.v);
            int(u256, transaction.r);
            int(u256, transaction.s);
        }
    }

    fn byteLists(value: []const []const u8) void {
        int(u64, value.len);
        for (value) |item| bytes(item);
    }

    fn withdrawals(value: []const input.Withdrawal) void {
        int(u64, value.len);
        for (value) |withdrawal| {
            int(u64, withdrawal.index);
            int(u64, withdrawal.validator_index);
            raw(&withdrawal.address);
            int(u64, withdrawal.amount);
        }
    }

    fn hashes(value: []const [32]u8) void {
        int(u64, value.len);
        for (value) |hash| raw(&hash);
    }
};

pub noinline fn writeFailure() void {
    Encoder.raw(prefix ++ [_]u8{0});
}

pub noinline fn writeSuccess(decoded: input.StatelessInput) void {
    Encoder.raw(prefix ++ [_]u8{1});

    const request = decoded.new_payload_request;
    const payload = request.execution_payload;
    Encoder.raw(&payload.parent_hash);
    Encoder.raw(&payload.fee_recipient);
    Encoder.raw(&payload.state_root);
    Encoder.raw(&payload.receipts_root);
    Encoder.raw(&payload.logs_bloom);
    Encoder.raw(&payload.prev_randao);
    Encoder.int(u64, payload.block_number);
    Encoder.int(u64, payload.gas_limit);
    Encoder.int(u64, payload.gas_used);
    Encoder.int(u64, payload.timestamp);
    Encoder.bytes(payload.extra_data);
    Encoder.int(u64, payload.base_fee_per_gas);
    Encoder.raw(&payload.block_hash);
    Encoder.transactions(payload.transactions);
    Encoder.byteLists(payload.raw_transactions);
    Encoder.withdrawals(payload.withdrawals);
    Encoder.int(u64, payload.blob_gas_used);
    Encoder.int(u64, payload.excess_blob_gas);
    Encoder.optionalU64(payload.slot_number);
    Encoder.bytes(payload.block_access_list);

    Encoder.raw(&request.parent_beacon_block_root);
    Encoder.hashes(request.versioned_hashes);
    Encoder.bytes(request.execution_requests.deposits);
    Encoder.bytes(request.execution_requests.withdrawals);
    Encoder.bytes(request.execution_requests.consolidations);
    Encoder.bytes(request.execution_requests.builder_deposits);
    Encoder.bytes(request.execution_requests.builder_exits);

    Encoder.byteLists(decoded.witness.nodes);
    Encoder.byteLists(decoded.witness.codes);
    Encoder.byteLists(decoded.witness.headers);

    Encoder.int(u64, decoded.chain_config.chain_id);
    if (decoded.chain_config.fork_name) |fork_name| {
        Encoder.boolean(true);
        Encoder.bytes(fork_name);
    } else {
        Encoder.boolean(false);
    }
    Encoder.int(u64, decoded.chain_config.active_fork_idx);
    Encoder.optionalU64(decoded.chain_config.activation_block);
    Encoder.optionalU64(decoded.chain_config.activation_timestamp);
    Encoder.byteLists(decoded.public_keys);
}
