## this file creates a test information hub generates a crypto key pair creates an empty ai pool 
###creates an information hub instance 
## it test hash only storage , hash handeling 
# test pool 

from __future__ import annotations

import time
from datetime import datetime, timezone

import pytest

from podl_chain.crypto import KeyPair, sha256
from podl_chain.hub import InformationHub
from podl_chain.pool import AIPool, PoolItem
from podl_chain.packets import Packet, PacketType
from podl_chain.records import Record, unpack, validate_record


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class DummyWriter:
    def __init__(self):
        self.buffer = b""

    def write(self, data: bytes):
        self.buffer += data

    async def drain(self):
        pass


def make_hub():
    kp = KeyPair.generate()
    pool = AIPool()
    return InformationHub(node_id="test-node", keypair=kp, pool=pool)


def new_data_payload():
    return {
        "data_id_hex": sha256(b"data-1").hex(),
        "content_hash_hex": sha256(b"raw dataset").hex(),
        "policy_hash_hex": sha256(b"policy-1").hex(),
        "storage_ref": "ipfs://data-1",
    }


def new_model_payload():
    return {
        "model_id": "model-1",
        "artifact_hash_hex": sha256(b"model bytes").hex(),
        "storage_ref": "s3://model-1",
    }


def new_proof_payload():
    return {
        "proof_id_hex": sha256(b"proof-1").hex(),
        "base_model_id": "model-1",
        "provider": "openai",
        "endpoint": "test-endpoint",
        "evalset_hash_hex": sha256(b"evalset").hex(),
        "decode_cfg_hash_hex": sha256(b"decode-cfg").hex(),
        "claimed_score_scaled": 9000,
        "score_scale": 10000,
        "artifact_hash_hex": sha256(b"proof artifact").hex(),
        "artifact_ref": "ipfs://proof-1",
    }


def make_unique_data_payload(i: int):
    return {
        "data_id_hex": sha256(f"data-{i}".encode()).hex(),
        "content_hash_hex": sha256(f"raw-dataset-{i}".encode()).hex(),
        "policy_hash_hex": sha256(f"policy-{i}".encode()).hex(),
        "storage_ref": f"ipfs://data-{i}",
    }


@pytest.mark.asyncio
async def test_hash_only_storage_data_record(case_tracker):
    hub = make_hub()
    writer = DummyWriter()

    raw_bytes = b"SECRET RAW DATASET BYTES"
    content_hash = sha256(raw_bytes)

    pkt = Packet(
        ptype=PacketType.NEW_DATA_RECORD,
        sender_id="client-1",
        payload={
            "data_id_hex": sha256(b"data-raw").hex(),
            "content_hash_hex": content_hash.hex(),
            "policy_hash_hex": sha256(b"policy").hex(),
            "storage_ref": "ipfs://offchain-data",
        },
        request_id="req-hash",
    )

    start_ts = utc_now_iso()
    start_perf = time.perf_counter()
    await hub.handle_packet(pkt, writer)

    resp = Packet.from_bytes(writer.buffer.strip())
    actual_passed = resp.ptype == PacketType.PONG and resp.payload["ok"] is True

    case_tracker(
        category="hub",
        expected="valid",
        actual_passed=actual_passed,
        start_perf=start_perf,
        start_ts=start_ts,
        notes="hash-only storage data submission",
    )

    assert resp.ptype == PacketType.PONG
    assert resp.payload["ok"] is True

    item = await hub.pool.get(resp.payload["item_id"])
    assert item is not None

    rec = Record.from_bytes(bytes.fromhex(item.payload["record_hex"]))
    payload_obj = unpack(rec.payload)

    assert "content_hash" in payload_obj
    assert payload_obj["content_hash"] == content_hash
    assert "storage_ref" in payload_obj
    assert "sig" in payload_obj
    assert raw_bytes not in rec.payload
    assert raw_bytes.hex().encode() not in rec.payload


@pytest.mark.asyncio
async def test_hub_accepts_new_data_record(case_tracker):
    hub = make_hub()
    writer = DummyWriter()

    pkt = Packet(
        ptype=PacketType.NEW_DATA_RECORD,
        sender_id="client-1",
        payload=new_data_payload(),
        request_id="req-data",
    )

    start_ts = utc_now_iso()
    start_perf = time.perf_counter()
    await hub.handle_packet(pkt, writer)

    resp = Packet.from_bytes(writer.buffer.strip())
    actual_passed = resp.ptype == PacketType.PONG and resp.payload["ok"] is True

    case_tracker(
        category="hub",
        expected="valid",
        actual_passed=actual_passed,
        start_perf=start_perf,
        start_ts=start_ts,
        notes="hub accepts new data record",
    )

    assert resp.ptype == PacketType.PONG
    assert resp.payload["ok"] is True
    assert "item_id" in resp.payload

    item = await hub.pool.get(resp.payload["item_id"])
    assert item is not None
    assert item.lane == "DATA"
    assert item.rtype == "OWNERSHIP_COMMIT"

    rec = Record.from_bytes(bytes.fromhex(item.payload["record_hex"]))
    ok, _ = validate_record(rec)
    assert ok is True


@pytest.mark.asyncio
async def test_hub_accepts_new_model_record(case_tracker):
    hub = make_hub()
    writer = DummyWriter()

    pkt = Packet(
        ptype=PacketType.NEW_MODEL_RECORD,
        sender_id="client-1",
        payload=new_model_payload(),
        request_id="req-model",
    )

    start_ts = utc_now_iso()
    start_perf = time.perf_counter()
    await hub.handle_packet(pkt, writer)

    resp = Packet.from_bytes(writer.buffer.strip())
    actual_passed = resp.ptype == PacketType.PONG and resp.payload["ok"] is True

    case_tracker(
        category="hub",
        expected="valid",
        actual_passed=actual_passed,
        start_perf=start_perf,
        start_ts=start_ts,
        notes="hub accepts new model record",
    )

    assert resp.ptype == PacketType.PONG
    assert resp.payload["ok"] is True
    assert "item_id" in resp.payload

    item = await hub.pool.get(resp.payload["item_id"])
    assert item is not None
    assert item.lane == "MODEL"
    assert item.rtype == "MODEL_COMMIT"

    rec = Record.from_bytes(bytes.fromhex(item.payload["record_hex"]))
    ok, _ = validate_record(rec)
    assert ok is True


@pytest.mark.asyncio
async def test_hub_accepts_new_proof_record(case_tracker):
    hub = make_hub()
    writer = DummyWriter()

    pkt = Packet(
        ptype=PacketType.NEW_PROOF_RECORD,
        sender_id="client-1",
        payload=new_proof_payload(),
        request_id="req-proof",
    )

    start_ts = utc_now_iso()
    start_perf = time.perf_counter()
    await hub.handle_packet(pkt, writer)

    resp = Packet.from_bytes(writer.buffer.strip())
    actual_passed = resp.ptype == PacketType.PONG and resp.payload["ok"] is True

    case_tracker(
        category="hub",
        expected="valid",
        actual_passed=actual_passed,
        start_perf=start_perf,
        start_ts=start_ts,
        notes="hub accepts new proof record",
    )

    assert resp.ptype == PacketType.PONG
    assert resp.payload["ok"] is True
    assert "item_id" in resp.payload

    item = await hub.pool.get(resp.payload["item_id"])
    assert item is not None
    assert item.lane == "PROOF"
    assert item.rtype == "PODL_LLM_EVAL"

    rec = Record.from_bytes(bytes.fromhex(item.payload["record_hex"]))
    ok, _ = validate_record(rec)
    assert ok is True


@pytest.mark.asyncio
async def test_hub_rejects_missing_field(case_tracker):
    hub = make_hub()
    writer = DummyWriter()

    pkt = Packet(
        ptype=PacketType.NEW_DATA_RECORD,
        sender_id="client-1",
        payload={
            "data_id_hex": sha256(b"bad-data").hex(),
            # missing content_hash_hex on purpose
            "policy_hash_hex": sha256(b"policy").hex(),
            "storage_ref": "ipfs://bad",
        },
        request_id="bad-1",
    )

    start_ts = utc_now_iso()
    start_perf = time.perf_counter()
    await hub.handle_packet(pkt, writer)

    resp = Packet.from_bytes(writer.buffer.strip())
    ok = resp.payload.get("ok") is True

    case_tracker(
        category="hub",
        expected="invalid",
        actual_passed=ok,
        start_perf=start_perf,
        start_ts=start_ts,
        notes="hub rejects payload missing required field",
    )

    assert ok is False


@pytest.mark.asyncio
async def test_hub_rejects_bad_hash_length(case_tracker):
    hub = make_hub()
    writer = DummyWriter()

    pkt = Packet(
        ptype=PacketType.NEW_DATA_RECORD,
        sender_id="client-1",
        payload={
            "data_id_hex": "123",
            "content_hash_hex": "abc",
            "policy_hash_hex": "xyz",
            "storage_ref": "ipfs://bad-hash",
        },
        request_id="bad-2",
    )

    start_ts = utc_now_iso()
    start_perf = time.perf_counter()
    await hub.handle_packet(pkt, writer)

    resp = Packet.from_bytes(writer.buffer.strip())
    ok = resp.payload.get("ok") is True

    case_tracker(
        category="hub",
        expected="invalid",
        actual_passed=ok,
        start_perf=start_perf,
        start_ts=start_ts,
        notes="hub rejects malformed hash lengths",
    )

    assert ok is False


@pytest.mark.asyncio
async def test_pool_adds_new_item(case_tracker):
    pool = AIPool()
    item = PoolItem(
        item_id="one",
        lane="DATA",
        rtype="OWNERSHIP_COMMIT",
        payload={"x": 1},
        ts=100,
    )

    start_ts = utc_now_iso()
    start_perf = time.perf_counter()
    added = await pool.add(item)

    case_tracker(
        category="pool",
        expected="valid",
        actual_passed=added,
        start_perf=start_perf,
        start_ts=start_ts,
        notes="pool add new item",
    )

    assert added is True

    got = await pool.get("one")
    assert got == item


@pytest.mark.asyncio
async def test_pool_rejects_duplicates(case_tracker):
    pool = AIPool()
    item = PoolItem(
        item_id="dup",
        lane="DATA",
        rtype="OWNERSHIP_COMMIT",
        payload={"x": 1},
        ts=100,
    )

    assert await pool.add(item) is True

    start_ts = utc_now_iso()
    start_perf = time.perf_counter()
    second_add = await pool.add(item)

    case_tracker(
        category="pool",
        expected="invalid",
        actual_passed=second_add,
        start_perf=start_perf,
        start_ts=start_ts,
        notes="duplicate item should be rejected",
    )

    assert second_add is False

    items = await pool.list_all()
    assert len(items) == 1


@pytest.mark.asyncio
async def test_pool_removes_items_correctly(case_tracker):
    pool = AIPool()
    item = PoolItem(
        item_id="gone",
        lane="MODEL",
        rtype="MODEL_COMMIT",
        payload={"x": 1},
        ts=100,
    )

    await pool.add(item)
    assert await pool.get("gone") is not None

    start_ts = utc_now_iso()
    start_perf = time.perf_counter()
    await pool.remove("gone")
    removed_ok = await pool.get("gone") is None

    case_tracker(
        category="pool",
        expected="valid",
        actual_passed=removed_ok,
        start_perf=start_perf,
        start_ts=start_ts,
        notes="pool remove item",
    )

    assert removed_ok is True


@pytest.mark.asyncio
async def test_pool_returns_items_in_expected_order(case_tracker):
    pool = AIPool()

    a = PoolItem("a", "DATA", "OWNERSHIP_COMMIT", {}, 300)
    b = PoolItem("b", "MODEL", "MODEL_COMMIT", {}, 100)
    c = PoolItem("c", "PROOF", "PODL_LLM_EVAL", {}, 200)

    await pool.add(a)
    await pool.add(b)
    await pool.add(c)

    start_ts = utc_now_iso()
    start_perf = time.perf_counter()
    selected = await pool.pop_for_block(limit=3)
    order_ok = [x.item_id for x in selected] == ["b", "c", "a"]

    case_tracker(
        category="pool",
        expected="valid",
        actual_passed=order_ok,
        start_perf=start_perf,
        start_ts=start_ts,
        notes="pool ordering for block selection",
    )

    assert order_ok is True

    remaining = await pool.list_all()
    assert remaining == []


@pytest.mark.asyncio
async def test_pool_sync_request_returns_items(case_tracker):
    hub = make_hub()

    await hub.pool.add(PoolItem("1", "DATA", "OWNERSHIP_COMMIT", {"a": 1}, 100))
    await hub.pool.add(PoolItem("2", "MODEL", "MODEL_COMMIT", {"b": 2}, 101))

    writer = DummyWriter()
    pkt = Packet(
        ptype=PacketType.POOL_SYNC_REQUEST,
        sender_id="client-1",
        payload={},
        request_id="sync-1",
    )

    start_ts = utc_now_iso()
    start_perf = time.perf_counter()
    await hub.handle_packet(pkt, writer)

    resp = Packet.from_bytes(writer.buffer.strip())
    sync_ok = (
        resp.ptype == PacketType.POOL_SYNC_RESPONSE
        and len(resp.payload["items"]) == 2
    )

    case_tracker(
        category="hub",
        expected="valid",
        actual_passed=sync_ok,
        start_perf=start_perf,
        start_ts=start_ts,
        notes="pool sync response returns two items",
    )

    assert resp.ptype == PacketType.POOL_SYNC_RESPONSE
    assert "items" in resp.payload
    assert len(resp.payload["items"]) == 2


@pytest.mark.asyncio
async def test_scale_submit_1000_records(case_tracker):
    hub = make_hub()
    total = 1000

    for i in range(total):
        writer = DummyWriter()

        pkt = Packet(
            ptype=PacketType.NEW_DATA_RECORD,
            sender_id=f"client-{i}",
            payload=make_unique_data_payload(i),
            request_id=f"req-{i}",
        )

        start_ts = utc_now_iso()
        start_perf = time.perf_counter()

        await hub.handle_packet(pkt, writer)
        resp = Packet.from_bytes(writer.buffer.strip())

        ok = resp.ptype == PacketType.PONG and resp.payload.get("ok") is True

        case_tracker(
            category="hub",
            expected="valid",
            actual_passed=ok,
            start_perf=start_perf,
            start_ts=start_ts,
            notes=f"scale_hub_1000 idx={i}",
        )

        assert ok is True, f"hub submission {i} failed"

    items = await hub.pool.list_all()
    assert len(items) == total