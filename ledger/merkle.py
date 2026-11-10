"""RFC 6962 domain-separated Merkle Tree and hash-chained immutable audit ledger."""

from __future__ import annotations

import hashlib
import hmac
import json
from datetime import UTC, datetime
from typing import Any

GENESIS_ROOT = "GENESIS_ROOT"
EMPTY_TREE_ROOT = hashlib.sha256(b"").hexdigest()


def hash_leaf(payload: bytes) -> bytes:
    """Compute RFC 6962 domain-separated leaf hash (0x00 || payload)."""
    return hashlib.sha256(b"\x00" + payload).digest()


def hash_node(left: bytes, right: bytes) -> bytes:
    """Compute RFC 6962 domain-separated internal node hash (0x01 || left || right)."""
    return hashlib.sha256(b"\x01" + left + right).digest()


def _largest_power_of_two_less_than(n: int) -> int:
    return 1 << ((n - 1).bit_length() - 1)


def compute_merkle_root(leaf_hashes: list[bytes]) -> bytes:
    """Compute RFC 6962 Merkle Tree Hash (MTH) eliminating duplicate-leaf malleability."""
    n = len(leaf_hashes)
    if n == 0:
        return hashlib.sha256(b"").digest()
    if n == 1:
        return leaf_hashes[0]
    k = _largest_power_of_two_less_than(n)
    return hash_node(
        compute_merkle_root(leaf_hashes[:k]),
        compute_merkle_root(leaf_hashes[k:]),
    )


def build_inclusion_proof(leaf_hashes: list[bytes], index: int) -> list[dict[str, str]]:
    """Build an O(log N) Merkle inclusion proof for the 0-based leaf index."""
    n = len(leaf_hashes)
    if index < 0 or index >= n:
        raise IndexError(f"Leaf index {index} out of range [0, {n})")
    if n <= 1:
        return []

    k = _largest_power_of_two_less_than(n)
    if index < k:
        proof = build_inclusion_proof(leaf_hashes[:k], index)
        proof.append({"position": "right", "sibling": compute_merkle_root(leaf_hashes[k:]).hex()})
        return proof

    proof = build_inclusion_proof(leaf_hashes[k:], index - k)
    proof.append({"position": "left", "sibling": compute_merkle_root(leaf_hashes[:k]).hex()})
    return proof


def verify_inclusion_proof(
    leaf_hash_hex: str,
    proof: list[dict[str, str]],
    expected_root_hex: str,
) -> bool:
    """Verify an RFC 6962 Merkle inclusion proof against an expected root hex digest."""
    try:
        current = bytes.fromhex(leaf_hash_hex)
        expected = bytes.fromhex(expected_root_hex)
        if len(current) != 32 or len(expected) != 32:
            return False

        for step in proof:
            sibling = bytes.fromhex(step["sibling"])
            if len(sibling) != 32:
                return False
            pos = step.get("position")
            if pos == "left":
                current = hash_node(sibling, current)
            elif pos == "right":
                current = hash_node(current, sibling)
            else:
                return False
    except (ValueError, KeyError, TypeError):
        return False

    return hmac.compare_digest(current, expected)


def _canonical_entry_bytes(
    index: int,
    action: str,
    actor: str,
    metadata: dict[str, Any],
    timestamp: str,
    prev_hash: str,
) -> bytes:
    payload = {
        "index": index,
        "action": action,
        "actor": actor,
        "metadata": metadata,
        "timestamp": timestamp,
        "prev_hash": prev_hash,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


class MerkleAuditLedger:
    """Tamper-evident hash-chained audit ledger backed by an RFC 6962 Merkle tree."""

    def __init__(self) -> None:
        self.chain: list[dict[str, Any]] = []

    def append_event(
        self,
        action: str,
        actor: str,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Append a signed audit event and return the sealed entry record."""
        if not action or not action.strip():
            raise ValueError("action must not be empty")
        if not actor or not actor.strip():
            raise ValueError("actor must not be empty")

        index = len(self.chain) + 1
        prev_hash = self.chain[-1]["hash"] if self.chain else GENESIS_ROOT
        ts = datetime.now(UTC).isoformat()
        meta = dict(metadata) if metadata else {}

        canonical = _canonical_entry_bytes(index, action, actor, meta, ts, prev_hash)
        curr_hash = hashlib.sha256(canonical).hexdigest()
        leaf_hash = hash_leaf(canonical).hex()

        entry = {
            "index": index,
            "action": action,
            "actor": actor,
            "metadata": meta,
            "timestamp": ts,
            "prev_hash": prev_hash,
            "hash": curr_hash,
            "leaf_hash": leaf_hash,
        }
        self.chain.append(entry)
        return dict(entry)

    def merkle_root(self) -> str:
        """Return the current RFC 6962 Merkle root hex digest across all entries."""
        if not self.chain:
            return EMPTY_TREE_ROOT
        leaves = [bytes.fromhex(item["leaf_hash"]) for item in self.chain]
        return compute_merkle_root(leaves).hex()

    def get_inclusion_proof(self, index: int) -> dict[str, Any]:
        """Generate a Merkle inclusion proof for a 1-based audit entry index."""
        if index < 1 or index > len(self.chain):
            raise IndexError(f"Audit index {index} out of bounds [1, {len(self.chain)}]")
        leaves = [bytes.fromhex(item["leaf_hash"]) for item in self.chain]
        proof = build_inclusion_proof(leaves, index - 1)
        entry = self.chain[index - 1]
        return {
            "index": index,
            "leaf_hash": entry["leaf_hash"],
            "merkle_root": compute_merkle_root(leaves).hex(),
            "proof": proof,
        }

    def verify_integrity_report(self) -> dict[str, Any]:
        """Recompute every entry hash, leaf hash, and prev_hash link across the ledger."""
        for i, entry in enumerate(self.chain):
            expected_index = i + 1
            expected_prev = self.chain[i - 1]["hash"] if i > 0 else GENESIS_ROOT

            if entry.get("index") != expected_index:
                return {
                    "is_valid": False,
                    "length": len(self.chain),
                    "first_corrupted_index": expected_index,
                    "reason": "Sequence index mismatch",
                }
            if not hmac.compare_digest(str(entry.get("prev_hash", "")), expected_prev):
                return {
                    "is_valid": False,
                    "length": len(self.chain),
                    "first_corrupted_index": expected_index,
                    "reason": "Broken prev_hash chain link",
                }

            try:
                canonical = _canonical_entry_bytes(
                    index=entry["index"],
                    action=entry["action"],
                    actor=entry["actor"],
                    metadata=entry.get("metadata", {}),
                    timestamp=entry["timestamp"],
                    prev_hash=entry["prev_hash"],
                )
            except (KeyError, TypeError) as exc:
                return {
                    "is_valid": False,
                    "length": len(self.chain),
                    "first_corrupted_index": expected_index,
                    "reason": f"Malformed entry fields: {exc}",
                }

            expected_hash = hashlib.sha256(canonical).hexdigest()
            expected_leaf = hash_leaf(canonical).hex()
            if not hmac.compare_digest(str(entry.get("hash", "")), expected_hash) or not hmac.compare_digest(
                str(entry.get("leaf_hash", "")), expected_leaf
            ):
                return {
                    "is_valid": False,
                    "length": len(self.chain),
                    "first_corrupted_index": expected_index,
                    "reason": "Entry payload digest tamper detected",
                }

        return {
            "is_valid": True,
            "length": len(self.chain),
            "merkle_root": self.merkle_root(),
            "first_corrupted_index": None,
            "reason": None,
        }

    def verify_integrity(self) -> bool:
        """Return True iff the entire hash chain and all canonical digests verify cleanly."""
        return bool(self.verify_integrity_report()["is_valid"])
