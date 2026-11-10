from fastapi.testclient import TestClient

from ledger.api import app
from ledger.merkle import (
    EMPTY_TREE_ROOT,
    MerkleAuditLedger,
    hash_leaf,
    hash_node,
    verify_inclusion_proof,
)


def test_ledger() -> None:
    ledger = MerkleAuditLedger()
    assert ledger.merkle_root() == EMPTY_TREE_ROOT
    ledger.append_event("LOGIN", "admin")
    ledger.append_event("GRANT_ROLE", "admin", metadata={"role": "security"})
    assert ledger.verify_integrity() is True


def test_merkle_inclusion_proofs_and_second_preimage_defense() -> None:
    ledger = MerkleAuditLedger()
    for i in range(1, 8):
        ledger.append_event(f"EVENT_{i}", f"user_{i}")

    root = ledger.merkle_root()
    for idx in range(1, 8):
        bundle = ledger.get_inclusion_proof(idx)
        assert bundle["merkle_root"] == root
        assert verify_inclusion_proof(bundle["leaf_hash"], bundle["proof"], root) is True

        # Mutating the leaf digest must invalidate proof verification
        tampered_leaf = ("f" if bundle["leaf_hash"][0] != "f" else "0") + bundle["leaf_hash"][1:]
        assert verify_inclusion_proof(tampered_leaf, bundle["proof"], root) is False

    # Domain separation ensures leaf(left||right) != internal_node(left, right)
    left = hash_leaf(b"alpha")
    right = hash_leaf(b"beta")
    assert hash_node(left, right) != hash_leaf(left + right)


def test_tamper_detection_catches_payload_modification() -> None:
    ledger = MerkleAuditLedger()
    ledger.append_event("CREATE_KEY", "alice")
    ledger.append_event("SIGN_TX", "bob")
    ledger.append_event("ROTATE_KEY", "carol")
    assert ledger.verify_integrity() is True

    # Mutate payload of entry 2 without breaking prev_hash links
    ledger.chain[1]["action"] = "DELETE_ALL_DATA"
    report = ledger.verify_integrity_report()
    assert ledger.verify_integrity() is False
    assert report["is_valid"] is False
    assert report["first_corrupted_index"] == 2


def test_http_api_audit_lifecycle() -> None:
    client = TestClient(app)

    health = client.get("/health")
    assert health.status_code == 200
    assert health.json()["status"] == "healthy"

    r1 = client.post("/api/v1/events", json={"action": "DEPLOY", "actor": "ci-bot"})
    r2 = client.post(
        "/api/v1/events",
        json={"action": "APPROVE", "actor": "lead", "metadata": {"pr": 42}},
    )
    assert r1.status_code == 201
    assert r2.status_code == 201
    assert r2.json()["is_valid"] is True

    root_resp = client.get("/api/v1/merkle/root")
    assert root_resp.status_code == 200
    root_hash = root_resp.json()["merkle_root"]

    proof_resp = client.get("/api/v1/merkle/proof/1")
    assert proof_resp.status_code == 200
    proof_data = proof_resp.json()

    verify_resp = client.post(
        "/api/v1/merkle/verify",
        json={
            "leaf_hash": proof_data["leaf_hash"],
            "merkle_root": root_hash,
            "proof": proof_data["proof"],
        },
    )
    assert verify_resp.status_code == 200
    assert verify_resp.json()["valid"] is True

    missing_proof = client.get("/api/v1/merkle/proof/999")
    assert missing_proof.status_code == 404

    integrity = client.get("/api/v1/integrity")
    assert integrity.status_code == 200
    assert integrity.json()["is_valid"] is True
