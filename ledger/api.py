"""FastAPI HTTP endpoints for the immutable Merkle audit ledger."""

from typing import Any

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from ledger.merkle import MerkleAuditLedger, verify_inclusion_proof

app = FastAPI(title="Merkle Audit Trail Ledger", version="1.0.0")
ledger = MerkleAuditLedger()


class EventReq(BaseModel):
    """Payload to append a new tamper-evident audit event."""

    action: str = Field(..., min_length=1, max_length=128)
    actor: str = Field(..., min_length=1, max_length=128)
    metadata: dict[str, Any] = Field(default_factory=dict)


class ProofVerifyReq(BaseModel):
    """Payload to verify a Merkle inclusion proof against a root hash."""

    leaf_hash: str = Field(..., min_length=64, max_length=64)
    merkle_root: str = Field(..., min_length=64, max_length=64)
    proof: list[dict[str, str]]


@app.get("/health", tags=["Monitoring"])
def health_check() -> dict[str, Any]:
    """Liveness check returning ledger height and Merkle root."""
    return {
        "status": "healthy",
        "entries": len(ledger.chain),
        "merkle_root": ledger.merkle_root(),
    }


@app.post("/api/v1/events", status_code=201, tags=["Audit Ledger"])
def add_event(req: EventReq) -> dict[str, Any]:
    """Append an audit event and return sealed entry, root, and integrity status."""
    entry = ledger.append_event(req.action, req.actor, metadata=req.metadata)
    return {
        "entry": entry,
        "merkle_root": ledger.merkle_root(),
        "is_valid": ledger.verify_integrity(),
    }


@app.get("/api/v1/events", tags=["Audit Ledger"])
def list_events() -> dict[str, Any]:
    """List all sealed audit log entries with the current Merkle root."""
    return {"entries": ledger.chain, "merkle_root": ledger.merkle_root()}


@app.get("/api/v1/merkle/root", tags=["Merkle Proofs"])
def get_merkle_root() -> dict[str, Any]:
    """Return the current RFC 6962 Merkle root digest."""
    return {"entries": len(ledger.chain), "merkle_root": ledger.merkle_root()}


@app.get("/api/v1/merkle/proof/{index}", tags=["Merkle Proofs"])
def get_merkle_proof(index: int) -> dict[str, Any]:
    """Generate an O(log N) Merkle inclusion proof for 1-based entry index."""
    try:
        return ledger.get_inclusion_proof(index)
    except IndexError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.post("/api/v1/merkle/verify", tags=["Merkle Proofs"])
def verify_merkle_proof_endpoint(req: ProofVerifyReq) -> dict[str, bool]:
    """Statelessly verify a Merkle inclusion proof against a root hash."""
    return {"valid": verify_inclusion_proof(req.leaf_hash, req.proof, req.merkle_root)}


@app.get("/api/v1/integrity", tags=["Audit Ledger"])
def verify_chain_integrity() -> dict[str, Any]:
    """Verify every hash link and recomputed digest across the ledger."""
    return ledger.verify_integrity_report()
