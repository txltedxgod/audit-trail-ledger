from fastapi import FastAPI
from pydantic import BaseModel
from ledger.merkle import MerkleAuditLedger

app = FastAPI(title="Merkle Audit Trail Ledger", version="0.1.0")
ledger = MerkleAuditLedger()

class EventReq(BaseModel):
    action: str
    actor: str

@app.post("/api/v1/events")
def add_event(req: EventReq):
    entry = ledger.append_event(req.action, req.actor)
    return {"entry": entry, "is_valid": ledger.verify_integrity()}
