import hashlib
import time
from typing import List, Dict, Any

class MerkleAuditLedger:
    def __init__(self):
        self.chain: List[Dict[str, Any]] = []

    def append_event(self, action: str, actor: str) -> Dict[str, Any]:
        prev_hash = self.chain[-1]["hash"] if self.chain else "GENESIS_ROOT"
        ts = time.time()
        raw = f"{action}_{actor}_{ts}_{prev_hash}".encode("utf-8")
        curr_hash = hashlib.sha256(raw).hexdigest()

        entry = {
            "index": len(self.chain) + 1,
            "action": action,
            "actor": actor,
            "timestamp": ts,
            "prev_hash": prev_hash,
            "hash": curr_hash
        }
        self.chain.append(entry)
        return entry

    def verify_integrity(self) -> bool:
        for i in range(1, len(self.chain)):
            if self.chain[i]["prev_hash"] != self.chain[i - 1]["hash"]:
                return False
        return True
