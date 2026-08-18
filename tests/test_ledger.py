from ledger.merkle import MerkleAuditLedger

def test_ledger():
    l = MerkleAuditLedger()
    l.append_event("LOGIN", "admin")
    l.append_event("GRANT_ROLE", "admin")
    assert l.verify_integrity() is True
