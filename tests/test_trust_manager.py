"""
tests/test_trust_manager.py - Tests for HadAgent trust transition rules.
"""
from core.poi.trust import TrustManager, TrustState


def test_trust_lifecycle():
    mgr = TrustManager(promote_threshold=5, demote_threshold=2)
    node = "test_node_01"
    mgr.register_node(node)

    # Initial state
    assert mgr.get_state(node) == TrustState.UNTRUSTED

    # 4 clean rounds -> still UNTRUSTED
    for _ in range(4):
        mgr.record_clean_round(node)
    assert mgr.get_state(node) == TrustState.UNTRUSTED

    # 5th clean round -> promoted to TRUSTED
    mgr.record_clean_round(node)
    assert mgr.get_state(node) == TrustState.TRUSTED

    # 1 failure -> still TRUSTED
    mgr.record_failure(node)
    assert mgr.get_state(node) == TrustState.TRUSTED

    # 2nd failure -> demoted to DEMOTED
    mgr.record_failure(node)
    assert mgr.get_state(node) == TrustState.DEMOTED


if __name__ == "__main__":
    test_trust_lifecycle()
    print("All test_trust_manager tests passed!")
