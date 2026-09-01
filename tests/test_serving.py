"""
tests/test_serving.py - Tests for two-tier optimistic serving logic.
"""
from core.poi.trust import TrustManager, TrustState
from core.poi.anomaly import AnomalyDetector, AnomalyMode
from core.poi.serving import TwoTierServer, ServingResult


def test_untrusted_node_holds_output():
    mgr = TrustManager()
    detector = AnomalyDetector(mode=AnomalyMode.EXACT)
    server = TwoTierServer(trust_manager=mgr, anomaly_detector=detector)

    node_id = "untrusted_node"
    mgr.register_node(node_id)

    res = server.serve(
        node_id=node_id,
        query="test query",
        claimed_score=800,
        output_text="test output",
        verified_score=800
    )
    # Untrusted nodes must NOT deliver before verification passes
    assert res.delivered_before_verification is False
    assert res.verification_passed is True


def test_trusted_node_delivers_optimistically():
    mgr = TrustManager()
    detector = AnomalyDetector(mode=AnomalyMode.EXACT)
    server = TwoTierServer(trust_manager=mgr, anomaly_detector=detector)

    node_id = "trusted_node"
    mgr.register_node(node_id)
    for _ in range(5):
        mgr.record_clean_round(node_id)

    assert mgr.get_state(node_id) == TrustState.TRUSTED

    res = server.serve(
        node_id=node_id,
        query="test query",
        claimed_score=800,
        output_text="test output",
        verified_score=800
    )
    # Trusted node delivers optimistically
    assert res.delivered_before_verification is True


if __name__ == "__main__":
    test_untrusted_node_holds_output()
    test_trusted_node_delivers_optimistically()
    print("All test_serving tests passed!")
