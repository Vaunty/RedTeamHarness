"""
PoI Consensus Simulation - Optimistic Serving.

Implements the two-tier optimistic serving architecture. Trusted nodes
can return results immediately, untrusted nodes wait for verification.
"""
from dataclasses import dataclass
from typing import Optional, Any
from core.poi.trust import TrustManager, TrustState
from core.poi.anomaly import AnomalyDetector

@dataclass
class ServingResult:
    output_text: str
    output_hash: str
    node_id: str
    trust_state: TrustState
    delivered_before_verification: bool
    verification_passed: Optional[bool] = None
    safety_verdict: Optional[str] = None
    blocked_by_defense: bool = False

class TwoTierServer:
    def __init__(self, trust_manager: TrustManager, anomaly_detector: AnomalyDetector, defense: Any = None):
        self.trust_manager = trust_manager
        self.anomaly_detector = anomaly_detector
        self.defense = defense
        self.served_results: list[ServingResult] = []

    def serve(self, node_id: str, query: str, claimed_score: int, output_text: str, verified_score: Optional[int] = None) -> ServingResult:
        import hashlib
        output_hash = hashlib.sha256(output_text.encode('utf-8')).hexdigest()
        trust_state = self.trust_manager.get_state(node_id)
        
        delivered_before_verification = (trust_state == TrustState.TRUSTED)
        
        result = ServingResult(
            output_text=output_text,
            output_hash=output_hash,
            node_id=node_id,
            trust_state=trust_state,
            delivered_before_verification=delivered_before_verification
        )
        
        if self.defense:
            if hasattr(self.defense, 'check_output'):
                should_block, verdict, reason = self.defense.check_output(output_text, query=query, trust_state=trust_state.value)
                result.blocked_by_defense = should_block
                result.safety_verdict = verdict
            elif hasattr(self.defense, 'check'):
                check_res = self.defense.check(output_text, query=query)
                if isinstance(check_res, tuple):
                    result.blocked_by_defense = check_res[0]
                    result.safety_verdict = check_res[1]
                else:
                    result.safety_verdict = str(check_res)

        if verified_score is not None:
            self.verify_and_update(result, verified_score=verified_score, claimed_score=claimed_score)
        
        self.served_results.append(result)
        return result

    def verify_and_update(self, result: ServingResult, verified_score: int, claimed_score: int) -> ServingResult:
        is_anomaly, _ = self.anomaly_detector.check(claimed_score, verified_score)
        
        result.verification_passed = not is_anomaly
        
        if result.verification_passed:
            self.trust_manager.record_clean_round(result.node_id)
        else:
            self.trust_manager.record_failure(result.node_id)
            
        return result

if __name__ == '__main__':
    from core.poi.anomaly import AnomalyMode
    tm = TrustManager()
    tm.register_node("node_1")
    tm.states["node_1"] = TrustState.TRUSTED
    
    ad = AnomalyDetector(AnomalyMode.EXACT)
    server = TwoTierServer(tm, ad)
    
    res = server.serve("node_1", "query", 850, "hello")
    assert res.delivered_before_verification == True
    server.verify_and_update(res, 850, 850)
    assert res.verification_passed == True
    print("serving.py self-test passed")
