"""
PoI Consensus Simulation - Anomaly Detector.

Score verifier with EXACT and TOLERANCE modes for handling heterogeneous hardware.
"""
from enum import Enum
from typing import Tuple, List

class AnomalyMode(Enum):
    EXACT = "EXACT"
    TOLERANCE = "TOLERANCE"

class AnomalyDetector:
    def __init__(self, mode: AnomalyMode = AnomalyMode.EXACT, tolerance: int = 0):
        self.mode = mode
        self.tolerance = tolerance

    def check(self, claimed_score: int, verified_score: int) -> Tuple[bool, float]:
        """
        Returns (is_anomaly, delta).
        """
        delta = abs(claimed_score - verified_score)
        if self.mode == AnomalyMode.EXACT:
            is_anomaly = claimed_score != verified_score
        else:
            is_anomaly = delta > self.tolerance
            
        return is_anomaly, float(delta)

    def compute_false_anomaly_rate(self, honest_pairs: List[Tuple[int, int]]) -> float:
        """
        Given pairs of (config_a_score, config_b_score) from honest nodes,
        returns the fraction that would be flagged as anomalies.
        """
        if not honest_pairs:
            return 0.0
            
        anomalies = 0
        for claimed, verified in honest_pairs:
            is_anomaly, _ = self.check(claimed, verified)
            if is_anomaly:
                anomalies += 1
                
        return anomalies / len(honest_pairs)

    def find_minimum_tolerance(self, honest_pairs: List[Tuple[int, int]]) -> int:
        """
        Find the smallest tolerance that yields 0% false anomalies on honest data.
        """
        if not honest_pairs:
            return 0
            
        max_diff = 0
        for claimed, verified in honest_pairs:
            max_diff = max(max_diff, abs(claimed - verified))
            
        return max_diff

if __name__ == '__main__':
    detector = AnomalyDetector(mode=AnomalyMode.TOLERANCE, tolerance=5)
    assert detector.check(850, 853)[0] == False
    assert detector.check(850, 860)[0] == True
    
    pairs = [(800, 802), (800, 807)]
    assert detector.find_minimum_tolerance(pairs) == 7
    print("anomaly.py self-test passed")
