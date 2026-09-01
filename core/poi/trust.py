"""
PoI Consensus Simulation - Trust Manager.

Implements the transition rules for node trust state: promote after 5 clean rounds, 
demote after 2 failures.
"""
from enum import Enum
from typing import Dict, List, Tuple

class TrustState(Enum):
    UNTRUSTED = "UNTRUSTED"
    TRUSTED = "TRUSTED"
    DEMOTED = "DEMOTED"

class TrustManager:
    def __init__(self, promote_threshold: int = 5, demote_threshold: int = 2):
        self.promote_threshold = promote_threshold
        self.demote_threshold = demote_threshold
        self.states: Dict[str, TrustState] = {}
        self.clean_rounds: Dict[str, int] = {}
        self.failure_rounds: Dict[str, int] = {}
        self.transition_log: List[Tuple[str, TrustState, TrustState, int, str]] = []
        self.round_num = 0

    def register_node(self, node_id: str):
        if node_id not in self.states:
            self.states[node_id] = TrustState.UNTRUSTED
            self.clean_rounds[node_id] = 0
            self.failure_rounds[node_id] = 0

    def record_clean_round(self, node_id: str):
        self.round_num += 1
        if node_id not in self.states:
            self.register_node(node_id)
            
        current_state = self.states[node_id]
        if current_state == TrustState.DEMOTED:
            return  # Cannot promote from DEMOTED
            
        self.clean_rounds[node_id] += 1
        if current_state == TrustState.UNTRUSTED and self.clean_rounds[node_id] >= self.promote_threshold:
            self._transition(node_id, TrustState.TRUSTED, "Reached promote threshold")
            self.clean_rounds[node_id] = 0

    def record_failure(self, node_id: str):
        self.round_num += 1
        if node_id not in self.states:
            self.register_node(node_id)
            
        current_state = self.states[node_id]
        if current_state == TrustState.DEMOTED:
            return
            
        self.failure_rounds[node_id] += 1
        self.clean_rounds[node_id] = 0  # Reset clean rounds on failure
        
        if self.failure_rounds[node_id] >= self.demote_threshold:
            self._transition(node_id, TrustState.DEMOTED, "Reached demote threshold")

    def _transition(self, node_id: str, new_state: TrustState, reason: str):
        old_state = self.states[node_id]
        self.states[node_id] = new_state
        self.transition_log.append((node_id, old_state, new_state, self.round_num, reason))

    def get_state(self, node_id: str) -> TrustState:
        return self.states.get(node_id, TrustState.UNTRUSTED)

    def get_all_states(self) -> Dict[str, TrustState]:
        return self.states.copy()

    def reset_node(self, node_id: str):
        old_state = self.states.get(node_id, TrustState.UNTRUSTED)
        self.states[node_id] = TrustState.UNTRUSTED
        self.clean_rounds[node_id] = 0
        self.failure_rounds[node_id] = 0
        self.transition_log.append((node_id, old_state, TrustState.UNTRUSTED, self.round_num, "Manual reset"))

if __name__ == '__main__':
    tm = TrustManager()
    tm.register_node("node_1")
    for _ in range(5):
        tm.record_clean_round("node_1")
    assert tm.get_state("node_1") == TrustState.TRUSTED
    tm.record_failure("node_1")
    tm.record_failure("node_1")
    assert tm.get_state("node_1") == TrustState.DEMOTED
    print("trust.py self-test passed")
