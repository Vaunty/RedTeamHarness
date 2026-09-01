"""
PoI Consensus Simulation - Node.

Simulated secondary node with configurable behaviors for red-teaming.
"""
from enum import Enum
from typing import Optional, Dict, Any
import requests

class NodeBehavior(Enum):
    HONEST = "HONEST"
    FABRICATOR = "FABRICATOR"
    LOOKUP_TABLE = "LOOKUP_TABLE"
    MODEL_SWAP = "MODEL_SWAP"
    TRUST_THEN_BETRAY = "TRUST_THEN_BETRAY"

class SimulatedNode:
    def __init__(
        self,
        node_id: str,
        model_id: str,
        behavior: NodeBehavior,
        betray_after: int = 5,
        lookup_table: Optional[Dict[str, str]] = None,
        swap_model_id: Optional[str] = None,
        api_base: str = "http://localhost:11434/v1"
    ):
        self.node_id = node_id
        self.model_id = model_id
        self.behavior = behavior
        self.betray_after = betray_after
        self.lookup_table = lookup_table or {}
        self.swap_model_id = swap_model_id
        self.api_base = api_base
        self.round_count = 0

    def generate(self, query: str, system: Optional[str] = None) -> str:
        model_to_use = self.model_id
        if self.behavior == NodeBehavior.MODEL_SWAP and self.swap_model_id:
            model_to_use = self.swap_model_id
            
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": query})
        
        payload = {
            "model": model_to_use,
            "messages": messages,
            "temperature": 0.0,
        }
        
        try:
            resp = requests.post(f"{self.api_base}/chat/completions", json=payload)
            resp.raise_for_status()
            data = resp.json()
            return data["choices"][0]["message"]["content"]
        except Exception as e:
            return f"Error: {e}"

    def compute_score(self, eval_tasks: Any) -> int:
        """
        In a real implementation, this would evaluate the model against the tasks.
        For simulation, we return a mock honest score based on behavior.
        """
        # This is a stub for the honest score computation on the committed model
        return 800

    def get_score_for_verification(self, claimed_score: int, honest_score: int) -> int:
        self.round_count += 1
        
        if self.behavior == NodeBehavior.HONEST:
            return honest_score
            
        elif self.behavior == NodeBehavior.FABRICATOR:
            # Returns a random fabricated score, e.g. close to claimed
            return claimed_score + 10
            
        elif self.behavior == NodeBehavior.LOOKUP_TABLE:
            # Assumes score based on lookup match
            return claimed_score
            
        elif self.behavior == NodeBehavior.MODEL_SWAP:
            # Score computed from the swapped model, might be different
            return honest_score - 50 
            
        elif self.behavior == NodeBehavior.TRUST_THEN_BETRAY:
            if self.round_count <= self.betray_after:
                return honest_score
            else:
                return claimed_score + 50
                
        return honest_score

if __name__ == '__main__':
    node = SimulatedNode("node_1", "llama2", NodeBehavior.HONEST)
    assert node.get_score_for_verification(800, 800) == 800
    print("node.py self-test passed")
