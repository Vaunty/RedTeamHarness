"""detector.py - Embedding-space attack detector that acts as a defense layer.
Projects input prompts onto the learned "attack direction" vector and filters
them based on a threshold.
"""
import os
import numpy as np
from core.embed import embed

class EmbeddingDetector:
    def __init__(self, model_path="data/detector_model.npz"):
        self.model_path = model_path
        self.w = None
        self.threshold = 0.0
        self.is_loaded = False
        self.load_model()

    def load_model(self):
        """Loads the saved weight vector and threshold from disk."""
        if os.path.exists(self.model_path):
            try:
                data = np.load(self.model_path)
                self.w = data["w"]
                self.threshold = float(data["threshold"])
                self.is_loaded = True
            except Exception as e:
                print(f"[Warning] Failed to load embedding detector model from {self.model_path}: {e}")
        else:
            # Model not trained yet or not found
            pass

    def save_model(self, w, threshold):
        """Saves the weight vector and threshold to disk."""
        os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
        np.savez(self.model_path, w=w, threshold=threshold)
        self.w = w
        self.threshold = threshold
        self.is_loaded = True

    def score_prompt(self, prompt):
        """
        Projects the prompt's embedding onto the attack direction vector.
        
        Args:
            prompt: String containing the user prompt.
            
        Returns:
            projection: Float score representing the projection value (dot product).
        """
        if not self.is_loaded or self.w is None:
            return 0.0
            
        v = embed(prompt)
        return float(v @ self.w)

    def is_attack(self, prompt):
        """
        Determines if the prompt is an attack based on the classification threshold.
        
        Args:
            prompt: String containing the user prompt.
            
        Returns:
            bool: True if prompt is classified as an attack, False otherwise.
        """
        if not self.is_loaded or self.w is None:
            return False
        score = self.score_prompt(prompt)
        return score > self.threshold
