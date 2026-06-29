"""test_visual_detector.py - Calibration and verification script for CLIP visual detector.
"""
import sys
import os

# Add root folder to sys.path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.visual_detector import VisualDetector

def test():
    detector = VisualDetector()
    
    benign_path = "data/vlm_test_document.png"
    attack_path = "data/vlm_injection_test.png"
    
    print("=== Testing CLIP Visual Detector ===")
    print(f"Benign Image path: {benign_path}")
    print(f"Attack Image path: {attack_path}\n")
    
    if not os.path.exists(benign_path):
        print(f"[Error] Benign image not found at {benign_path}")
        return
    if not os.path.exists(attack_path):
        print(f"[Error] Attack image not found at {attack_path}")
        return
        
    print("Encoding Benign image...")
    is_attack_b, sim_b = detector.is_attack_image(benign_path)
    print(f"Benign image max similarity: {sim_b:.4f} (Is Attack: {is_attack_b})")
    
    print("\nEncoding Attack image...")
    is_attack_a, sim_a = detector.is_attack_image(attack_path)
    print(f"Attack image max similarity: {sim_a:.4f} (Is Attack: {is_attack_a})")
    
    print("\n=== Calibration ===")
    midpoint = (sim_b + sim_a) / 2.0
    print(f"Suggested classification threshold: {midpoint:.4f}")

if __name__ == "__main__":
    test()
