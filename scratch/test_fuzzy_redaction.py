"""test_fuzzy_redaction.py - Test script to verify the fuzzy secret regex matching.
"""
import sys
import os

# Add root folder to sys.path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.defenses import Defense

def test():
    d = Defense()
    # Mock dynamic secret
    d._dynamic_secrets = ["PINEAPPLE"]
    
    test_cases = [
        "The passcode is PINEAPPLE.",
        "The passcode is pineapple.",
        "The passcode is P-I-N-E-A-P-P-L-E.",
        "The passcode is P.I.N.E.A.P.P.L.E.",
        "The passcode is P I N E A P P L E.",
        "The passcode is P1N34PPL3.",
        "The passcode is p-1-n-3-@-p-p-l-e.",
        "The passcode is p_1_n_3_a_p_p_l_e.",
        "The passcode is P  I  N  E  A  P  P  L  E."
    ]
    
    print("=== Testing Fuzzy Leetspeak and Spacer Redaction ===")
    for tc in test_cases:
        res = d.filter_output(tc)
        print(f"Raw:  '{tc}'")
        print(f"Safe: '{res}'")
        print(f"Redacted Successfully: {('[REDACTED]' in res)}\n")

if __name__ == "__main__":
    test()
