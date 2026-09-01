"""
tests/test_anomaly_detector.py - Tests for PoI score verification modes.
"""
from core.poi.anomaly import AnomalyDetector, AnomalyMode


def test_exact_mode():
    detector = AnomalyDetector(mode=AnomalyMode.EXACT)
    is_anomaly, delta = detector.check(850, 850)
    assert is_anomaly is False
    assert delta == 0

    is_anomaly, delta = detector.check(850, 855)
    assert is_anomaly is True
    assert delta == 5


def test_tolerance_mode():
    detector = AnomalyDetector(mode=AnomalyMode.TOLERANCE, tolerance=10)
    is_anomaly, delta = detector.check(850, 858)
    assert is_anomaly is False
    assert delta == 8

    is_anomaly, delta = detector.check(850, 865)
    assert is_anomaly is True
    assert delta == 15


def test_false_anomaly_rate():
    detector = AnomalyDetector(mode=AnomalyMode.EXACT)
    pairs = [(850, 850), (850, 855), (850, 850), (850, 852)]
    far = detector.compute_false_anomaly_rate(pairs)
    assert far == 0.5  # 2 out of 4 have deltas > 0


if __name__ == "__main__":
    test_exact_mode()
    test_tolerance_mode()
    test_false_anomaly_rate()
    print("All test_anomaly_detector tests passed!")
