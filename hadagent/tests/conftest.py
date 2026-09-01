from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

import pytest


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class CaseResult:
    test_name: str
    category: str
    expected: str
    actual_passed: bool
    correctly_handled: bool
    start_ts: str
    end_ts: str
    latency_ms: float
    notes: str = ""


@dataclass
class MetricsStore:
    cases: list[CaseResult] = field(default_factory=list)

    def add_case(
        self,
        *,
        test_name: str,
        category: str,
        expected: str,
        actual_passed: bool,
        start_ts: str,
        end_ts: str,
        latency_ms: float,
        notes: str = "",
    ) -> None:
        correctly_handled = (
            (expected == "valid" and actual_passed is True)
            or (expected == "invalid" and actual_passed is False)
        )
        self.cases.append(
            CaseResult(
                test_name=test_name,
                category=category,
                expected=expected,
                actual_passed=actual_passed,
                correctly_handled=correctly_handled,
                start_ts=start_ts,
                end_ts=end_ts,
                latency_ms=latency_ms,
                notes=notes,
            )
        )

    def summary(self) -> dict:
        tracked = self.cases

        valid_records = [
            c for c in tracked if c.category == "record" and c.expected == "valid"
        ]
        invalid_records = [
            c for c in tracked if c.category == "record" and c.expected == "invalid"
        ]
        valid_blocks = [
            c for c in tracked if c.category == "block" and c.expected == "valid"
        ]
        invalid_blocks = [
            c for c in tracked if c.category == "block" and c.expected == "invalid"
        ]

        valid_hub = [
            c for c in tracked if c.category == "hub" and c.expected == "valid"
        ]
        invalid_hub = [
            c for c in tracked if c.category == "hub" and c.expected == "invalid"
        ]
        valid_pool = [
            c for c in tracked if c.category == "pool" and c.expected == "valid"
        ]
        invalid_pool = [
            c for c in tracked if c.category == "pool" and c.expected == "invalid"
        ]

        invalid_total = [c for c in tracked if c.expected == "invalid"]
        invalid_correct = [c for c in invalid_total if c.correctly_handled]

        valid_total = [c for c in tracked if c.expected == "valid"]
        valid_incorrect = [c for c in valid_total if c.actual_passed is False]

        detection_rate = (
            len(invalid_correct) / len(invalid_total) if invalid_total else 0.0
        )
        false_positive_rate = (
            len(valid_incorrect) / len(valid_total) if valid_total else 0.0
        )

        return {
            "valid_records_tested": len(valid_records),
            "invalid_records_tested": len(invalid_records),
            "valid_blocks_tested": len(valid_blocks),
            "invalid_blocks_tested": len(invalid_blocks),
            "valid_hub_tested": len(valid_hub),
            "invalid_hub_tested": len(invalid_hub),
            "valid_pool_tested": len(valid_pool),
            "invalid_pool_tested": len(invalid_pool),
            "invalid_cases_correctly_rejected": len(invalid_correct),
            "invalid_cases_total": len(invalid_total),
            "detection_rate": detection_rate,
            "valid_cases_incorrectly_rejected": len(valid_incorrect),
            "valid_cases_total": len(valid_total),
            "false_positive_rate": false_positive_rate,
            "cases": [asdict(c) for c in tracked],
        }


def pytest_configure(config) -> None:
    if not hasattr(config, "_metrics_store"):
        config._metrics_store = MetricsStore()


@pytest.fixture(scope="session")
def metrics_store(pytestconfig) -> MetricsStore:
    return pytestconfig._metrics_store


@pytest.fixture
def case_tracker(request, metrics_store: MetricsStore):
    def _track(
        *,
        category: str,
        expected: str,
        actual_passed: bool,
        start_perf: float,
        start_ts: str,
        notes: str = "",
    ) -> None:
        end_perf = time.perf_counter()
        end_ts = utc_now_iso()
        latency_ms = (end_perf - start_perf) * 1000.0

        metrics_store.add_case(
            test_name=request.node.name,
            category=category,
            expected=expected,
            actual_passed=actual_passed,
            start_ts=start_ts,
            end_ts=end_ts,
            latency_ms=latency_ms,
            notes=notes,
        )

    return _track


def pytest_terminal_summary(terminalreporter, exitstatus, config) -> None:
    metrics_store = config._metrics_store
    summary = metrics_store.summary()

    terminalreporter.write_sep("=", "Validation Metrics Summary")
    terminalreporter.write_line(
        f"Valid records tested: {summary['valid_records_tested']}"
    )
    terminalreporter.write_line(
        f"Invalid records tested: {summary['invalid_records_tested']}"
    )
    terminalreporter.write_line(
        f"Valid blocks tested: {summary['valid_blocks_tested']}"
    )
    terminalreporter.write_line(
        f"Invalid blocks tested: {summary['invalid_blocks_tested']}"
    )
    terminalreporter.write_line(
        f"Valid hub tests: {summary['valid_hub_tested']}"
    )
    terminalreporter.write_line(
        f"Invalid hub tests: {summary['invalid_hub_tested']}"
    )
    terminalreporter.write_line(
        f"Valid pool tests: {summary['valid_pool_tested']}"
    )
    terminalreporter.write_line(
        f"Invalid pool tests: {summary['invalid_pool_tested']}"
    )
    terminalreporter.write_line(
        f"Detection rate: "
        f"{summary['invalid_cases_correctly_rejected']}/"
        f"{summary['invalid_cases_total']} = "
        f"{summary['detection_rate']:.2%}"
    )
    terminalreporter.write_line(
        f"False positive rate: "
        f"{summary['valid_cases_incorrectly_rejected']}/"
        f"{summary['valid_cases_total']} = "
        f"{summary['false_positive_rate']:.2%}"
    )

    out_dir = Path("test_results")
    out_dir.mkdir(exist_ok=True)

    out_file = out_dir / "validation_metrics.json"
    out_file.write_text(json.dumps(summary, indent=2))
    terminalreporter.write_line(f"Saved metrics JSON to {out_file}")