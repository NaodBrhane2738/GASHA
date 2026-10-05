"""
==============================================================================
FILE: apps/api/app/ai/tests/e2e/runner.py
ROLE / OWNERSHIP: AI & Security Intelligence Engineers
OBJECTIVE: Standalone CLI runner to execute the End-to-End AI Integration
           Validation Suite and output console diagnostics and performance metrics.
==============================================================================
"""

import sys
import asyncio
from app.ai.tests.e2e.harness import E2ETestHarness, E2ETestResult


async def run_e2e_suite_cli():
    print("================================================================================")
    print("           GASHA AI SUBSYSTEM — END-TO-END INTEGRATION VALIDATION               ")
    print("================================================================================")

    harness = E2ETestHarness()
    print(f"Target Production Model: {harness.default_model}\n")

    result: E2ETestResult = await harness.run_all_cases(use_mock=True)

    print(f"{'Case ID':<10} | {'Case Name':<32} | {'Status':<12} | {'Fallback':<8} | {'Lat (ms)':<8} | {'Valid'}")
    print("-" * 88)

    for m in result.metrics:
        val_str = "PASS" if m.validation_passed else "FAIL"
        fb_str = "YES" if m.is_fallback else "NO"
        print(f"{m.case_id:<10} | {m.case_name:<32} | {m.status:<12} | {fb_str:<8} | {m.duration_ms:<8.1f} | {val_str}")

    print("-" * 88)
    print(f"Total Cases: {result.total_cases} | Passed: {result.passed_cases} | Failed: {result.failed_cases} | Avg Latency: {result.avg_duration_ms:.1f}ms")
    print(f"All Invariants Verified: {result.all_passed}\n")

    if not result.all_passed:
        print("ERROR: One or more E2E validation cases failed!")
        sys.exit(1)
    else:
        print("SUCCESS: All E2E AI Integration Validation cases passed cleanly.")


if __name__ == "__main__":
    asyncio.run(run_e2e_suite_cli())
