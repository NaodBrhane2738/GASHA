"""
GASHA Benchmark Cases Suite.

Exports all 15 synthetic security incident evaluation cases.
"""

from typing import List
from app.ai.evaluations.models import BenchmarkCase

from app.ai.evaluations.cases.case_001_straightforward_attack import get_case as get_case_1
from app.ai.evaluations.cases.case_002_credential_abuse import get_case as get_case_2
from app.ai.evaluations.cases.case_003_web_attack import get_case as get_case_3
from app.ai.evaluations.cases.case_004_unauthorized_access import get_case as get_case_4
from app.ai.evaluations.cases.case_005_attack_path_assisted import get_case as get_case_5
from app.ai.evaluations.cases.case_006_insufficient_evidence import get_case as get_case_6
from app.ai.evaluations.cases.case_007_conflicting_evidence import get_case as get_case_7
from app.ai.evaluations.cases.case_008_false_positive import get_case as get_case_8
from app.ai.evaluations.cases.case_009_prompt_injection import get_case as get_case_9
from app.ai.evaluations.cases.case_010_hallucinated_evidence_trap import get_case as get_case_10
from app.ai.evaluations.cases.case_011_multiple_affected_assets import get_case as get_case_11
from app.ai.evaluations.cases.case_012_noisy_incident import get_case as get_case_12
from app.ai.evaluations.cases.case_013_valid_response_rec import get_case as get_case_13
from app.ai.evaluations.cases.case_014_invalid_action_trap import get_case as get_case_14
from app.ai.evaluations.cases.case_015_partial_telemetry import get_case as get_case_15


def load_all_benchmark_cases() -> List[BenchmarkCase]:
    """Loads all 15 predefined GASHA security benchmark cases."""
    return [
        get_case_1(),
        get_case_2(),
        get_case_3(),
        get_case_4(),
        get_case_5(),
        get_case_6(),
        get_case_7(),
        get_case_8(),
        get_case_9(),
        get_case_10(),
        get_case_11(),
        get_case_12(),
        get_case_13(),
        get_case_14(),
        get_case_15(),
    ]


__all__ = [
    "load_all_benchmark_cases",
    "get_case_1",
    "get_case_2",
    "get_case_3",
    "get_case_4",
    "get_case_5",
    "get_case_6",
    "get_case_7",
    "get_case_8",
    "get_case_9",
    "get_case_10",
    "get_case_11",
    "get_case_12",
    "get_case_13",
    "get_case_14",
    "get_case_15",
]
