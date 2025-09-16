
from __future__ import annotations

from pathlib import Path

from binstrike.decision.engine import AnalysisPlanner, PlannerConfig
from binstrike.pipeline.models import AnalysisArtifact, BinaryAnalysisResult


def build_sample_result() -> BinaryAnalysisResult:
    result = BinaryAnalysisResult(target=Path("/tmp/sample"))
    result.add_artifact(
        AnalysisArtifact(
            name="checksec",
            type="text/plain",
            data="checksec output",
            metadata={
                "mitigations": {
                    "relro": "Full RELRO",
                    "nx": "NX disabled",
                    "stack_canary": "No canary found",
                }
            },
        )
    )
    strings = ["Welcome", "Enter password:", "Usage: %s <flag>", "/bin/sh"]
    result.add_artifact(
        AnalysisArtifact(
            name="strings",
            type="text/list",
            data=strings,
            metadata={"interesting": ["Enter password:"]},
        )
    )
    result.add_artifact(
        AnalysisArtifact(
            name="functions",
            type="application/json",
            data=[
                {"name": "sym.main"},
                {"name": "sym.check_password"},
            ],
        )
    )
    result.add_artifact(
        AnalysisArtifact(
            name="rop_gadgets",
            type="text/list",
            data=[{"address": "0x401016", "instruction": "pop rdi ; ret"}],
            metadata={"count": 1},
        )
    )
    return result


def test_planner_enables_symbolic_and_fuzzing_steps() -> None:
    result = build_sample_result()
    planner = AnalysisPlanner(PlannerConfig())
    plan = planner.plan_binary(result.target, initial_result=result)
    names = plan.step_names()
    assert "symbolic_execution" in names
    assert "fuzzing" in names
    assert "debugger" in names
    assert "emulation" not in names


def test_planner_respects_manual_configuration() -> None:
    result = build_sample_result()
    config = PlannerConfig(
        enable_symbolic_execution="never",
        enable_fuzzing="always",
        enable_debugger="never",
    )
    planner = AnalysisPlanner(config)
    plan = planner.plan_binary(result.target, initial_result=result, hints={"architecture": "arm"})
    names = plan.step_names()
    assert "fuzzing" in names  # forced by configuration
    assert "symbolic_execution" not in names
    assert "debugger" not in names
    assert "emulation" in names  # triggered by non-x86 architecture
