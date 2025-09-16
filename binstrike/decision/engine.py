from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from binstrike.pipeline.models import BinaryAnalysisResult


@dataclass
class PlannerConfig:
    """Configuration governing dynamic planning decisions."""

    disassembler: str = "radare2"
    strings_min_length: int = 4
    enable_symbolic_execution: str = "auto"
    enable_fuzzing: str = "auto"
    enable_emulation: str = "auto"
    enable_debugger: str = "auto"
    extra_steps: List[str] = field(default_factory=list)


@dataclass
class AnalysisStep:
    """Single actionable step in a binary analysis plan."""

    name: str
    description: str
    tool: Optional[str] = None
    enabled: bool = True
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AnalysisPlan:
    """Ordered sequence of analysis steps."""

    target: Path
    steps: List[AnalysisStep] = field(default_factory=list)

    def add_step(self, step: AnalysisStep) -> None:
        self.steps.append(step)

    def step_names(self) -> List[str]:
        return [step.name for step in self.steps]


class AnalysisPlanner:
    """Derives follow-up actions based on results and configuration."""

    def __init__(self, config: Optional[PlannerConfig] = None) -> None:
        self.config = config or PlannerConfig()

    def plan_binary(
        self,
        target: Path,
        *,
        initial_result: Optional[BinaryAnalysisResult] = None,
        hints: Optional[Dict[str, Any]] = None,
    ) -> AnalysisPlan:
        """Create a plan for binary analysis using heuristics and hints."""

        plan = AnalysisPlan(target=Path(target))
        plan.add_step(
            AnalysisStep(
                name="checksec",
                description="Assess compiler mitigations",
                tool="checksec",
            )
        )
        plan.add_step(
            AnalysisStep(
                name="strings",
                description=f"Extract strings (min length {self.config.strings_min_length})",
                tool="strings",
                metadata={"min_length": self.config.strings_min_length},
            )
        )
        plan.add_step(
            AnalysisStep(
                name="disassembly",
                description=f"Recover functions with {self.config.disassembler}",
                tool=self.config.disassembler,
            )
        )
        plan.add_step(
            AnalysisStep(
                name="ropgadget",
                description="Enumerate ROP gadgets",
                tool="ROPgadget",
            )
        )
        plan.add_step(
            AnalysisStep(
                name="pwntools",
                description="Generate exploitation skeleton with pwntools",
                tool="pwntools",
            )
        )

        if self._should_enable("symbolic_execution", initial_result, hints):
            plan.add_step(
                AnalysisStep(
                    name="symbolic_execution",
                    description="Explore execution paths using angr",
                    tool="angr",
                )
            )
        if self._should_enable("fuzzing", initial_result, hints):
            plan.add_step(
                AnalysisStep(
                    name="fuzzing",
                    description="Exercise program paths with AFL++",
                    tool="afl++",
                )
            )
        if self._should_enable("emulation", initial_result, hints):
            plan.add_step(
                AnalysisStep(
                    name="emulation",
                    description="Emulate binary with Qiling/Unicorn",
                    tool="qiling",
                )
            )
        if self._should_enable("debugger", initial_result, hints):
            plan.add_step(
                AnalysisStep(
                    name="debugger",
                    description="Set up pwndbg/gdb debugging session",
                    tool="gdb",
                )
            )

        for step_name in self.config.extra_steps:
            plan.add_step(
                AnalysisStep(
                    name=step_name,
                    description="Custom step from configuration",
                    tool=None,
                )
            )

        return plan

    # Internal helpers -----------------------------------------------------

    def _should_enable(
        self,
        capability: str,
        result: Optional[BinaryAnalysisResult],
        hints: Optional[Dict[str, Any]],
    ) -> bool:
        config_value = getattr(self.config, f"enable_{capability}", "auto")
        decision = self._normalise_decision(config_value)
        if hints and capability in hints:
            hint = hints[capability]
            if isinstance(hint, bool):
                return hint
        if decision == "always":
            return True
        if decision == "never":
            return False
        if decision != "auto":
            return bool(decision)
        if result is None:
            return False
        if capability == "symbolic_execution":
            return self._needs_symbolic_execution(result)
        if capability == "fuzzing":
            return self._needs_fuzzing(result)
        if capability == "emulation":
            return self._needs_emulation(result, hints)
        if capability == "debugger":
            return self._needs_debugger(result)
        return False

    @staticmethod
    def _normalise_decision(value: Any) -> str:
        if isinstance(value, bool):
            return "always" if value else "never"
        if isinstance(value, str):
            lowered = value.lower()
            if lowered in {"auto", "always", "never"}:
                return lowered
        return "auto"

    # Heuristics -----------------------------------------------------------

    def _needs_symbolic_execution(self, result: BinaryAnalysisResult) -> bool:
        strings_artifact = result.get_artifact("strings")
        if strings_artifact:
            interesting = strings_artifact.metadata.get("interesting", [])
            if interesting:
                return True
            for entry in strings_artifact.data:
                lowered = str(entry).lower()
                if any(token in lowered for token in ("password", "serial", "token", "flag")):
                    return True
        functions_artifact = result.get_artifact("functions")
        if functions_artifact:
            for fn in functions_artifact.data:
                name = str(fn.get("name", "")).lower()
                if any(token in name for token in ("check", "validate", "auth", "verify", "decrypt")):
                    return True
        return False

    def _needs_fuzzing(self, result: BinaryAnalysisResult) -> bool:
        strings_artifact = result.get_artifact("strings")
        if strings_artifact:
            for entry in strings_artifact.data:
                lowered = str(entry).lower()
                if any(token in lowered for token in ("usage", "invalid", "enter", "option", "input")):
                    return True
        functions_artifact = result.get_artifact("functions")
        if functions_artifact:
            for fn in functions_artifact.data:
                name = str(fn.get("name", "")).lower()
                if any(token in name for token in ("parse", "read", "recv", "handle")):
                    return True
        return False

    def _needs_emulation(
        self,
        result: BinaryAnalysisResult,
        hints: Optional[Dict[str, Any]] = None,
    ) -> bool:
        if hints:
            architecture = str(hints.get("architecture", "")).lower()
            if architecture and architecture not in {"amd64", "x86_64", "i386", "x86"}:
                return True
        rop_artifact = result.get_artifact("rop_gadgets")
        if rop_artifact and rop_artifact.metadata.get("count", 0) == 0:
            return True
        return False

    def _needs_debugger(self, result: BinaryAnalysisResult) -> bool:
        checksec_artifact = result.get_artifact("checksec")
        if checksec_artifact:
            mitigations = checksec_artifact.metadata.get("mitigations", {})
            for key, value in mitigations.items():
                lowered = str(value).lower()
                if key in {"nx", "stack_canary", "pie"} and any(
                    token in lowered for token in ("no", "disabled", "missing", "partial")
                ):
                    return True
        rop_artifact = result.get_artifact("rop_gadgets")
        if rop_artifact and rop_artifact.metadata.get("count", 0) > 0:
            return True
        return False
