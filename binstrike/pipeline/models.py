from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional


@dataclass
class AnalysisFinding:
    """Structured representation of an analytic conclusion."""

    title: str
    summary: str
    severity: str = "info"
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AnalysisArtifact:
    """Container for artefacts generated during analysis."""

    name: str
    type: str
    data: Any
    description: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class BinaryAnalysisResult:
    """Aggregate for binary workflow outputs."""

    target: Path
    findings: List[AnalysisFinding] = field(default_factory=list)
    artifacts: List[AnalysisArtifact] = field(default_factory=list)

    def add_finding(self, finding: AnalysisFinding) -> None:
        self.findings.append(finding)

    def add_artifact(self, artifact: AnalysisArtifact) -> None:
        self.artifacts.append(artifact)

    def extend(self, findings: Iterable[AnalysisFinding], artifacts: Iterable[AnalysisArtifact]) -> None:
        self.findings.extend(findings)
        self.artifacts.extend(artifacts)

    def get_artifact(self, name: str) -> Optional[AnalysisArtifact]:
        for artifact in self.artifacts:
            if artifact.name == name:
                return artifact
        return None
