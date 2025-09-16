
from __future__ import annotations

from pathlib import Path
from typing import Dict, Tuple

from binstrike.pipeline.workflows.binary import BinaryAnalysisWorkflow, BinaryWorkflowConfig
from binstrike.tooling.process import CommandResult, CommandRunner


class StubCommandRunner(CommandRunner):
    """Deterministic command runner used to simulate tooling output."""

    def __init__(self, responses: Dict[str, Dict[str, str]]) -> None:
        super().__init__()
        self.responses = responses
        self.calls: list[Tuple[str, ...]] = []

    def run(self, command, **kwargs):  # type: ignore[override]
        cmd = tuple(command)
        self.calls.append(cmd)
        key = self._key_for_command(cmd)
        if key not in self.responses:
            raise AssertionError(f"No stub available for command {cmd}")
        payload = self.responses[key]
        return CommandResult(
            command=cmd,
            stdout=payload.get("stdout", ""),
            stderr=payload.get("stderr", ""),
            returncode=payload.get("returncode", 0),
            duration=payload.get("duration", 0.01),
        )

    @staticmethod
    def _key_for_command(command: Tuple[str, ...]) -> str:
        if not command:
            return ""
        binary = command[0]
        if binary == "radare2" and len(command) > 3:
            expression = command[3]
            if "afl" in expression:
                return "radare2_afl"
            if "agC" in expression:
                return "radare2_agC"
        return binary


def test_binary_workflow_collects_structured_artifacts(tmp_path: Path) -> None:
    sample_binary = tmp_path / "sample"
    sample_binary.write_bytes(b"ELFsimulated")

    checksec_output = (
        "RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH     Symbols     FORTIFY Fortified Fortifiable FILE\n"
        "Full RELRO      Canary found      NX enabled    PIE enabled     No RPATH   No RUNPATH  73 Symbols  FORTIFY Fortified     0   sample\n"
    )
    strings_output = "Welcome\nEnter password:\nTry again\n/bin/sh\n"
    radare_afl_output = (
        "0x00001060    16  14  sym._init\n"
        "0x00001120    45  43  sym.main\n"
        "0x00001150    32  30  sym.check_password\n"
    )
    radare_cfg_output = "digraph { main -> sym.check_password }\n"
    ropgadget_output = (
        "0x0000000000401016 : pop rdi ; ret\n"
        "0x0000000000401018 : ret\n"
        "0x0000000000401050 : system\n"
    )

    responses = {
        "checksec": {"stdout": checksec_output},
        "strings": {"stdout": strings_output},
        "radare2_afl": {"stdout": radare_afl_output},
        "radare2_agC": {"stdout": radare_cfg_output},
        "ROPgadget": {"stdout": ropgadget_output},
    }

    runner = StubCommandRunner(responses)
    config = BinaryWorkflowConfig(strings_limit=10, disassembler="radare2")
    workflow = BinaryAnalysisWorkflow(sample_binary, runner, config=config)
    result = workflow.run()

    invoked_commands = [cmd[0] for cmd in runner.calls]
    assert invoked_commands[:5] == ["checksec", "strings", "radare2", "radare2", "ROPgadget"]

    checksec_artifact = result.get_artifact("checksec")
    assert checksec_artifact is not None
    assert "Full RELRO" in checksec_artifact.data
    assert checksec_artifact.metadata["mitigations"]["nx"] == "NX enabled"

    strings_artifact = result.get_artifact("strings")
    assert strings_artifact is not None
    assert len(strings_artifact.data) == 4
    assert "Enter password:" in strings_artifact.metadata["interesting"]

    functions_artifact = result.get_artifact("functions")
    assert functions_artifact is not None
    assert any(fn["name"] == "sym.main" for fn in functions_artifact.data)

    cfg_artifact = result.get_artifact("control_flow_graph")
    assert cfg_artifact is not None
    assert "digraph" in cfg_artifact.data

    rop_gadgets = result.get_artifact("rop_gadgets")
    assert rop_gadgets is not None
    assert rop_gadgets.metadata["count"] == 3

    rop_chain = result.get_artifact("rop_chain")
    assert rop_chain is not None
    assert rop_chain.metadata["length"] >= 1

    pwntools_template = result.get_artifact("pwntools_template")
    assert pwntools_template is not None
    assert "context.binary" in pwntools_template.data
    assert "rop = ROP" in pwntools_template.data

    finding_titles = {finding.title for finding in result.findings}
    assert "Binary mitigations" in finding_titles
    assert "ROP gadget enumeration" in finding_titles
