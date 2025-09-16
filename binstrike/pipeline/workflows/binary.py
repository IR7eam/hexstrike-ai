
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from binstrike.pipeline.models import AnalysisArtifact, AnalysisFinding, BinaryAnalysisResult
from binstrike.tooling.process import CommandExecutionError, CommandRunner

StageReturn = Tuple[List[AnalysisFinding], List[AnalysisArtifact]]


@dataclass
class BinaryWorkflowConfig:
    """Configuration options controlling the binary analysis pipeline."""

    enable_checksec: bool = True
    enable_strings: bool = True
    enable_disassembly: bool = True
    enable_ropgadget: bool = True
    enable_pwntools: bool = True
    strings_min_length: int = 4
    strings_limit: int = 64
    disassembler: str = "radare2"
    architecture: str = "amd64"
    ropgadget_options: Sequence[str] = field(default_factory=tuple)
    interesting_strings: Sequence[str] = field(
        default_factory=lambda: (
            "flag",
            "password",
            "secret",
            "token",
            "shell",
            "admin",
            "usage",
            "enter",
            "input",
            "invalid",
            "key",
        )
    )
    pwntools_remote_host: str = "challenge.local"
    pwntools_remote_port: int = 1337
    stop_on_error: bool = False
    ghidra_headless: str = "ghidra-headless"
    ghidra_project_dir: Optional[Path] = None
    ghidra_project_name: str = "analysis"
    ghidra_script_path: Optional[Path] = None
    ghidra_post_script: Optional[str] = None


class BinaryAnalysisWorkflow:
    """Coordinated workflow that orchestrates binary triage tooling."""

    def __init__(
        self,
        target: Path,
        runner: CommandRunner,
        *,
        config: Optional[BinaryWorkflowConfig] = None,
    ) -> None:
        self.target = Path(target)
        self.runner = runner
        self.config = config or BinaryWorkflowConfig()
        self._state: Dict[str, Any] = {}

    def run(self) -> BinaryAnalysisResult:
        """Execute the configured workflow and return aggregated results."""

        result = BinaryAnalysisResult(target=self.target)
        stages: Iterable[Tuple[str, Any]] = (
            ("checksec", self._run_checksec),
            ("strings", self._run_strings),
            (self.config.disassembler.lower(), self._run_disassembler),
            ("ropgadget", self._run_ropgadget),
            ("pwntools", self._generate_pwntools_template),
        )

        for stage_name, handler in stages:
            if not self._stage_enabled(stage_name):
                continue
            try:
                findings, artifacts = handler()
            except CommandExecutionError as exc:
                failure_finding = AnalysisFinding(
                    title=f"{stage_name} execution failed",
                    summary="External command returned a non-zero exit status",
                    severity="error",
                    details={
                        "stage": stage_name,
                        "command": list(exc.result.command),
                        "returncode": exc.result.returncode,
                        "stderr": exc.result.stderr,
                    },
                )
                failure_artifact = AnalysisArtifact(
                    name=f"{stage_name}_error",
                    type="text/plain",
                    data=exc.result.stderr or exc.result.stdout,
                    description=f"Captured stderr from {stage_name}",
                    metadata={
                        "command": list(exc.result.command),
                        "returncode": exc.result.returncode,
                    },
                )
                result.extend([failure_finding], [failure_artifact])
                if self.config.stop_on_error:
                    raise
            except FileNotFoundError as exc:
                failure_finding = AnalysisFinding(
                    title=f"{stage_name} command missing",
                    summary=str(exc),
                    severity="error",
                    details={"stage": stage_name},
                )
                failure_artifact = AnalysisArtifact(
                    name=f"{stage_name}_error",
                    type="text/plain",
                    data=str(exc),
                    description=f"Failure invoking {stage_name}",
                    metadata={"stage": stage_name},
                )
                result.extend([failure_finding], [failure_artifact])
                if self.config.stop_on_error:
                    raise
            else:
                result.extend(findings, artifacts)
        return result

    # Stage execution helpers -------------------------------------------------

    def _stage_enabled(self, stage_name: str) -> bool:
        if stage_name == "checksec":
            return self.config.enable_checksec
        if stage_name == "strings":
            return self.config.enable_strings
        if stage_name in {"radare2", "ghidra"}:
            return self.config.enable_disassembly
        if stage_name == "ropgadget":
            return self.config.enable_ropgadget
        if stage_name == "pwntools":
            return self.config.enable_pwntools
        return True

    # Individual stages -------------------------------------------------------

    def _run_checksec(self) -> StageReturn:
        command = ("checksec", "--file", str(self.target))
        result = self.runner.run(command)
        artifact = AnalysisArtifact(
            name="checksec",
            type="text/plain",
            data=result.stdout,
            description="Raw output from checksec",
            metadata={
                "command": list(result.command),
                "returncode": result.returncode,
                "duration": result.duration,
            },
        )
        mitigations = self._parse_checksec_output(result.stdout)
        artifact.metadata["mitigations"] = mitigations
        severity, summary = self._summarize_mitigations(mitigations)
        finding = AnalysisFinding(
            title="Binary mitigations",
            summary=summary,
            severity=severity,
            details=mitigations,
        )
        self._state["mitigations"] = mitigations
        return [finding], [artifact]

    def _run_strings(self) -> StageReturn:
        command = (
            "strings",
            "-n",
            str(self.config.strings_min_length),
            str(self.target),
        )
        result = self.runner.run(command)
        all_strings = [line.strip() for line in result.stdout.splitlines() if line.strip()]
        if self.config.strings_limit:
            truncated = all_strings[: self.config.strings_limit]
        else:
            truncated = all_strings
        interesting = [s for s in truncated if self._is_interesting_string(s)]
        artifact = AnalysisArtifact(
            name="strings",
            type="text/list",
            data=truncated,
            description="Printable strings extracted with binutils strings",
            metadata={
                "command": list(result.command),
                "returncode": result.returncode,
                "duration": result.duration,
                "count": len(all_strings),
                "limit": self.config.strings_limit,
                "interesting": interesting,
            },
        )
        if interesting:
            summary = (
                "Identified potentially sensitive strings: "
                + ", ".join(interesting[:5])
            )
            severity = "medium"
        else:
            summary = f"Extracted {len(truncated)} printable strings"
            severity = "info"
        finding = AnalysisFinding(
            title="Static string analysis",
            summary=summary,
            severity=severity,
            details={
                "total_strings": len(all_strings),
                "interesting": interesting,
            },
        )
        self._state["strings"] = truncated
        self._state["interesting_strings"] = interesting
        return [finding], [artifact]

    def _run_disassembler(self) -> StageReturn:
        if self.config.disassembler.lower() == "ghidra":
            return self._run_ghidra()
        return self._run_radare2()

    def _run_radare2(self) -> StageReturn:
        functions_cmd = (
            "radare2",
            "-q",
            "-c",
            "aaa; afl",
            str(self.target),
        )
        functions_result = self.runner.run(functions_cmd)
        functions = self._parse_radare2_functions(functions_result.stdout)
        artifact_functions = AnalysisArtifact(
            name="functions",
            type="application/json",
            data=functions,
            description="Functions discovered by radare2",
            metadata={
                "command": list(functions_result.command),
                "returncode": functions_result.returncode,
                "duration": functions_result.duration,
                "count": len(functions),
            },
        )
        entry_function = self._select_entry_function(functions)
        cfg_cmd = (
            "radare2",
            "-q",
            "-c",
            "aaa; agC",
            str(self.target),
        )
        cfg_result = self.runner.run(cfg_cmd)
        cfg_output = cfg_result.stdout or cfg_result.stderr
        artifact_cfg = AnalysisArtifact(
            name="control_flow_graph",
            type="text/vnd.graphviz",
            data=cfg_output,
            description="Control flow graph from radare2 (DOT)",
            metadata={
                "command": list(cfg_result.command),
                "returncode": cfg_result.returncode,
                "duration": cfg_result.duration,
            },
        )
        findings = [
            AnalysisFinding(
                title="Disassembly overview",
                summary=self._format_disassembly_summary(functions, entry_function),
                severity="info",
                details={
                    "function_count": len(functions),
                    "entry_function": entry_function,
                },
            )
        ]
        self._state["functions"] = functions
        self._state["cfg"] = cfg_output
        return findings, [artifact_functions, artifact_cfg]

    def _run_ghidra(self) -> StageReturn:
        command: List[str] = [self.config.ghidra_headless]
        if self.config.ghidra_project_dir is not None:
            command.append(str(self.config.ghidra_project_dir))
        command.append(self.config.ghidra_project_name)
        command.extend(["-import", str(self.target)])
        if self.config.ghidra_script_path is not None:
            command.extend(["-scriptPath", str(self.config.ghidra_script_path)])
        if self.config.ghidra_post_script is not None:
            command.extend(["-postScript", self.config.ghidra_post_script])
        result = self.runner.run(tuple(command))
        functions: List[Dict[str, Any]] = []
        cfg_output = ""
        try:
            payload = json.loads(result.stdout)
        except json.JSONDecodeError:
            functions = self._parse_radare2_functions(result.stdout)
            cfg_output = result.stderr
        else:
            functions = list(payload.get("functions", []))
            cfg_output = payload.get("control_flow_graph", "")
        artifact_functions = AnalysisArtifact(
            name="functions",
            type="application/json",
            data=functions,
            description="Functions exported via Ghidra script",
            metadata={
                "command": list(command),
                "returncode": result.returncode,
                "duration": result.duration,
                "count": len(functions),
            },
        )
        artifact_cfg = AnalysisArtifact(
            name="control_flow_graph",
            type="text/vnd.graphviz",
            data=cfg_output,
            description="Control flow graph recovered via Ghidra",
            metadata={
                "command": list(command),
                "returncode": result.returncode,
                "duration": result.duration,
            },
        )
        entry_function = self._select_entry_function(functions)
        finding = AnalysisFinding(
            title="Disassembly overview",
            summary=self._format_disassembly_summary(functions, entry_function),
            severity="info",
            details={
                "function_count": len(functions),
                "entry_function": entry_function,
            },
        )
        self._state["functions"] = functions
        self._state["cfg"] = cfg_output
        return [finding], [artifact_functions, artifact_cfg]

    def _run_ropgadget(self) -> StageReturn:
        command = ["ROPgadget", "--binary", str(self.target)]
        command.extend(self.config.ropgadget_options)
        result = self.runner.run(tuple(command))
        gadgets = self._parse_ropgadget_output(result.stdout)
        artifact = AnalysisArtifact(
            name="rop_gadgets",
            type="text/list",
            data=gadgets,
            description="Gadgets enumerated by ROPgadget",
            metadata={
                "command": list(result.command),
                "returncode": result.returncode,
                "duration": result.duration,
                "count": len(gadgets),
            },
        )
        rop_chain = self._derive_rop_chain(gadgets)
        if rop_chain:
            chain_artifact = AnalysisArtifact(
                name="rop_chain",
                type="application/json",
                data=rop_chain,
                description="Heuristic ROP chain leveraging discovered gadgets",
                metadata={"length": len(rop_chain)},
            )
            artifacts = [artifact, chain_artifact]
            summary = f"Constructed candidate ROP chain with {len(rop_chain)} gadgets"
            severity = "high"
            self._state["rop_chain"] = rop_chain
        else:
            artifacts = [artifact]
            summary = f"Enumerated {len(gadgets)} ROP gadgets"
            severity = "info"
        finding = AnalysisFinding(
            title="ROP gadget enumeration",
            summary=summary,
            severity=severity,
            details={
                "gadgets_found": len(gadgets),
                "rop_chain": rop_chain,
            },
        )
        self._state["rop_gadgets"] = gadgets
        return [finding], artifacts

    def _generate_pwntools_template(self) -> StageReturn:
        mitigations = self._state.get("mitigations", {})
        rop_chain = self._state.get("rop_chain", [])
        functions = self._state.get("functions", [])
        binary_path = str(self.target)
        template_lines = [
            "from pwn import *",
            "",
            f"context.binary = ELF({binary_path!r})",
            f"context.arch = {self.config.architecture!r}",
            "",
            "def start(argv=None, *a, **kw):",
            "    if argv is None:",
            "        argv = []",
            "    if args.GDB:",
            "        return gdb.debug([context.binary.path] + argv, gdbscript=kw.get('gdbscript', 'continue'), *a, **kw)",
            "    if args.REMOTE:",
            f"        return remote({self.config.pwntools_remote_host!r}, {self.config.pwntools_remote_port})",
            "    return process([context.binary.path] + argv, *a, **kw)",
            "",
            "io = start()",
            "",
            "# Mitigation summary:",
        ]
        for key, value in mitigations.items():
            template_lines.append(f"#  - {key}: {value}")
        template_lines.extend([
            "",
            "elf = context.binary",
            "",
        ])
        if rop_chain:
            template_lines.append("rop = ROP(elf)")
            template_lines.append("# Construct ROP chain")
            for step in rop_chain:
                address = step.get("address")
                instruction = step.get("instruction", "")
                comment = step.get("comment", "")
                if address is None:
                    continue
                template_lines.append(f"rop.raw({address})  # {instruction}")
                register = step.get("register")
                if register:
                    template_lines.append(f"rop.raw(0x0)  # TODO: value for {register}")
                if comment:
                    template_lines.append(f"# {comment}")
            template_lines.extend([
                "",
                "payload = flat({",
                "    'padding': b'A' * 64,  # TODO: adjust offset",
                "    'rop': rop.chain(),",
                "})",
                "io.sendlineafter(b'>', payload)",
            ])
        else:
            template_lines.append("# TODO: Build exploit payload")
        main_function = next((fn for fn in functions if "main" in fn.get("name", "")), None)
        if main_function is not None:
            main_address = main_function.get("address")
            main_size = main_function.get("size")
            template_lines.append(
                f"log.info('main located at {main_address} with size {main_size}')"
            )
        template_lines.extend([
            "",
            "io.interactive()",
        ])
        template = "\n".join(template_lines)
        artifact = AnalysisArtifact(
            name="pwntools_template",
            type="text/x-python",
            data=template,
            description="Pwntools exploitation template",
            metadata={
                "rop_chain_present": bool(rop_chain),
                "mitigations": mitigations,
            },
        )
        finding = AnalysisFinding(
            title="Pwntools template generated",
            summary="Produced exploitation skeleton leveraging gathered intelligence",
            severity="info",
            details={
                "includes_rop": bool(rop_chain),
                "mitigations": mitigations,
            },
        )
        self._state["pwntools_template"] = template
        return [finding], [artifact]

    # Parsing helpers ---------------------------------------------------------

    def _parse_checksec_output(self, output: str) -> Dict[str, str]:
        lines = [line.strip() for line in output.splitlines() if line.strip()]
        if len(lines) < 2:
            return {}
        header = re.split(r"\s{2,}", lines[0])
        values = re.split(r"\s{2,}", lines[-1])
        mapping = {
            self._normalise_key(key): value.strip()
            for key, value in zip(header, values)
        }
        return mapping

    @staticmethod
    def _normalise_key(value: str) -> str:
        return value.strip().lower().replace(" ", "_")

    def _summarize_mitigations(self, mitigations: Dict[str, str]) -> Tuple[str, str]:
        if not mitigations:
            return "warning", "checksec did not produce mitigation information"
        positives: List[str] = []
        negatives: List[str] = []
        for key, value in mitigations.items():
            lowered = value.lower()
            if any(token in lowered for token in ("enabled", "found", "full", "present")):
                positives.append(f"{key}: {value}")
            elif any(token in lowered for token in ("disabled", "no", "partial", "missing")):
                negatives.append(f"{key}: {value}")
        if negatives:
            high_risk = any(
                any(keyword in entry.lower() for keyword in ("nx", "canary", "fortify"))
                for entry in negatives
            )
            severity = "high" if high_risk else "medium"
            summary = "Missing mitigations -> " + "; ".join(negatives)
        else:
            severity = "info"
            summary = "Protections enabled -> " + "; ".join(positives)
        return severity, summary

    def _is_interesting_string(self, value: str) -> bool:
        lowered = value.lower()
        return any(token in lowered for token in self.config.interesting_strings)

    def _parse_radare2_functions(self, output: str) -> List[Dict[str, Any]]:
        functions: List[Dict[str, Any]] = []
        for line in output.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            parts = re.split(r"\s+", stripped)
            if len(parts) < 4:
                continue
            address, size, _cc, name = parts[0], parts[1], parts[2], " ".join(parts[3:])
            function: Dict[str, Any] = {
                "address": address,
                "size": self._safe_int(size),
                "name": name,
            }
            functions.append(function)
        return functions

    @staticmethod
    def _safe_int(value: str) -> Optional[int]:
        try:
            return int(value, 0)
        except ValueError:
            return None

    @staticmethod
    def _select_entry_function(functions: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        for candidate in functions:
            name = candidate.get("name", "").lower()
            if name.endswith("main") or name == "main":
                return candidate
        return functions[0] if functions else None

    @staticmethod
    def _format_disassembly_summary(
        functions: List[Dict[str, Any]],
        entry_function: Optional[Dict[str, Any]],
    ) -> str:
        if not functions:
            return "No functions discovered"
        if entry_function:
            return (
                f"Identified {len(functions)} functions; "
                f"likely entry {entry_function.get('name')} @ {entry_function.get('address')}"
            )
        return f"Identified {len(functions)} functions"

    def _parse_ropgadget_output(self, output: str) -> List[Dict[str, str]]:
        gadgets: List[Dict[str, str]] = []
        pattern = re.compile(r"^(0x[0-9a-fA-F]+)\s*:\s*(.+)$")
        for line in output.splitlines():
            match = pattern.match(line.strip())
            if not match:
                continue
            address, instruction = match.groups()
            gadgets.append({"address": address, "instruction": instruction.strip()})
        return gadgets

    def _derive_rop_chain(self, gadgets: List[Dict[str, str]]) -> List[Dict[str, Any]]:
        def find(predicate):
            for gadget in gadgets:
                if predicate(gadget):
                    return gadget
            return None

        chain: List[Dict[str, Any]] = []
        pop_rdi = find(lambda g: "pop rdi" in g["instruction"])  # type: ignore[index]
        pop_rsi = find(lambda g: "pop rsi" in g["instruction"])  # type: ignore[index]
        pop_rdx = find(lambda g: "pop rdx" in g["instruction"])  # type: ignore[index]
        ret = find(lambda g: g["instruction"].strip() == "ret")  # type: ignore[index]
        system = find(lambda g: "system" in g["instruction"])  # type: ignore[index]
        if pop_rdi:
            chain.append({
                "address": pop_rdi["address"],
                "instruction": pop_rdi["instruction"],
                "register": "rdi",
            })
        if pop_rsi:
            chain.append({
                "address": pop_rsi["address"],
                "instruction": pop_rsi["instruction"],
                "register": "rsi",
            })
        if pop_rdx:
            chain.append({
                "address": pop_rdx["address"],
                "instruction": pop_rdx["instruction"],
                "register": "rdx",
            })
        if system:
            chain.append({
                "address": system["address"],
                "instruction": system["instruction"],
                "comment": "Potential system() invocation",
            })
        elif ret and chain:
            chain.append({
                "address": ret["address"],
                "instruction": ret["instruction"],
                "comment": "Align stack with ret gadget",
            })
        return chain
