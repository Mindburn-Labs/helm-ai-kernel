from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
import json
from pathlib import Path
from typing import Any


class OpenEnvMode(str, Enum):
    SIMULATION = "SIMULATION"
    SHADOW = "SHADOW"
    PRODUCTION_UNSUPPORTED = "PRODUCTION_UNSUPPORTED"


class ProductionUnsupportedError(RuntimeError):
    """Raised when an OpenEnv-shaped caller attempts production execution."""


@dataclass(frozen=True)
class HelmSafetyTask:
    task_id: str
    name: str
    prompt: str
    expected_verdict: str
    required_evidence_refs: tuple[str, ...] = ()
    disallowed_verdicts: tuple[str, ...] = ()
    success_criteria: tuple[str, ...] = ()

    @classmethod
    def from_json(cls, payload: dict[str, Any]) -> "HelmSafetyTask":
        return cls(
            task_id=str(payload["task_id"]),
            name=str(payload["name"]),
            prompt=str(payload["prompt"]),
            expected_verdict=str(payload["expected_verdict"]).upper(),
            required_evidence_refs=tuple(
                str(ref) for ref in payload.get("required_evidence_refs", [])
            ),
            disallowed_verdicts=tuple(
                str(verdict).upper()
                for verdict in payload.get("disallowed_verdicts", [])
            ),
            success_criteria=tuple(
                str(criterion) for criterion in payload.get("success_criteria", [])
            ),
        )


@dataclass
class HelmBoundaryEnvState:
    task_id: str
    mode: OpenEnvMode
    step_count: int = 0
    done: bool = False
    status: str = "initialized"
    last_action: dict[str, Any] | None = None
    reward: float = 0.0
    evidence_refs: list[str] = field(default_factory=list)
    info: dict[str, Any] = field(default_factory=dict)

    def to_openenv_state(self) -> dict[str, Any]:
        state = asdict(self)
        state["mode"] = self.mode.value
        return state


class HelmBoundaryEnv:
    """OpenEnv-shaped harness for synthetic HELM safety tasks."""

    def __init__(
        self,
        task: HelmSafetyTask,
        mode: OpenEnvMode | str = OpenEnvMode.SIMULATION,
    ) -> None:
        self.task = task
        self.mode = OpenEnvMode(mode)
        self._state = HelmBoundaryEnvState(task_id=task.task_id, mode=self.mode)

    def reset(self) -> dict[str, Any]:
        self._state = HelmBoundaryEnvState(
            task_id=self.task.task_id,
            mode=self.mode,
            status="ready",
            info={
                "non_authoritative": True,
                "kernel_authority": "not-mounted",
                "expected_verdict": self.task.expected_verdict,
            },
        )
        return self.state()

    def state(self) -> dict[str, Any]:
        return self._state.to_openenv_state()

    def step(self, action: dict[str, Any]) -> tuple[dict[str, Any], float, bool, dict[str, Any]]:
        if self.mode == OpenEnvMode.PRODUCTION_UNSUPPORTED:
            raise ProductionUnsupportedError(
                "OpenEnv production mode is unsupported for HELM Kernel execution"
            )

        verdict = str(action.get("verdict", "")).upper()
        evidence_refs = [str(ref) for ref in action.get("evidence_refs", [])]
        missing_refs = [
            ref for ref in self.task.required_evidence_refs if ref not in evidence_refs
        ]
        disallowed = verdict in self.task.disallowed_verdicts
        matched = verdict == self.task.expected_verdict and not missing_refs

        if self.mode == OpenEnvMode.SHADOW:
            status = "shadow_recorded"
            reward = 0.0
        elif matched:
            status = "satisfied"
            reward = 1.0
        else:
            status = "failed"
            reward = -2.0 if disallowed else -1.0

        info = {
            "non_authoritative": True,
            "kernel_authority": "not-mounted",
            "expected_verdict": self.task.expected_verdict,
            "missing_evidence_refs": missing_refs,
            "disallowed_verdict": disallowed,
        }
        self._state = HelmBoundaryEnvState(
            task_id=self.task.task_id,
            mode=self.mode,
            step_count=self._state.step_count + 1,
            done=True,
            status=status,
            last_action=dict(action),
            reward=reward,
            evidence_refs=evidence_refs,
            info=info,
        )
        return self.state(), reward, True, info


def load_task(path: str | Path) -> HelmSafetyTask:
    with Path(path).open("r", encoding="utf-8") as handle:
        return HelmSafetyTask.from_json(json.load(handle))


def load_taskset(directory: str | Path) -> list[HelmSafetyTask]:
    root = Path(directory)
    return [load_task(path) for path in sorted(root.glob("*.json"))]
