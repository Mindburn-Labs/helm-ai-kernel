from __future__ import annotations

import json
from pathlib import Path

from helm_boundary_env import (
    HelmBoundaryEnv,
    OpenEnvMode,
    ProductionUnsupportedError,
    load_taskset,
)


REPO_ROOT = Path(__file__).resolve().parents[3]
TASKSET = REPO_ROOT / "examples" / "openenv" / "tasksets" / "action_safety"


def _expected_action(task):
    return {
        "verdict": task.expected_verdict,
        "evidence_refs": list(task.required_evidence_refs),
    }


def main() -> None:
    tasks = load_taskset(TASKSET)
    assert len(tasks) == 5, f"expected 5 action-safety fixtures, found {len(tasks)}"

    for task in tasks:
        simulation = HelmBoundaryEnv(task, OpenEnvMode.SIMULATION)
        simulation.reset()
        state, reward, done, info = simulation.step(_expected_action(task))
        assert done is True
        assert reward == 1.0
        assert state["status"] == "satisfied"
        assert info["non_authoritative"] is True
        assert info["kernel_authority"] == "not-mounted"

        shadow = HelmBoundaryEnv(task, OpenEnvMode.SHADOW)
        shadow.reset()
        state, reward, done, info = shadow.step(_expected_action(task))
        assert done is True
        assert reward == 0.0
        assert state["status"] == "shadow_recorded"
        assert info["non_authoritative"] is True

        production = HelmBoundaryEnv(task, OpenEnvMode.PRODUCTION_UNSUPPORTED)
        production.reset()
        try:
            production.step(_expected_action(task))
        except ProductionUnsupportedError:
            pass
        else:
            raise AssertionError("production mode must raise ProductionUnsupportedError")

    print(
        json.dumps(
            {
                "taskset": str(TASKSET.relative_to(REPO_ROOT)),
                "fixtures": len(tasks),
                "modes": [mode.value for mode in OpenEnvMode],
                "production": "unsupported",
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
