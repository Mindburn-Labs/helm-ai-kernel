#!/usr/bin/env python3
"""Sharding `make check` must run every gate of the profile exactly once."""

from __future__ import annotations

import argparse
import pathlib
import sys
import unittest
import unittest.mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import quality  # noqa: E402


def registry(seconds: dict[str, float], order: list[str] | None = None) -> dict:
    return {
        "version": 1,
        "gates": [
            {"id": gate_id, "command": "true", **({"seconds": value} if value else {})}
            for gate_id, value in seconds.items()
        ],
        "profiles": {"merge": {"gates": order or list(seconds)}},
    }


class ShardPlanTest(unittest.TestCase):
    def test_every_count_runs_each_merge_gate_exactly_once(self) -> None:
        shipped = quality.load_registry(quality.DEFAULT_REGISTRY)
        gates = quality.gates_by_id(shipped)
        for profile in shipped["profiles"]:
            ids = quality.profile_gate_ids(shipped, profile)
            for count in range(1, quality.MAX_SHARDS + 1):
                with self.subTest(profile=profile, count=count):
                    parts = quality.shard_plan(gates, ids, count)
                    self.assertEqual(len(parts), count)
                    self.assertEqual(sorted(g for part in parts for g in part), sorted(ids))

    def test_one_shard_is_the_whole_profile_in_order(self) -> None:
        shipped = quality.load_registry(quality.DEFAULT_REGISTRY)
        ids = quality.profile_gate_ids(shipped, "merge")
        self.assertEqual(quality.shard_plan(quality.gates_by_id(shipped), ids, 1), [ids])

    def test_parts_are_balanced_and_keep_profile_order(self) -> None:
        reg = registry({"a": 0, "slow": 400, "b": 0, "mid": 200, "c": 0, "mid2": 200})
        parts = quality.shard_plan(quality.gates_by_id(reg), quality.profile_gate_ids(reg, "merge"), 2)
        # 400 against 200 + 200, then the unmeasured gates alternate.
        self.assertEqual(parts, [["a", "slow", "c"], ["b", "mid", "mid2"]])

    def test_plan_depends_only_on_the_registry(self) -> None:
        reg = registry({"x": 30, "y": 30, "z": 30, "w": 0})
        gates = quality.gates_by_id(reg)
        ids = quality.profile_gate_ids(reg, "merge")
        self.assertEqual(quality.shard_plan(gates, ids, 3), quality.shard_plan(gates, list(ids), 3))
        self.assertEqual(quality.shard_plan(gates, ids, 3), [["x", "w"], ["y"], ["z"]])

    def test_more_shards_than_gates_leaves_empty_parts_not_lost_gates(self) -> None:
        reg = registry({"only": 10})
        self.assertEqual(quality.shard_plan(quality.gates_by_id(reg), ["only"], 3), [["only"], [], []])

    def test_unknown_gate_still_lands_in_a_shard_so_the_runner_reports_it(self) -> None:
        reg = registry({"known": 10}, order=["known", "missing"])
        parts = quality.shard_plan(quality.gates_by_id(reg), quality.profile_gate_ids(reg, "merge"), 2)
        self.assertEqual(sorted(g for part in parts for g in part), ["known", "missing"])


class ShardArgumentTest(unittest.TestCase):
    def test_valid_shards(self) -> None:
        self.assertEqual(quality.parse_shard("1/1"), (1, 1))
        self.assertEqual(quality.parse_shard(" 3/4\n"), (3, 4))

    def test_invalid_shards_are_refused(self) -> None:
        for raw in ("", "0/4", "5/4", "1/0", "2", "a/b", "1/4/2", "-1/4", "1.5/4", "1 / 4"):
            with self.subTest(raw=raw), self.assertRaises(SystemExit):
                quality.parse_shard(raw)

    def run_shard(self, shard: str) -> list[str]:
        reg = registry({"slow": 400, "a": 0, "mid": 200, "b": 0})
        ran: list[str] = []

        def fake_run_gate(gate, strict, env):
            ran.append(gate["id"])
            return quality.GateResult(gate["id"], "passed", advisory=False)

        args = argparse.Namespace(gate=None, selection="merge", strict=True, impact=False, shard=shard)
        with unittest.mock.patch.object(quality, "run_gate", fake_run_gate), \
                unittest.mock.patch("builtins.print"):
            self.assertEqual(quality.run_selection(reg, args), 0)
        return ran

    def test_shards_together_run_the_profile_and_no_shard_means_all(self) -> None:
        whole = self.run_shard("")
        self.assertEqual(whole, ["slow", "a", "mid", "b"])
        first, second = self.run_shard("1/2"), self.run_shard("2/2")
        self.assertEqual(sorted(first + second), sorted(whole))
        self.assertFalse(set(first) & set(second))


class RegistrySelfTest(unittest.TestCase):
    def self_test(self, reg: dict) -> int:
        with unittest.mock.patch.object(quality, "EXPECTED_PROFILES", set()), \
                unittest.mock.patch("builtins.print"):
            return quality.self_test(reg)

    def test_well_formed_registry_passes(self) -> None:
        self.assertEqual(self.self_test(registry({"a": 10, "b": 0})), 0)

    def test_bad_seconds_and_repeated_gates_fail(self) -> None:
        for seconds in (0, -1, "12", True):
            with self.subTest(seconds=seconds):
                reg = registry({"a": 10})
                reg["gates"][0]["seconds"] = seconds
                self.assertEqual(self.self_test(reg), 1)
        self.assertEqual(self.self_test(registry({"a": 10}, order=["a", "a"])), 1)


if __name__ == "__main__":
    unittest.main()
