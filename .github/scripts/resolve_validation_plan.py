#!/usr/bin/env python3
"""Resolve a bounded, target-pinned Toolkit Frontier validation plan.

The planner is deliberately side-effect free.  A workflow first resolves the
checkout to an exact commit and then uses this module to select a finite lane
matrix.  Lane definitions are data, so adding a lane cannot silently widen a
workflow's permissions or publish authority.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path


PROFILE_BANDS = {
    "targeted": {"fail_fast": True, "cap": 4, "intent": "one named validation seam"},
    "frontier": {"fail_fast": False, "cap": 12, "intent": "bounded fail-slow blocker harvest"},
    "checkpoint": {"fail_fast": False, "cap": 8, "intent": "finite milestone confidence checkpoint"},
}
FANOUT_CAPS = {"balanced": 4, "enterprise": 12, "soak": 24}
SETUP_CLASSES = {"workflow", "rust", "package", "attestation"}
STATUS_CLASSES = {"active", "catalog-only"}
ROLES = {"sentinel", "depth"}


def default_catalog_path() -> Path:
    return Path(__file__).resolve().parents[1] / "validation-lanes.json"


def load_catalog(path: Path) -> dict:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"cannot read validation catalog {path}: {exc}") from exc
    if not isinstance(payload, dict) or not isinstance(payload.get("lanes"), list):
        raise SystemExit("validation catalog must be an object with a lanes array")
    return payload


def _relative_path(value: object, *, field: str) -> str:
    if not isinstance(value, str) or not value or value.startswith("/"):
        raise SystemExit(f"{field} must be a non-empty repository-relative path")
    if any(part == ".." for part in Path(value).parts):
        raise SystemExit(f"{field} must not contain '..'")
    return value


def _lane_id(value: object) -> str:
    if not isinstance(value, str) or not value.strip():
        raise SystemExit("lane_id must be a non-empty string")
    return value.strip()


def normalize_catalog(catalog: dict) -> dict:
    """Validate and add deterministic sentinel/depth roles to catalog lanes."""

    lanes: list[dict] = []
    seen: set[str] = set()
    family_members: dict[str, list[str]] = {}
    for raw in catalog["lanes"]:
        if not isinstance(raw, dict):
            raise SystemExit("each validation lane must be an object")
        lane = dict(raw)
        lane_id = _lane_id(lane.get("lane_id"))
        if lane_id in seen:
            raise SystemExit(f"duplicate lane id: {lane_id}")
        seen.add(lane_id)
        status = lane.get("status_class", "active")
        if status not in STATUS_CLASSES:
            raise SystemExit(f"lane {lane_id} has unsupported status_class {status!r}")
        setup = lane.get("setup_class")
        if setup not in SETUP_CLASSES:
            raise SystemExit(f"lane {lane_id} has unsupported setup_class {setup!r}")
        groups = lane.get("groups", [])
        lane_sets = lane.get("lane_sets", [])
        for name, value in (("groups", groups), ("lane_sets", lane_sets)):
            if not isinstance(value, list) or not value or not all(isinstance(x, str) and x for x in value):
                raise SystemExit(f"lane {lane_id} must define a non-empty {name} array")
        lane["lane_id"] = lane_id
        lane["status_class"] = status
        lane["summary_family"] = str(lane.get("summary_family") or lane_id)
        lane["working_directory"] = _relative_path(lane.get("working_directory", "."), field=f"lane {lane_id} working_directory")
        lane["script_path"] = _relative_path(lane.get("script_path"), field=f"lane {lane_id} script_path")
        args = lane.get("script_args", [])
        if not isinstance(args, list) or not all(isinstance(arg, str) for arg in args):
            raise SystemExit(f"lane {lane_id} script_args must be an array of strings")
        lane["script_args"] = args
        timeout = lane.get("timeout_minutes", 30)
        if isinstance(timeout, bool) or not isinstance(timeout, int) or timeout <= 0:
            raise SystemExit(f"lane {lane_id} timeout_minutes must be a positive integer")
        lane["timeout_minutes"] = timeout
        lane["always_upload_artifact"] = bool(lane.get("always_upload_artifact", True))
        family_members.setdefault(lane["summary_family"], []).append(lane_id)
        lanes.append(lane)

    active_family_members = {
        family: sorted(
            item["lane_id"] for item in lanes
            if item["summary_family"] == family and item["status_class"] == "active"
        )
        for family in family_members
    }
    for lane in lanes:
        members = sorted(family_members[lane["summary_family"]])
        expected = "sentinel" if lane["lane_id"] == members[0] else "depth"
        declared = lane.get("frontier_role")
        if declared is not None and declared not in ROLES:
            raise SystemExit(f"lane {lane['lane_id']} has unsupported frontier_role {declared!r}")
        # The lexicographically first active lane is always the sentinel.  This
        # is deterministic even when catalog entries are reordered.
        active_members = active_family_members[lane["summary_family"]]
        if lane["status_class"] == "active":
            expected = "sentinel" if lane["lane_id"] == active_members[0] else "depth"
        if declared is not None and declared != expected:
            raise SystemExit(
                f"lane {lane['lane_id']} declares frontier_role={declared!r}, "
                f"but deterministic role is {expected!r} for summary_family="
                f"{lane['summary_family']!r}"
            )
        lane["frontier_role"] = expected
    return {**catalog, "lanes": lanes}


def _selected(catalog: dict, profile: str, lane_set: str, explicit: str) -> list[dict]:
    by_id = {lane["lane_id"]: lane for lane in catalog["lanes"]}
    if explicit.strip():
        ids = [part.strip() for part in explicit.split(",") if part.strip()]
        if len(ids) != len(set(ids)):
            raise SystemExit("explicit lanes must be duplicate-free")
        unknown = [lane_id for lane_id in ids if lane_id not in by_id]
        if unknown:
            raise SystemExit("unknown explicit lane(s): " + ", ".join(unknown))
        selected = [by_id[lane_id] for lane_id in ids]
        catalog_only = [
            lane["lane_id"] for lane in selected if lane["status_class"] == "catalog-only"
        ]
        if catalog_only:
            raise SystemExit(
                "catalog-only lane(s) are not executable until implemented: "
                + ", ".join(catalog_only)
            )
    else:
        if profile == "targeted" and lane_set == "all":
            raise SystemExit("profile=targeted requires a named lane_set or explicit lanes")
        selected = [
            lane for lane in catalog["lanes"]
            if lane["status_class"] == "active"
            and lane_set in lane.get("lane_sets", [])
            and (profile != "frontier" or lane.get("frontier_default", True))
        ]
        if profile == "frontier" and lane_set != "all":
            selected = [
                lane for lane in selected
                if lane_set in lane.get("frontier_lane_sets", lane.get("lane_sets", []))
            ]
        if profile == "frontier" and lane_set == "all":
            selected = [
                lane for lane in catalog["lanes"]
                if lane["status_class"] == "active"
                and lane.get("frontier_default", True)
            ]
        if profile == "checkpoint" and lane_set == "all":
            selected = [lane for lane in catalog["lanes"] if lane["status_class"] == "active"]
    return selected


def lane_payload(lane: dict, profile: str) -> dict:
    return {
        "lane_id": lane["lane_id"],
        "lane_phase": profile,
        "groups": lane["groups"],
        "lane_sets": lane["lane_sets"],
        "summary_family": lane["summary_family"],
        "frontier_role": lane["frontier_role"],
        "status_class": lane["status_class"],
        "setup_class": lane["setup_class"],
        "working_directory": lane["working_directory"],
        "script_path": lane["script_path"],
        "script_args": lane["script_args"],
        "timeout_minutes": lane["timeout_minutes"],
        "always_upload_artifact": lane["always_upload_artifact"],
        "contract": lane.get("contract", {}),
    }


def plan(args: argparse.Namespace) -> None:
    if args.profile not in PROFILE_BANDS:
        raise SystemExit("profile must be one of: targeted, frontier, checkpoint")
    if args.fanout_tier not in FANOUT_CAPS:
        raise SystemExit("fanout-tier must be one of: balanced, enterprise, soak")
    catalog = normalize_catalog(load_catalog(Path(args.catalog_path) if args.catalog_path else default_catalog_path()))
    selected_specs = _selected(catalog, args.profile, args.lane_set, args.lanes)
    selected = [lane_payload(lane, args.profile) for lane in selected_specs]
    cap = min(PROFILE_BANDS[args.profile]["cap"], FANOUT_CAPS[args.fanout_tier])
    if len(selected) > 256:
        raise SystemExit("validation plan exceeds the 256-lane safety cap")
    setup_counts = Counter(lane["setup_class"] for lane in selected)
    families = {
        family: {
            "sentinel": sorted(
                lane["lane_id"] for lane in selected
                if lane["summary_family"] == family and lane["frontier_role"] == "sentinel"
            ),
            "depth": sorted(
                lane["lane_id"] for lane in selected
                if lane["summary_family"] == family and lane["frontier_role"] == "depth"
            ),
        }
        for family in sorted({lane["summary_family"] for lane in selected})
    }
    if args.profile == "frontier" and not selected:
        raise SystemExit("frontier selection is empty; refusing false success")
    payload = {
        "profile": args.profile,
        "profile_intent": PROFILE_BANDS[args.profile]["intent"],
        "lane_set": args.lane_set,
        "fanout_tier": args.fanout_tier,
        "matrix_fail_fast": "true" if PROFILE_BANDS[args.profile]["fail_fast"] else "false",
        "matrix_max_parallel": str(cap),
        "fanout_cap": cap,
        "selected_lane_ids": [lane["lane_id"] for lane in selected],
        "selected_matrix": {"include": selected},
        "planned_matrix": {"include": selected},
        "selected_setup_classes": sorted(setup_counts),
        "setup_counts": dict(sorted(setup_counts.items())),
        "summary_families": families,
        "planned_job_count": len(selected),
        "run_selected_lanes": "true" if selected else "false",
        "lane_summary": f"profile={args.profile}, lane_set={args.lane_set}, selected={len(selected)}, cap={cap}",
    }
    print(json.dumps(payload, separators=(",", ":")))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    lab = sub.add_parser("lab")
    lab.add_argument("--profile", required=True)
    lab.add_argument("--lane-set", required=True)
    lab.add_argument("--lanes", default="")
    lab.add_argument("--fanout-tier", default="enterprise")
    lab.add_argument("--catalog-path", default="")
    lab.set_defaults(func=plan)
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
