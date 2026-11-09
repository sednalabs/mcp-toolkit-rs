#!/usr/bin/env python3
"""Require the archived webhook feature graph to match its test-only Cargo lock."""

import argparse
import json
from pathlib import Path
import tomllib


REQUIRED_FEATURES = {"gzip", "brotli", "zstd", "deflate", "native-tls"}
REQUIRED_PACKAGES = {"native-tls", "async-compression", "compression-codecs", "brotli", "zstd"}


def check(metadata, lock):
    packages = {package["id"]: package for package in metadata["packages"]}
    nodes = {node["id"]: node for node in metadata["resolve"]["nodes"]}
    reqwest = [p for p in packages.values() if p["name"] == "reqwest"]
    if len(reqwest) != 1:
        raise ValueError("expected one resolved reqwest version")
    features = set(nodes[reqwest[0]["id"]]["features"])
    if missing := REQUIRED_FEATURES - features:
        raise ValueError(f"missing reqwest features: {sorted(missing)}")
    resolved = [packages[identifier] for identifier in nodes]
    if missing := REQUIRED_PACKAGES - {p["name"] for p in resolved}:
        raise ValueError(f"missing unified packages: {sorted(missing)}")
    locked = {(p["name"], p["version"], p.get("source")) for p in lock["package"]}
    for package in resolved:
        identity = (package["name"], package["version"], package.get("source"))
        if identity not in locked:
            raise ValueError(f"resolved package absent from archived lock: {identity}")
    return {
        "reqwest_version": reqwest[0]["version"],
        "reqwest_features": sorted(features),
        "resolved_packages": len(resolved),
        "lock_matches_resolved_graph": True,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--metadata", type=Path, required=True)
    parser.add_argument("--lock", type=Path, required=True)
    args = parser.parse_args()
    result = check(
        json.loads(args.metadata.read_text()),
        tomllib.loads(args.lock.read_text()),
    )
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
