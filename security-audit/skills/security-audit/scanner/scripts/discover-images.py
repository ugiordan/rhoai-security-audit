#!/usr/bin/env python3
"""Discover container images from opendatahub-operator manifests.

Clones the operator repo (or uses a local path) and extracts all
container image references from params.env and YAML manifests.
Outputs a list of scannable images to stdout or updates scan-config.yaml.

Usage:
    python3 discover-images.py                          # clone operator, print images
    python3 discover-images.py --operator-path /path    # use local operator checkout
    python3 discover-images.py --update-config           # update scan-config.yaml in-place
"""
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

IMAGE_RE = re.compile(r'(quay\.io/[a-zA-Z0-9._/-]+:[a-zA-Z0-9._-]+)')
REGISTRY_RE = re.compile(r'(registry\.redhat\.io/[a-zA-Z0-9._/-]+@sha256:[a-fA-F0-9]+)')

OPERATOR_REPO = "https://github.com/opendatahub-io/opendatahub-operator.git"

# Skip test/dev/scorecard images that aren't production
SKIP_PATTERNS = {
    "scorecard-test",
    "minio:",
    "s2i-minimal",
    "ktunnel",
    "mariadb",
    "origin-cli",
    "origin-oauth-proxy",
    "metadata-envoy",
    "metadata-grpc",
    "quay.io/org/",
    "quay.io/brancz/",
    "quay.io/modh/",
}


def extract_images_from_dir(operator_path: str) -> list[dict]:
    """Extract all container image references from operator manifests."""
    opt_dir = Path(operator_path) / "opt"
    if not opt_dir.exists():
        print(f"WARNING: {opt_dir} not found, trying to fetch manifests", file=sys.stderr)
        return []

    images = {}

    # Extract from params.env files
    for params_file in opt_dir.rglob("params.env"):
        component = params_file.parent.parent.name
        content = params_file.read_text()
        for match in IMAGE_RE.finditer(content):
            img = match.group(1)
            if not any(skip in img for skip in SKIP_PATTERNS):
                key = img.split(":")[0]
                if key not in images or len(img) > len(images[key]["image"]):
                    images[key] = {
                        "image": img,
                        "component": component,
                        "source": str(params_file.relative_to(operator_path)),
                    }

    # Extract from YAML manifests
    for yaml_file in opt_dir.rglob("*.yaml"):
        component = yaml_file.parts[len(opt_dir.parts)]
        content = yaml_file.read_text()
        for match in IMAGE_RE.finditer(content):
            img = match.group(1)
            if not any(skip in img for skip in SKIP_PATTERNS):
                key = img.split(":")[0]
                if key not in images:
                    images[key] = {
                        "image": img,
                        "component": str(component),
                        "source": str(yaml_file.relative_to(operator_path)),
                    }

    # Sort by component then image name
    result = sorted(images.values(), key=lambda x: (x["component"], x["image"]))
    return result


def clone_operator(branch: str = "main") -> str:
    """Clone the operator repo to a temp directory. Returns path."""
    tmpdir = tempfile.mkdtemp(prefix="odh-operator-")
    subprocess.run(
        ["git", "clone", "--depth", "1", "--branch", branch, OPERATOR_REPO, tmpdir],
        capture_output=True, text=True, timeout=120, check=True,
    )
    # Fetch manifests
    subprocess.run(
        ["make", "get-manifests"],
        cwd=tmpdir, capture_output=True, text=True, timeout=300,
    )
    return tmpdir


def update_scan_config(images: list[dict], config_path: str):
    """Update scan-config.yaml with discovered images."""
    import yaml

    with open(config_path) as f:
        config = yaml.safe_load(f)

    config["images"] = [img["image"] for img in images]

    with open(config_path, "w") as f:
        yaml.dump(config, f, default_flow_style=False, sort_keys=False)

    print(f"Updated {config_path} with {len(images)} images", file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(description="Discover container images from ODH operator")
    parser.add_argument("--operator-path", help="Path to local operator checkout")
    parser.add_argument("--branch", default="main", help="Branch to clone (default: main)")
    parser.add_argument("--update-config", action="store_true", help="Update scan-config.yaml")
    parser.add_argument("--config-path", default=None, help="Path to scan-config.yaml")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    args = parser.parse_args()

    tmpdir = None
    try:
        if args.operator_path:
            operator_path = args.operator_path
        else:
            print("Cloning opendatahub-operator...", file=sys.stderr)
            operator_path = clone_operator(args.branch)
            tmpdir = operator_path

        images = extract_images_from_dir(operator_path)

        if not images:
            print("No images found", file=sys.stderr)
            sys.exit(1)

        if args.json:
            print(json.dumps(images, indent=2))
        elif args.update_config:
            config_path = args.config_path or os.path.join(
                os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                "scan-config.yaml",
            )
            update_scan_config(images, config_path)
        else:
            # Group by component
            by_component = {}
            for img in images:
                comp = img["component"]
                by_component.setdefault(comp, []).append(img)

            for comp, imgs in sorted(by_component.items()):
                print(f"# {comp}")
                for img in imgs:
                    print(f"  {img['image']}")
                print()

            print(f"# Total: {len(images)} images from {len(by_component)} components",
                  file=sys.stderr)

    finally:
        if tmpdir:
            shutil.rmtree(tmpdir, ignore_errors=True)


if __name__ == "__main__":
    main()
