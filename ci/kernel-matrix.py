#!/usr/bin/env python3
"""Resolve moving release channels once per workflow; retain the JSON as an artifact."""

import json
import re
import sys
from urllib.request import urlopen


def upstream_matrix(metadata):
    rows = {}
    for release in metadata["releases"]:
        kind, version = release["moniker"], release["version"]
        if kind not in {"stable", "longterm", "mainline"} or release.get("iseol"):
            continue
        if not re.fullmatch(r"\d+\.\d+(?:\.\d+)?(?:-rc\d+)?", version):
            raise ValueError(f"Invalid kernel version: {version}")
        url = release["source"]
        if not url.startswith(("https://cdn.kernel.org/", "https://git.kernel.org/")):
            raise ValueError(f"Unexpected kernel source: {url}")
        # At a final release, mainline and stable can name the same tarball.
        # Prefer stable regardless of the feed's ordering.
        if version not in rows or kind == "stable":
            rows[version] = {"version": version, "channel": kind, "url": url}
    if not rows or not any(r["channel"] == "stable" for r in rows.values()):
        raise ValueError("No stable kernel in release metadata")
    return {"include": list(rows.values())}


def distro_matrix(metadata):
    rows = []
    for version, flavor, packages in [
        ("24.04", "ga", "linux-generic"),
        ("24.04", "hwe", "linux-generic-hwe-24.04"),
        ("26.04", "ga", "linux-generic"),
    ]:
        rows.append({
            "name": f"ubuntu-{version}-{flavor}",
            "url": f"https://cloud-images.ubuntu.com/releases/{version}/release/ubuntu-{version}-server-cloudimg-amd64.img",
            "packages": packages,
        })
    rows.append({
        "name": "debian-13",
        # generic includes the normal Debian kernel, not a restricted cloud flavor.
        "url": "https://cloud.debian.org/images/cloud/trixie/latest/debian-13-generic-amd64.qcow2",
        "packages": "linux-image-amd64 linux-headers-amd64",
    })
    fedora = {}
    for release in metadata:
        if (release.get("arch") == "x86_64"
                and release.get("subvariant") == "Cloud_Base"
                and re.fullmatch(r"\d+", release["version"])
                and release["link"].endswith(".qcow2")):
            fedora[int(release["version"])] = release
    if len(fedora) < 2:
        raise ValueError("Expected at least two released Fedora cloud images")
    for version in sorted(fedora, reverse=True)[:2]:
        release = fedora[version]
        if not release["link"].startswith("https://download.fedoraproject.org/"):
            raise ValueError("Unexpected Fedora download host")
        rows.append({
            "name": f"fedora-{version}", "url": release["link"],
            "sha256": release["sha256"],
            "packages": "kernel kernel-devel kernel-modules-extra",
        })
    return {"include": rows}


def fetch(url):
    with urlopen(url, timeout=60) as response:
        return json.load(response)


if __name__ == "__main__":
    # Optional files make resolution reproducible and testable without network.
    kernels = json.load(open(sys.argv[1])) if len(sys.argv) > 1 else fetch("https://www.kernel.org/releases.json")
    fedora = json.load(open(sys.argv[2])) if len(sys.argv) > 2 else fetch("https://fedoraproject.org/releases.json")
    print("upstream=" + json.dumps(upstream_matrix(kernels), separators=(",", ":")))
    print("distro=" + json.dumps(distro_matrix(fedora), separators=(",", ":")))
