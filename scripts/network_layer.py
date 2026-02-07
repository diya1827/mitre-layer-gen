#!/usr/bin/env python3

import os
import json
import re
import argparse
from collections import defaultdict
from typing import Any, Dict, List, Optional, Tuple

import yaml

# --------------------------------------------------
# Configuration
# --------------------------------------------------

# Match MITRE technique IDs like T1059 or T1059.001
TECHNIQUE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)

# Rippling severity → Navigator score
SEVERITY_TO_SCORE = {
    "sev0": 100,
    "sev1": 90,
    "sev2": 70,
    "sev3": 40,
    "sev4": 20,
}

#   Network platforms we want to include (folder names under app/detections)
NETWORK_PLATFORMS = {
    "Cloudflare",
    "Netcraft",
    "Datadog",
}


# Directories to skip
EXCLUDE_DIRS = {
    ".git", ".github", ".codebuild", ".cursor", ".hooks", ".hooks_scripts",
    "__pycache__", ".venv", "venv", "node_modules", "dist", "build",
    "docs", "infra", "templates", "tests",
    "global_helpers", "procedures", "schemas", "signals", "watchdogs",
}

# YAML field names
SEVERITY_KEYS = ["Severity", "severity"]
TECHNIQUE_KEYS = ["MitreTechniques"]


# --------------------------------------------------
# Helpers
# --------------------------------------------------

def iter_yaml_files(root: str) -> List[str]:
    """
    Find YAML files ONLY under network platform directories.

    Expected structure:
      app/detections/<NetworkPlatform>/<rule_name>/*.yaml
    """
    results: List[str] = []
    root = os.path.abspath(root)

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in EXCLUDE_DIRS]

        rel_path = os.path.relpath(dirpath, root)
        parts = rel_path.split(os.sep)

        # Network platform must be the first folder under detections
        if parts:
            platform = parts[0].lower().replace("_", "").replace(" ", "")
            allowed = {p.lower() for p in NETWORK_PLATFORMS}

            if platform not in allowed:
               continue


        for filename in filenames:
            if filename.lower().endswith((".yml", ".yaml")):
                results.append(os.path.join(dirpath, filename))

    return sorted(results)


def read_yaml(path: str) -> Tuple[Optional[Dict[str, Any]], str]:
    with open(path, "r", encoding="utf-8") as f:
        raw = f.read()
    try:
        obj = yaml.safe_load(raw)
        return obj if isinstance(obj, dict) else None, raw
    except Exception:
        return None, raw


def get_first_string(d: Dict[str, Any], keys: List[str]) -> Optional[str]:
    for key in keys:
        value = d.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def get_severity(d: Optional[Dict[str, Any]]) -> str:
    if not d:
        return "unknown"
    sev = get_first_string(d, SEVERITY_KEYS)
    return sev.lower() if sev else "unknown"


def normalize_techniques(value: Any) -> List[str]:
    techniques: List[str] = []

    if isinstance(value, str):
        techniques.extend(TECHNIQUE_RE.findall(value))
    elif isinstance(value, list):
        for item in value:
            if isinstance(item, str):
                techniques.extend(TECHNIQUE_RE.findall(item))

    return sorted({t.upper() for t in techniques})


def get_techniques(d: Optional[Dict[str, Any]], raw_text: str) -> List[str]:
    if d:
        for key in TECHNIQUE_KEYS:
            if key in d:
                techs = normalize_techniques(d[key])
                if techs:
                    return techs

    # fallback scan
    return sorted({t.upper() for t in TECHNIQUE_RE.findall(raw_text)})


def severity_to_score(severity: str) -> int:
    return SEVERITY_TO_SCORE.get(severity.lower(), 50)


# --------------------------------------------------
# Navigator Layer Builder
# --------------------------------------------------

def build_layer(layer_name: str, technique_data: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    techniques = []

    for tid in sorted(technique_data.keys()):
        info = technique_data[tid]
        techniques.append({
            "techniqueID": tid,
            "score": info["score"],
            "comment": info["comment"],
            "metadata": [
                {"name": "detections_count", "value": str(info["count"])},
                {"name": "max_severity", "value": info["max_severity"]},
            ],
        })

    return {
        "name": layer_name,
        "domain": "enterprise-attack",
        "description": "Auto-generated network-only ATT&CK coverage from Rippling detections.",
        "gradient": {"minValue": 0, "maxValue": 100},
        "layout": {"layout": "side"},
        "hideDisabled": False,
        "techniques": techniques,
    }


# --------------------------------------------------
# Main
# --------------------------------------------------

def main(repo_root: str, out_path: str, layer_name: str):
    yaml_files = iter_yaml_files(repo_root)
    if not yaml_files:
        raise SystemExit("No Network detection YAML files found.")

    max_score = defaultdict(int)
    max_severity = defaultdict(lambda: "unknown")
    counts = defaultdict(int)
    examples = defaultdict(list)

    parsed = 0
    skipped = 0

    for path in yaml_files:
        data, raw = read_yaml(path)
        severity = get_severity(data)
        techniques = get_techniques(data, raw)

        if not techniques:
            skipped += 1
            continue

        parsed += 1
        score = severity_to_score(severity)
        rule_dir = os.path.basename(os.path.dirname(path))
        rule_file = os.path.basename(path)

        for tid in techniques:
            counts[tid] += 1

            if len(examples[tid]) < 5:
                examples[tid].append(f"{rule_dir}/{rule_file}")

            if score > max_score[tid]:
                max_score[tid] = score
                max_severity[tid] = severity

    technique_data: Dict[str, Dict[str, Any]] = {}

    for tid in counts:
        technique_data[tid] = {
            "score": max_score[tid],
            "max_severity": max_severity[tid],
            "count": counts[tid],
            "comment": (
                f"detections={counts[tid]}; "
                f"max_sev={max_severity[tid]}; "
                f"examples={', '.join(examples[tid])}"
            ),
        }

    layer = build_layer(layer_name, technique_data)

    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(layer, f, indent=2)

    print(f"Network detections parsed: {parsed}")
    print(f"Skipped (no techniques): {skipped}")
    print(f"Layer written to: {out_path}")
    print(f"Techniques in layer: {len(layer['techniques'])}")


# --------------------------------------------------
# CLI
# --------------------------------------------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Generate network-only MITRE ATT&CK Navigator layer from Rippling detections."
    )
    parser.add_argument(
        "--repo",
        required=True,
        help="Local path to secops-cheetah/app/detections",
    )
    parser.add_argument(
        "--out",
        default="out/layers/coverage_network.json",
        help="Output Navigator layer JSON path",
    )
    parser.add_argument(
        "--name",
        default="Coverage - Network",
        help="Navigator layer name",
    )

    args = parser.parse_args()
    main(args.repo, args.out, args.name)
