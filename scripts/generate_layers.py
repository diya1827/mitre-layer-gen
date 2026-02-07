#!/usr/bin/env python3
import os
import json  # navigator layer in json format
import re   #regex to catch the technique format 
import argparse
from collections import defaultdict
from typing import Any, Dict, List, Optional, Tuple

import yaml

TECHNIQUE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE) #regex to catch the technique format 

SEVERITY_TO_SCORE = {
    "Sev0": 100,
    "Sev1": 90,
    "Sev2": 70,
    "Sev3": 40,
    "Sev4": 20,
}

EXCLUDE_DIRS = {
    # VCS / tooling
    ".git",
    ".github",
    ".codebuild",
    ".cursor",
    ".hooks",
    ".hooks_scripts",

    # Python / node junk
    "__pycache__",
    ".venv",
    "venv",
    "node_modules",
    "dist",
    "build",

    # Non-detection project dirs
    "docs",
    "infra",
    "templates",
    "tests",

    # App subdirs we don't want to parse as detections
    "global_helpers",
    "procedures",
    "schemas",
    "signals",
    "watchdogs",
}

# If your yaml uses different key names, add them here:
SEVERITY_KEYS = ["Severity", "severity"]
TECHNIQUE_KEYS = ["MitreTechniques"]


def iter_yaml_files(root: str) -> List[str]: #find all yaml files in the repo
    out = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in EXCLUDE_DIRS]
        for fn in filenames:
            if fn.lower().endswith((".yml", ".yaml")):
                out.append(os.path.join(dirpath, fn))
    return sorted(out)


def read_yaml(path: str) -> Tuple[Optional[Dict[str, Any]], str]: #read the yaml file and return the object and the raw text
    raw = open(path, "r", encoding="utf-8").read()
    try:
        obj = yaml.safe_load(raw)
        if isinstance(obj, dict):
            return obj, raw
        else:
            return None, raw
    except Exception:
        return None, raw


def get_first_str(d: Dict[str, Any], keys: List[str]) -> Optional[str]: #get the first string from the dictionary
    for k in keys:
        v = d.get(k)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return None


def get_severity(d: Optional[Dict[str, Any]]) -> str: #get the severity from the dictionary
    if not d:
        return "unknown"
    s = get_first_str(d, SEVERITY_KEYS)
    return s.lower() if s else "unknown"


def normalize_techniques(value: Any) -> List[str]: #normalize the techniques to the format T1059, T1110.001, T1059, T1110
    """
    Handles technique stored as:
    - "T1059"
    - ["T1059", "T1110.001"]
    - "T1059, T1110"
    """
    techs: List[str] = []
    if isinstance(value, str):
        techs = [t.upper() for t in TECHNIQUE_RE.findall(value)]
    elif isinstance(value, list):
        for item in value:
            if isinstance(item, str):
                techs.extend([t.upper() for t in TECHNIQUE_RE.findall(item)])
    return sorted(set(techs))


def get_techniques(d: Optional[Dict[str, Any]], raw_text: str) -> List[str]:
    # Prefer structured keys if present
    if d:
        for k in TECHNIQUE_KEYS:
            if k in d:
                techs = normalize_techniques(d[k])
                if techs:
                    return techs

    # Fallback: regex scan entire yaml text
    return sorted(set(t.upper() for t in TECHNIQUE_RE.findall(raw_text)))


def severity_score(sev: str) -> int:
    return SEVERITY_TO_SCORE.get(sev.lower(), 50)


def build_layer(layer_name: str, technique_info: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    techniques_arr = []
    for tid in sorted(technique_info.keys()):
        info = technique_info[tid]
        techniques_arr.append({
            "techniqueID": tid,
            "score": int(info["score"]),
            "comment": info["comment"],
            "metadata": [
                {"name": "detections_count", "value": str(info["count"])},
                {"name": "max_severity", "value": info["max_severity"]},
            ],
        })

    return {
        "name": layer_name,
        "domain": "enterprise-attack",
        "description": "Auto-generated from detection YAML files in repo (technique + severity).",
        "gradient": {"minValue": 0, "maxValue": 100},
        "layout": {"layout": "side"},
        "hideDisabled": False,
        "techniques": techniques_arr,
    }


def main(repo_root: str, out_path: str, layer_name: str):
    yaml_files = iter_yaml_files(repo_root)
    if not yaml_files:
        raise SystemExit(f"No .yaml/.yml files found under: {repo_root}")

    # technique_id -> track max score, count, examples
    max_score: Dict[str, int] = defaultdict(int)
    max_sev: Dict[str, str] = defaultdict(lambda: "unknown")
    counts: Dict[str, int] = defaultdict(int)
    examples: Dict[str, List[str]] = defaultdict(list)

    parsed_files = 0
    skipped_no_technique = 0

    for ypath in yaml_files:
        d, raw = read_yaml(ypath)
        sev = get_severity(d)
        techs = get_techniques(d, raw)

        if not techs:
            skipped_no_technique += 1
            continue

        parsed_files += 1
        score = severity_score(sev)
        det_name = os.path.basename(os.path.dirname(ypath))  # folder name as detection name
        file_name = os.path.basename(ypath)

        for tid in techs:
            counts[tid] += 1
            if len(examples[tid]) < 5:
                examples[tid].append(f"{det_name}/{file_name}")

            if score > max_score[tid]:
                max_score[tid] = score
                max_sev[tid] = sev

    technique_info: Dict[str, Dict[str, Any]] = {} 
    for tid in counts.keys():
        comment = f"detections={counts[tid]}; max_sev={max_sev[tid]}; examples={', '.join(examples[tid])}"
        technique_info[tid] = {
            "score": max_score[tid],
            "max_severity": max_sev[tid],
            "count": counts[tid],
            "comment": comment,
        }

    layer = build_layer(layer_name, technique_info)

    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(layer, f, indent=2)

    print(f"Parsed YAML files with techniques: {parsed_files}")
    print(f"Skipped YAML files (no techniques found): {skipped_no_technique}")
    print(f"Wrote layer: {out_path}")
    print(f"Techniques in layer: {len(layer['techniques'])}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", required=True, help="https://github.com/Rippling/secops-cheetah/tree/main/app/detections")
    ap.add_argument("--out", default="out/layers/coverage_all.json", help="Output layer JSON path")
    ap.add_argument("--name", default="Coverage - All", help="Navigator layer name")
    args = ap.parse_args()
    main(args.repo, args.out, args.name)
