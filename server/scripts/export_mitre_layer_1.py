#!/usr/bin/env python3
"""
MITRE ATT&CK Navigator Layer Export Script.

Generates a MITRE ATT&CK Navigator layer JSON file from UEBA detection rules.
This allows visualization of rule coverage in the MITRE Navigator tool.

Usage:
    python export_mitre_layer.py [--output exports/mitre_layer.json]

Output:
    JSON file compatible with MITRE ATT&CK Navigator (https://mitre-attack.github.io/attack-navigator/)
"""

import argparse
import json
import logging
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

try:
    import yaml
except ImportError:
    print("ERROR: PyYAML not installed. Run: pip install pyyaml")
    sys.exit(1)

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)


# MITRE ATT&CK Tactic ID to Name mapping
TACTIC_ID_MAP = {
    "TA0001": "Initial Access",
    "TA0002": "Execution",
    "TA0003": "Persistence",
    "TA0004": "Privilege Escalation",
    "TA0005": "Defense Evasion",
    "TA0006": "Credential Access",
    "TA0007": "Discovery",
    "TA0008": "Lateral Movement",
    "TA0009": "Collection",
    "TA0010": "Exfiltration",
    "TA0011": "Command and Control",
    "TA0040": "Impact",
    "TA0042": "Resource Development",
    "TA0043": "Reconnaissance",
}

# Reverse mapping: Tactic Name to ID
TACTIC_NAME_MAP = {v: k for k, v in TACTIC_ID_MAP.items()}


def load_rules_from_yaml(rules_path: Path) -> List[Dict[str, Any]]:
    """Load all rules from YAML files in the given path."""
    rules = []
    
    if rules_path.is_file():
        files = [rules_path]
    else:
        files = list(rules_path.glob("*.yaml")) + list(rules_path.glob("*.yml"))
    
    for yaml_file in files:
        try:
            with open(yaml_file, 'r', encoding='utf-8') as f:
                content = yaml.safe_load(f)
            
            if content is None:
                continue
            
            # Handle 'rules' key wrapper
            if isinstance(content, dict) and 'rules' in content:
                rules.extend(content['rules'])
            elif isinstance(content, list):
                rules.extend(content)
            else:
                rules.append(content)
                
            logger.info(f"Loaded rules from {yaml_file.name}")
        except Exception as e:
            logger.error(f"Failed to load {yaml_file}: {e}")
    
    return rules


def extract_techniques_from_rules(rules: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    """
    Extract MITRE techniques from rules and count coverage.
    
    Returns:
        Dict mapping technique_id -> {count, rules, tactics, name}
    """
    techniques: Dict[str, Dict[str, Any]] = defaultdict(lambda: {
        "count": 0,
        "rules": [],
        "tactics": set(),
        "name": ""
    })
    
    for rule in rules:
        if not rule.get('enabled', True):
            continue
        
        rule_id = rule.get('id', 'unknown')
        rule_name = rule.get('name', 'Unknown Rule')
        
        mitre_list = rule.get('mitre', [])
        
        for mitre in mitre_list:
            technique_id = mitre.get('technique_id', '')
            technique_name = mitre.get('technique', '')
            tactic = mitre.get('tactic', '')
            
            if not technique_id:
                continue
            
            # Normalize technique ID (ensure T prefix)
            if not technique_id.startswith('T'):
                technique_id = f"T{technique_id}"
            
            techniques[technique_id]["count"] += 1
            techniques[technique_id]["rules"].append({
                "id": rule_id,
                "name": rule_name
            })
            techniques[technique_id]["name"] = technique_name
            
            # Map tactic name to ID if needed
            if tactic:
                if tactic.startswith("TA"):
                    techniques[technique_id]["tactics"].add(tactic)
                elif tactic in TACTIC_NAME_MAP:
                    techniques[technique_id]["tactics"].add(TACTIC_NAME_MAP[tactic])
    
    # Convert sets to lists for JSON serialization
    for tech_id in techniques:
        techniques[tech_id]["tactics"] = list(techniques[tech_id]["tactics"])
    
    return dict(techniques)


def generate_navigator_layer(
    techniques: Dict[str, Dict[str, Any]],
    layer_name: str = "Blueberry UEBA Detection Coverage",
    layer_description: str = "MITRE ATT&CK coverage from UEBA detection rules"
) -> Dict[str, Any]:
    """
    Generate MITRE ATT&CK Navigator layer JSON.
    
    Args:
        techniques: Dict of technique_id -> coverage info
        layer_name: Name for the layer
        layer_description: Description for the layer
        
    Returns:
        Navigator layer JSON structure
    """
    # Calculate max count for color scaling
    max_count = max((t["count"] for t in techniques.values()), default=1)
    
    # Build techniques array for Navigator
    nav_techniques = []
    for tech_id, info in techniques.items():
        # Calculate score (1-100 based on rule count)
        # More rules = higher score = darker color
        score = min(100, int((info["count"] / max_count) * 100))
        if score < 10:
            score = 10  # Minimum visibility
        
        # Build comment with rule details
        rule_names = [f"- {r['id']}: {r['name']}" for r in info["rules"]]
        comment = f"Covered by {info['count']} rule(s):\n" + "\n".join(rule_names)
        
        # Handle sub-techniques (e.g., T1003.001)
        base_technique = tech_id.split('.')[0]
        
        nav_techniques.append({
            "techniqueID": tech_id,
            "score": score,
            "color": "",  # Let Navigator use gradient
            "comment": comment,
            "enabled": True,
            "metadata": [],
            "links": [],
            "showSubtechniques": '.' in tech_id
        })
    
    # Navigator layer structure
    layer = {
        "name": layer_name,
        "versions": {
            "attack": "14",  # ATT&CK version
            "navigator": "4.9.1",
            "layer": "4.5"
        },
        "domain": "enterprise-attack",
        "description": layer_description,
        "filters": {
            "platforms": [
                "Windows"
            ]
        },
        "sorting": 0,
        "layout": {
            "layout": "side",
            "aggregateFunction": "average",
            "showID": True,
            "showName": True,
            "showAggregateScores": True,
            "countUnscored": False
        },
        "hideDisabled": False,
        "techniques": nav_techniques,
        "gradient": {
            "colors": [
                "#ffffff",  # White (no coverage)
                "#66b3ff",  # Light blue (low coverage)
                "#0066cc",  # Medium blue
                "#003366"   # Dark blue (high coverage)
            ],
            "minValue": 0,
            "maxValue": 100
        },
        "legendItems": [
            {"label": "No coverage", "color": "#ffffff"},
            {"label": "1 rule", "color": "#66b3ff"},
            {"label": "2-3 rules", "color": "#0066cc"},
            {"label": "4+ rules", "color": "#003366"}
        ],
        "metadata": [
            {
                "name": "Generated",
                "value": datetime.utcnow().isoformat() + "Z"
            },
            {
                "name": "Total Techniques",
                "value": str(len(techniques))
            },
            {
                "name": "Total Rules",
                "value": str(sum(t["count"] for t in techniques.values()))
            }
        ],
        "links": [],
        "showTacticRowBackground": True,
        "tacticRowBackground": "#dddddd",
        "selectTechniquesAcrossTactics": True,
        "selectSubtechniquesWithParent": False
    }
    
    return layer


def print_coverage_summary(techniques: Dict[str, Dict[str, Any]]):
    """Print a summary of technique coverage."""
    print("\n" + "=" * 60)
    print("MITRE ATT&CK COVERAGE SUMMARY")
    print("=" * 60)
    
    # Group by tactic
    tactic_coverage: Dict[str, List[str]] = defaultdict(list)
    for tech_id, info in techniques.items():
        for tactic in info["tactics"]:
            tactic_name = TACTIC_ID_MAP.get(tactic, tactic)
            tactic_coverage[tactic_name].append(tech_id)
    
    print(f"\nTotal Techniques Covered: {len(techniques)}")
    print(f"Total Rule Mappings: {sum(t['count'] for t in techniques.values())}")
    
    print("\nCoverage by Tactic:")
    print("-" * 40)
    for tactic_name in sorted(tactic_coverage.keys()):
        techs = tactic_coverage[tactic_name]
        print(f"  {tactic_name}: {len(techs)} techniques")
    
    print("\nTop 10 Most Covered Techniques:")
    print("-" * 40)
    sorted_techs = sorted(techniques.items(), key=lambda x: x[1]["count"], reverse=True)[:10]
    for tech_id, info in sorted_techs:
        print(f"  {tech_id} ({info['count']} rules): {info['name'][:50]}")
    
    print("=" * 60 + "\n")


def main():
    parser = argparse.ArgumentParser(
        description="Generate MITRE ATT&CK Navigator layer from UEBA detection rules"
    )
    parser.add_argument(
        "--rules-path",
        type=str,
        default=None,
        help="Path to rules YAML file or directory (default: server/config/rules/)"
    )
    parser.add_argument(
        "--output",
        type=str,
        default=None,
        help="Output JSON file path (default: exports/mitre_layer_blueberry_ueba.json)"
    )
    parser.add_argument(
        "--name",
        type=str,
        default="Blueberry UEBA Detection Coverage",
        help="Layer name"
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress summary output"
    )
    
    args = parser.parse_args()
    
    # Determine paths
    script_dir = Path(__file__).parent
    project_root = script_dir.parent
    
    if args.rules_path:
        rules_path = Path(args.rules_path)
    else:
        rules_path = project_root / "config" / "rules"
    
    if args.output:
        output_path = Path(args.output)
    else:
        exports_dir = project_root / "exports"
        exports_dir.mkdir(exist_ok=True)
        output_path = exports_dir / "mitre_layer_blueberry_ueba.json"
    
    # Load rules
    logger.info(f"Loading rules from: {rules_path}")
    rules = load_rules_from_yaml(rules_path)
    
    if not rules:
        logger.error("No rules found!")
        sys.exit(1)
    
    logger.info(f"Loaded {len(rules)} rules")
    
    # Extract techniques
    techniques = extract_techniques_from_rules(rules)
    
    if not techniques:
        logger.warning("No MITRE techniques found in rules!")
    else:
        logger.info(f"Found {len(techniques)} unique techniques")
    
    # Print summary
    if not args.quiet:
        print_coverage_summary(techniques)
    
    # Generate layer
    layer = generate_navigator_layer(
        techniques,
        layer_name=args.name,
        layer_description=f"MITRE ATT&CK coverage from {len(rules)} UEBA detection rules"
    )
    
    # Write output
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(layer, f, indent=2)
    
    logger.info(f"Navigator layer written to: {output_path}")
    print(f"\n✅ MITRE Navigator layer exported to: {output_path}")
    print(f"   Open in MITRE ATT&CK Navigator: https://mitre-attack.github.io/attack-navigator/")
    print(f"   Click 'Open Existing Layer' -> 'Upload from Local' -> select the JSON file")


if __name__ == "__main__":
    main()
