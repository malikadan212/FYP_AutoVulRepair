#!/usr/bin/env python3
"""
Generate Critical Vulnerabilities Report for Dynamic Analysis
Extracts critical vulnerabilities from the main report for Module 3 (Dynamic Analysis)
"""

import json
import sys
import os
from datetime import datetime
from pathlib import Path

def generate_critical_report(vulnerability_report_path, output_dir="artifacts"):
    """Generate a critical vulnerabilities file for dynamic analysis"""
    
    if not os.path.exists(vulnerability_report_path):
        print(f"Error: Vulnerability report not found at {vulnerability_report_path}")
        return None
    
    # Read the main vulnerability report
    with open(vulnerability_report_path, 'r') as f:
        main_report = json.load(f)
    
    # Extract critical vulnerabilities
    critical_vulns = []
    for vuln in main_report.get('vulnerabilities', []):
        if vuln.get('severity') == 'critical':
            critical_vulns.append(vuln)
    
    if not critical_vulns:
        print("[*] No critical vulnerabilities found - no critical file needed")
        return None
    
    # Generate critical vulnerabilities file
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    critical_file = os.path.join(output_dir, f"critical-vulnerabilities-{timestamp}.json")
    
    # Prepare data for dynamic analysis
    critical_data = {
        "metadata": {
            "generated_at": datetime.now().isoformat(),
            "total_critical": len(critical_vulns),
            "purpose": "Input for Module 3 - Dynamic Analysis",
            "source_report": os.path.basename(vulnerability_report_path),
            "module": "Critical Vulnerability Extraction",
            "version": "1.0"
        },
        "critical_vulnerabilities": [
            {
                "id": vuln.get('id'),
                "type": vuln.get('type'),
                "severity": vuln.get('severity'),
                "file_path": vuln.get('file_path'),
                "line": vuln.get('line'),
                "column": vuln.get('column'),
                "message": vuln.get('message'),
                "cwe_id": vuln.get('cwe_id'),
                "tool": vuln.get('tool'),
                "rule_id": vuln.get('rule_id'),
                "description": vuln.get('description'),
                "priority_score": calculate_priority_score(vuln)
            }
            for vuln in critical_vulns
        ],
        "dynamic_analysis_targets": generate_dynamic_targets(critical_vulns)
    }
    
    # Save critical vulnerabilities file
    os.makedirs(output_dir, exist_ok=True)
    with open(critical_file, 'w') as f:
        json.dump(critical_data, f, indent=2)
    
    print(f"[*] Critical vulnerabilities file generated: {critical_file}")
    print(f"[*] Found {len(critical_vulns)} critical vulnerabilities for dynamic analysis")
    
    return critical_file

def calculate_priority_score(vulnerability):
    """Calculate priority score for dynamic analysis (1-10, 10 = highest priority)"""
    base_score = 10  # Critical = highest priority
    
    # Adjust based on vulnerability type
    high_priority_types = [
        "buffer_overflow",
        "use_after_free", 
        "null_pointer_dereference"
    ]
    
    vuln_type = vulnerability.get('type', '')
    if vuln_type in high_priority_types:
        return base_score
    else:
        return base_score - 1

def generate_dynamic_targets(critical_vulns):
    """Generate targets and suggestions for dynamic analysis"""
    targets = {
        "files_to_analyze": list(set(v.get('file_path') for v in critical_vulns if v.get('file_path'))),
        "functions_to_test": [],
        "test_cases_needed": [],
        "analysis_suggestions": []
    }
    
    # Group by vulnerability type for targeted testing
    vuln_by_type = {}
    for v in critical_vulns:
        vtype = v.get('type', 'unknown')
        if vtype not in vuln_by_type:
            vuln_by_type[vtype] = []
        vuln_by_type[vtype].append(v)
    
    # Generate specific test suggestions
    for vtype, vulns in vuln_by_type.items():
        if vtype == "buffer_overflow":
            targets["test_cases_needed"].extend([
                f"Test {v.get('file_path')}:{v.get('line')} with oversized input",
                f"Boundary testing for buffer at {v.get('file_path')}:{v.get('line')}"
                for v in vulns if v.get('file_path') and v.get('line')
            ])
            targets["analysis_suggestions"].append(
                "Use fuzzing tools (AFL, libFuzzer) to test buffer boundaries"
            )
        
        elif vtype == "null_pointer_dereference":
            targets["test_cases_needed"].extend([
                f"Test {v.get('file_path')}:{v.get('line')} with NULL inputs",
                f"Memory allocation failure simulation at {v.get('file_path')}:{v.get('line')}"
                for v in vulns if v.get('file_path') and v.get('line')
            ])
            targets["analysis_suggestions"].append(
                "Use Valgrind or AddressSanitizer for runtime detection"
            )
        
        elif vtype == "use_after_free":
            targets["test_cases_needed"].extend([
                f"Test memory access patterns at {v.get('file_path')}:{v.get('line')}",
                f"Double-free detection at {v.get('file_path')}:{v.get('line')}"
                for v in vulns if v.get('file_path') and v.get('line')
            ])
            targets["analysis_suggestions"].append(
                "Use AddressSanitizer (ASan) for use-after-free detection"
            )
    
    return targets

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 generate_critical_report.py <vulnerability_report.json> [output_dir]")
        print("Example: python3 generate_critical_report.py artifacts/vulnerability-report-20241007-210000.json")
        sys.exit(1)
    
    vulnerability_report = sys.argv[1]
    output_dir = sys.argv[2] if len(sys.argv) > 2 else "artifacts"
    
    critical_file = generate_critical_report(vulnerability_report, output_dir)
    
    if critical_file:
        print(f"\n✅ Critical vulnerabilities report ready for Module 3")
        print(f"📁 File: {critical_file}")
        print(f"🎯 Ready for dynamic analysis pipeline")
    else:
        print(f"\n✅ No critical vulnerabilities found")
        print(f"🎯 No dynamic analysis needed")

if __name__ == "__main__":
    main()
