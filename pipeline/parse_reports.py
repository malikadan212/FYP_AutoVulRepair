#!/usr/bin/env python3
"""
Vulnerability Report Parser and Classifier
Parses Cppcheck XML and CodeQL SARIF reports to classify vulnerabilities by type and severity
"""

import json
import xml.etree.ElementTree as ET
import sys
import os
from datetime import datetime
from typing import Dict, List, Any
from dataclasses import dataclass, asdict
from enum import Enum

class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class VulnType(Enum):
    BUFFER_OVERFLOW = "buffer_overflow"
    MEMORY_LEAK = "memory_leak"
    NULL_POINTER = "null_pointer_dereference"
    USE_AFTER_FREE = "use_after_free"
    INTEGER_OVERFLOW = "integer_overflow"
    FORMAT_STRING = "format_string"
    INJECTION = "injection"
    UNINITIALIZED_VAR = "uninitialized_variable"
    RESOURCE_LEAK = "resource_leak"
    RACE_CONDITION = "race_condition"
    OTHER = "other"

@dataclass
class Vulnerability:
    id: str
    type: VulnType
    severity: Severity
    message: str
    file_path: str
    line: int
    column: int
    cwe_id: str = ""
    tool: str = ""
    rule_id: str = ""
    description: str = ""

class VulnerabilityClassifier:
    """Classifies vulnerabilities based on patterns and CWE mappings"""
    
    # CWE to vulnerability type mapping
    CWE_MAPPING = {
        "CWE-120": VulnType.BUFFER_OVERFLOW,  # Buffer Copy without Checking Size of Input
        "CWE-121": VulnType.BUFFER_OVERFLOW,  # Stack-based Buffer Overflow
        "CWE-122": VulnType.BUFFER_OVERFLOW,  # Heap-based Buffer Overflow
        "CWE-401": VulnType.MEMORY_LEAK,      # Memory Leak
        "CWE-476": VulnType.NULL_POINTER,     # NULL Pointer Dereference
        "CWE-416": VulnType.USE_AFTER_FREE,   # Use After Free
        "CWE-190": VulnType.INTEGER_OVERFLOW, # Integer Overflow
        "CWE-134": VulnType.FORMAT_STRING,    # Format String Vulnerability
        "CWE-457": VulnType.UNINITIALIZED_VAR, # Use of Uninitialized Variable
        "CWE-404": VulnType.RESOURCE_LEAK,    # Resource Leak
        "CWE-362": VulnType.RACE_CONDITION,   # Race Condition
    }
    
    # Keyword patterns for classification
    KEYWORD_PATTERNS = {
        VulnType.BUFFER_OVERFLOW: ["buffer", "overflow", "strcpy", "strcat", "sprintf", "gets"],
        VulnType.MEMORY_LEAK: ["memory leak", "not freed", "allocated"],
        VulnType.NULL_POINTER: ["null", "nullptr", "dereference"],
        VulnType.USE_AFTER_FREE: ["use after free", "freed memory"],
        VulnType.UNINITIALIZED_VAR: ["uninitialized", "not initialized"],
        VulnType.RESOURCE_LEAK: ["resource leak", "file not closed", "handle leak"],
    }
    
    # Severity mapping based on error types
    SEVERITY_MAPPING = {
        "error": Severity.HIGH,
        "warning": Severity.MEDIUM,
        "style": Severity.LOW,
        "performance": Severity.LOW,
        "portability": Severity.LOW,
        "information": Severity.INFO,
    }

    def classify_vulnerability(self, message: str, severity_hint: str = "", cwe_id: str = "") -> tuple[VulnType, Severity]:
        """Classify vulnerability type and severity based on message content and hints"""
        
        # First try CWE mapping
        if cwe_id and cwe_id in self.CWE_MAPPING:
            vuln_type = self.CWE_MAPPING[cwe_id]
        else:
            # Fall back to keyword matching
            vuln_type = VulnType.OTHER
            message_lower = message.lower()
            
            for vtype, keywords in self.KEYWORD_PATTERNS.items():
                if any(keyword in message_lower for keyword in keywords):
                    vuln_type = vtype
                    break
        
        # Determine severity
        if severity_hint.lower() in self.SEVERITY_MAPPING:
            severity = self.SEVERITY_MAPPING[severity_hint.lower()]
        else:
            # Default severity based on vulnerability type
            if vuln_type in [VulnType.BUFFER_OVERFLOW, VulnType.USE_AFTER_FREE, VulnType.NULL_POINTER]:
                severity = Severity.HIGH
            elif vuln_type in [VulnType.MEMORY_LEAK, VulnType.RESOURCE_LEAK]:
                severity = Severity.MEDIUM
            else:
                severity = Severity.LOW
                
        return vuln_type, severity

class CppcheckParser:
    """Parser for Cppcheck XML reports"""
    
    def __init__(self, classifier: VulnerabilityClassifier):
        self.classifier = classifier
    
    def parse(self, xml_file: str) -> List[Vulnerability]:
        """Parse Cppcheck XML report and return list of vulnerabilities"""
        vulnerabilities = []
        
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            
            for error in root.findall('.//error'):
                # Extract error details
                error_id = error.get('id', 'unknown')
                severity = error.get('severity', 'unknown')
                msg = error.get('msg', '')
                cwe = error.get('cwe', '')
                
                # Get location info
                location = error.find('location')
                if location is not None:
                    file_path = location.get('file', '')
                    line = int(location.get('line', 0))
                    column = int(location.get('column', 0))
                else:
                    file_path = ''
                    line = 0
                    column = 0
                
                # Classify vulnerability
                vuln_type, vuln_severity = self.classifier.classify_vulnerability(
                    msg, severity, f"CWE-{cwe}" if cwe else ""
                )
                
                vulnerability = Vulnerability(
                    id=f"cppcheck-{error_id}-{line}",
                    type=vuln_type,
                    severity=vuln_severity,
                    message=msg,
                    file_path=file_path,
                    line=line,
                    column=column,
                    cwe_id=f"CWE-{cwe}" if cwe else "",
                    tool="cppcheck",
                    rule_id=error_id
                )
                
                vulnerabilities.append(vulnerability)
                
        except ET.ParseError as e:
            print(f"Error parsing Cppcheck XML: {e}")
        except FileNotFoundError:
            print(f"Cppcheck report file not found: {xml_file}")
            
        return vulnerabilities

class CodeQLParser:
    """Parser for CodeQL SARIF reports"""
    
    def __init__(self, classifier: VulnerabilityClassifier):
        self.classifier = classifier
    
    def parse(self, sarif_file: str) -> List[Vulnerability]:
        """Parse CodeQL SARIF report and return list of vulnerabilities"""
        vulnerabilities = []
        
        try:
            with open(sarif_file, 'r') as f:
                sarif_data = json.load(f)
            
            for run in sarif_data.get('runs', []):
                for result in run.get('results', []):
                    rule_id = result.get('ruleId', 'unknown')
                    message = result.get('message', {}).get('text', '')
                    level = result.get('level', 'note')
                    
                    # Get location info
                    locations = result.get('locations', [])
                    if locations:
                        location = locations[0]
                        physical_location = location.get('physicalLocation', {})
                        artifact_location = physical_location.get('artifactLocation', {})
                        region = physical_location.get('region', {})
                        
                        file_path = artifact_location.get('uri', '')
                        line = region.get('startLine', 0)
                        column = region.get('startColumn', 0)
                    else:
                        file_path = ''
                        line = 0
                        column = 0
                    
                    # Map CodeQL levels to severity
                    severity_map = {
                        'error': 'error',
                        'warning': 'warning',
                        'note': 'information'
                    }
                    
                    # Classify vulnerability
                    vuln_type, vuln_severity = self.classifier.classify_vulnerability(
                        message, severity_map.get(level, 'information')
                    )
                    
                    vulnerability = Vulnerability(
                        id=f"codeql-{rule_id}-{line}",
                        type=vuln_type,
                        severity=vuln_severity,
                        message=message,
                        file_path=file_path,
                        line=line,
                        column=column,
                        tool="codeql",
                        rule_id=rule_id
                    )
                    
                    vulnerabilities.append(vulnerability)
                    
        except json.JSONDecodeError as e:
            print(f"Error parsing CodeQL SARIF: {e}")
        except FileNotFoundError:
            print(f"CodeQL report file not found: {sarif_file}")
            
        return vulnerabilities

class ReportGenerator:
    """Generate consolidated vulnerability reports"""
    
    def generate_summary(self, vulnerabilities: List[Vulnerability]) -> Dict[str, Any]:
        """Generate vulnerability summary statistics"""
        total = len(vulnerabilities)
        
        # Count by severity
        severity_counts = {}
        for severity in Severity:
            severity_counts[severity.value] = sum(1 for v in vulnerabilities if v.severity == severity)
        
        # Count by type
        type_counts = {}
        for vtype in VulnType:
            type_counts[vtype.value] = sum(1 for v in vulnerabilities if v.type == vtype)
        
        # Count by tool
        tool_counts = {}
        for vuln in vulnerabilities:
            tool_counts[vuln.tool] = tool_counts.get(vuln.tool, 0) + 1
        
        return {
            "total_vulnerabilities": total,
            "severity_breakdown": severity_counts,
            "type_breakdown": type_counts,
            "tool_breakdown": tool_counts,
            "scan_timestamp": datetime.now().isoformat()
        }
    
    def save_json_report(self, vulnerabilities: List[Vulnerability], output_file: str):
        """Save vulnerabilities as JSON report"""
        data = {
            "summary": self.generate_summary(vulnerabilities),
            "vulnerabilities": [asdict(v) for v in vulnerabilities]
        }
        
        with open(output_file, 'w') as f:
            json.dump(data, f, indent=2, default=str)
        
        print(f"[*] JSON report saved to: {output_file}")

def main():
    if len(sys.argv) < 3:
        print("Usage: python3 parse_reports.py <cppcheck_xml> <codeql_sarif>")
        sys.exit(1)
    
    cppcheck_file = sys.argv[1]
    codeql_file = sys.argv[2]
    
    # Initialize components
    classifier = VulnerabilityClassifier()
    cppcheck_parser = CppcheckParser(classifier)
    codeql_parser = CodeQLParser(classifier)
    report_generator = ReportGenerator()
    
    # Parse reports
    print("[*] Parsing Cppcheck report...")
    cppcheck_vulns = cppcheck_parser.parse(cppcheck_file)
    print(f"[*] Found {len(cppcheck_vulns)} issues in Cppcheck report")
    
    print("[*] Parsing CodeQL report...")
    codeql_vulns = codeql_parser.parse(codeql_file)
    print(f"[*] Found {len(codeql_vulns)} issues in CodeQL report")
    
    # Combine vulnerabilities
    all_vulnerabilities = cppcheck_vulns + codeql_vulns
    
    # Generate reports
    output_dir = os.path.dirname(cppcheck_file) or "/app/artifacts"
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    json_report = os.path.join(output_dir, f"vulnerability-report-{timestamp}.json")
    
    report_generator.save_json_report(all_vulnerabilities, json_report)
    
    # Print summary
    summary = report_generator.generate_summary(all_vulnerabilities)
    print("\n" + "="*50)
    print("VULNERABILITY SCAN SUMMARY")
    print("="*50)
    print(f"Total Vulnerabilities: {summary['total_vulnerabilities']}")
    print("\nSeverity Breakdown:")
    for severity, count in summary['severity_breakdown'].items():
        if count > 0:
            print(f"  {severity.upper()}: {count}")
    
    print("\nVulnerability Types:")
    for vtype, count in summary['type_breakdown'].items():
        if count > 0:
            print(f"  {vtype.replace('_', ' ').title()}: {count}")
    
    print(f"\nDetailed report: {json_report}")

if __name__ == "__main__":
    main()
