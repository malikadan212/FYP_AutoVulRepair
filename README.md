# FYP AutoVulRepair - Automated Vulnerability Detection and Repair

## Overview
This Final Year Project implements an automated system for detecting and repairing security vulnerabilities in C/C++ code using static analysis tools and machine learning techniques.

## Module 1 - Static Analysis Pipeline ✅

### Features Implemented
- **Multi-tool Static Analysis**: Integration of Cppcheck and CodeQL for comprehensive vulnerability detection
- **Vulnerability Classification**: Automatic categorization by type (buffer overflow, memory leak, etc.) and severity (critical, high, medium, low)
- **CVE Knowledge Base**: Structured database of Common Vulnerabilities and Exposures for pattern matching
- **Docker Containerization**: Consistent analysis environment with all required tools
- **CI/CD Integration**: GitHub Actions workflow for automated scanning
- **Comprehensive Reporting**: JSON reports with detailed vulnerability information and statistics

### Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Source Code   │───▶│  Static Analysis │───▶│ Classification  │
│   (C/C++)      │    │   (Cppcheck +    │    │   & Reporting   │
└─────────────────┘    │    CodeQL)       │    └─────────────────┘
                       └──────────────────┘              │
                                                         ▼
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│ CVE Knowledge   │◀───│  Vulnerability   │◀───│   JSON Report   │
│     Base        │    │  Classification  │    │   Generation    │
└─────────────────┘    └──────────────────┘    └─────────────────┘
```

### Quick Start

#### Prerequisites
- Docker
- Git

#### Running the Analysis

1. **Build the container:**
   ```bash
   docker build -t autovulrepair:latest .
   ```

2. **Run analysis on sample code:**
   ```bash
   docker run --rm \
     -v $(pwd)/artifacts:/app/artifacts \
     -v $(pwd)/src:/app/src \
     autovulrepair:latest \
     /app/pipeline/static_scan.sh /app/src
   ```

3. **Run comprehensive test:**
   ```bash
   ./test_module1.sh
   ```

### Vulnerability Types Detected

| Type | CWE | Description | Severity |
|------|-----|-------------|----------|
| Buffer Overflow | CWE-120, CWE-121, CWE-122 | Unsafe string operations | High |
| Memory Leak | CWE-401 | Missing memory deallocation | Medium |
| Null Pointer Dereference | CWE-476 | Dereferencing null pointers | High |
| Use After Free | CWE-416 | Using freed memory | High |
| Integer Overflow | CWE-190 | Arithmetic overflow conditions | Medium |
| Format String | CWE-134 | Unsafe format string usage | Medium |
| Uninitialized Variable | CWE-457 | Using uninitialized variables | Low |
| Resource Leak | CWE-404 | Unclosed file handles/resources | Medium |

### Project Structure

```
fyp_autovulrepair/
├── pipeline/
│   ├── static_scan.sh          # Main scanning orchestrator
│   └── parse_reports.py        # Vulnerability classification engine
├── src/
│   └── test.cpp               # Sample vulnerable code
├── datasets/
│   ├── cve_knowledge_base.json # CVE patterns and repair strategies
│   └── vulnerable_samples.cpp  # Comprehensive test cases
├── .github/workflows/
│   └── static-analysis.yml    # CI/CD pipeline
├── Dockerfile                 # Container configuration
└── test_module1.sh           # Module testing script
```

### Sample Output

```json
{
  "summary": {
    "total_vulnerabilities": 5,
    "severity_breakdown": {
      "critical": 0,
      "high": 2,
      "medium": 2,
      "low": 1
    },
    "type_breakdown": {
      "buffer_overflow": 2,
      "memory_leak": 1,
      "null_pointer_dereference": 1,
      "uninitialized_variable": 1
    }
  },
  "vulnerabilities": [...]
}
```

### Tools Integration

#### Cppcheck
- **Purpose**: General static analysis for C/C++
- **Configuration**: All checks enabled, XML output
- **Strengths**: Fast, comprehensive rule coverage

#### CodeQL
- **Purpose**: Semantic analysis for security vulnerabilities
- **Configuration**: Security and quality rule suites
- **Strengths**: Deep semantic understanding, low false positives

### CI/CD Pipeline

The GitHub Actions workflow automatically:
1. Builds the analysis container
2. Runs static analysis on code changes
3. Generates vulnerability reports
4. Fails builds with critical/high severity issues
5. Uploads artifacts for review

### Next Steps - Module 2

- [ ] Implement automated vulnerability repair algorithms
- [ ] Add machine learning-based pattern recognition
- [ ] Develop repair strategy selection logic
- [ ] Create repair validation framework

### Testing

Run the comprehensive test suite:
```bash
./test_module1.sh
```

This validates:
- ✅ Docker container builds successfully
- ✅ Static analysis tools execute properly
- ✅ Vulnerability classification works
- ✅ Report generation functions
- ✅ CVE knowledge base integration

### Contributing

1. Fork the repository
2. Create a feature branch
3. Run tests: `./test_module1.sh`
4. Submit a pull request

### License

This project is part of a Final Year Project for academic purposes.

---

**Status**: Module 1 Complete ✅  
**Next**: Module 2 - Automated Vulnerability Repair