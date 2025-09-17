# 🚀 Quick Setup Guide for Team Members

## Prerequisites (Must Have)
- **Docker**: Install from [docker.com](https://docker.com)
- **Git**: For cloning the repository

## One-Command Setup

```bash
# 1. Clone the repository
git clone <your-repo-url>
cd fyp_autovulrepair

# 2. Build the container (takes 5-8 minutes first time)
docker build -t autovulrepair:latest .

# 3. Test it works
./test_module1.sh
```

## Usage

### Scan Your C/C++ Code
```bash
# Replace /path/to/your/code with your actual code directory
docker run --rm \
  -v $(pwd)/artifacts:/app/artifacts \
  -v /path/to/your/code:/app/src \
  autovulrepair:latest \
  /app/pipeline/static_scan.sh /app/src
```

### View Results
```bash
# Check the generated report
ls artifacts/
cat artifacts/vulnerability-report-*.json | jq '.summary'
```

## What You Get
- **Cppcheck**: Fast static analysis
- **CodeQL**: Deep security analysis  
- **Classified Results**: Vulnerabilities sorted by severity
- **JSON Reports**: Machine-readable output

## Troubleshooting

### Build Issues
- **Docker not found**: Install Docker Desktop
- **Permission denied**: Run with `sudo` on Linux
- **Network timeout**: Check internet connection

### Scan Issues
- **No results**: Make sure your code directory has .cpp/.c files
- **CodeQL fails**: Ensure your code compiles with g++

## Support
If you encounter issues, check the full README.md or contact the project maintainer.
