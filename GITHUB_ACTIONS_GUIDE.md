# 🚀 GitHub Actions User Guide

## Quick Start for GitHub Actions Users

This guide is for users who want to use AutoVulRepair through GitHub Actions without any local setup.

## 📋 Prerequisites

**Nothing!** Just a GitHub repository with C/C++ code.

## 🔧 Setup (One-Time)

### **Step 1: Fork or Use This Repository**

**Option A: Fork this repository**
```bash
# Fork the repository on GitHub, then clone your fork
git clone https://github.com/YOUR-USERNAME/FYP_AutoVulRepair.git
cd FYP_AutoVulRepair
```

**Option B: Copy workflow to your existing repository**
```bash
# Copy just the workflow file to your C/C++ project
mkdir -p .github/workflows
curl -o .github/workflows/auto-scan-repair.yml \
  https://raw.githubusercontent.com/YOUR-ORG/FYP_AutoVulRepair/main/.github/workflows/auto-scan-repair.yml
```

### **Step 2: Add Your C/C++ Code**
```bash
# Add your C/C++ files to the repository
cp -r /path/to/your/cpp/project/* .
git add .
git commit -m "Add C/C++ project for vulnerability scanning"
git push origin main
```

## 🎯 How to Use

### **Automatic Scanning (Recommended)**

The workflow **automatically triggers** on:
- **Push to `main` or `develop`** branches
- **Pull requests to `main`** branch

Just push your code and the scan runs automatically!

```bash
# Make changes to your C/C++ code
vim src/my_program.cpp

# Commit and push
git add .
git commit -m "Update C++ code"
git push origin main

# 🎉 Workflow automatically starts scanning!
```

### **Manual Scanning with Tool Selection**

1. Go to **Actions** tab in your GitHub repository
2. Click **"Auto-scan & Detect"** workflow
3. Click **"Run workflow"** button
4. Choose your scanning tool:
   - **`cppcheck`** - Fast scan (~30 seconds)
   - **`codeql`** - Thorough scan (~2-5 minutes)  
   - **`both`** - Comprehensive scan (default)
5. Click **"Run workflow"**

## 📊 Understanding Results

### **Where to Find Results**

#### **1. GitHub Actions Summary**
- Go to **Actions** → Click on your workflow run
- View the **Summary** section for overview
- See detailed breakdown by severity and type

#### **2. Pull Request Comments**
When you create a PR, you'll get an automatic comment like:
```markdown
## 🔍 Vulnerability Scan Results

### 📊 Detection Summary
- **Total vulnerabilities**: 5
- **Critical**: 1
- **High**: 2
- **Medium**: 2
- **Low**: 0

### 🚨 Critical Vulnerabilities - Module 3 Ready
- **Critical vulnerabilities file**: `critical-vulnerabilities-20241007-213000.json`
- **Files requiring dynamic analysis**: 2
- **Status**: Ready for Module 3 (Dynamic Analysis)

### ⚠️ Action Required
This PR introduces **3 critical/high severity vulnerabilities**.
Please review and fix these issues before merging.
```

#### **3. Downloadable Artifacts**
- **Vulnerability Reports**: `vulnerability-report-*.json`
- **Critical Issues File**: `critical-vulnerabilities-*.json` (for Module 3)
- **Raw Tool Output**: `cppcheck-report-*.xml`, `codeql-report-*.sarif`

### **Security Gate Behavior**

| **Severity** | **Build Status** | **Action** |
|-------------|------------------|------------|
| **Critical** | ❌ **FAILS** | Must fix before merge |
| **High (>3)** | ⚠️ **WARNING** | Consider fixing |
| **Medium/Low** | ✅ **PASSES** | Optional fixes |

## 🔧 Configuration Options

### **Set Default Scanning Tool**

1. Go to **Settings** → **Variables** → **Repository variables**
2. Add variable:
   - **Name**: `SCAN_TOOL`
   - **Value**: `cppcheck`, `codeql`, or `both`

This sets the default tool for automatic scans (push/PR triggers).

### **Customize Security Gate**

Edit `.github/workflows/auto-scan-repair.yml`:

```yaml
# Fail build on critical vulnerabilities
if [ "$CRITICAL" -gt 0 ]; then
  exit 1
# Warn on high vulnerabilities (change threshold here)
elif [ "$HIGH" -gt 3 ]; then  # Change 3 to your preferred threshold
  echo "Warning: High severity vulnerabilities found"
fi
```

### **Exclude Files/Directories**

Modify the file detection in the workflow:
```bash
# Exclude vendor and third-party directories
git diff --name-only $BASE_SHA HEAD -- '*.cpp' '*.c' '*.h' ':!vendor/' ':!third_party/'
```

## 📁 Artifacts and Module 3 Integration

### **Generated Files**

Every scan produces:

1. **`vulnerability-report-TIMESTAMP.json`**
   - Complete scan results
   - All severities included
   - Tool breakdown and statistics

2. **`critical-vulnerabilities-TIMESTAMP.json`** ⭐
   - **Module 3 input file**
   - Only critical vulnerabilities
   - Dynamic analysis targets
   - Test case suggestions

### **Module 3 Ready Files**

The critical vulnerabilities file contains:
```json
{
  "metadata": {
    "total_critical": 3,
    "purpose": "Input for Module 3 - Dynamic Analysis"
  },
  "critical_vulnerabilities": [...],
  "dynamic_analysis_targets": {
    "files_to_analyze": ["src/unsafe.cpp", "src/buffer.cpp"],
    "test_cases_needed": [
      "Test src/unsafe.cpp:45 with oversized input",
      "Boundary testing for buffer at src/buffer.cpp:23"
    ],
    "analysis_suggestions": [
      "Use fuzzing tools (AFL, libFuzzer) to test buffer boundaries",
      "Use AddressSanitizer (ASan) for use-after-free detection"
    ]
  }
}
```

## 🎯 Common Workflows

### **Development Workflow**
```bash
# 1. Create feature branch
git checkout -b feature/new-functionality

# 2. Write C/C++ code
vim src/new_feature.cpp

# 3. Commit and push
git add .
git commit -m "Add new feature"
git push origin feature/new-functionality

# 4. Create PR
# → Automatic scan runs
# → Results appear in PR comment
# → Fix any critical/high issues
# → Merge when clean
```

### **Security Review Workflow**
```bash
# 1. Manual comprehensive scan
# Go to Actions → Auto-scan & Detect → Run workflow → Select "both"

# 2. Download artifacts
# Actions → Workflow run → Artifacts section

# 3. Review critical vulnerabilities file
# Use for Module 3 dynamic analysis

# 4. Address findings and re-scan
```

## 🚨 Troubleshooting

### **Workflow Not Running**
- ✅ Check that `.github/workflows/auto-scan-repair.yml` exists
- ✅ Verify you're pushing to `main` or `develop` branch
- ✅ Ensure GitHub Actions are enabled in repository settings

### **No Vulnerabilities Detected**
- ✅ **Good news!** Your code might be secure
- ✅ Check that C/C++ files were actually changed
- ✅ Review workflow logs for any analysis errors

### **Build Failing on Critical Issues**
- ✅ Download the `critical-vulnerabilities-*.json` file
- ✅ Review each critical vulnerability
- ✅ Fix the issues in your code
- ✅ Push fixes to re-trigger scan

### **False Positives**
- ✅ Review the specific vulnerability details
- ✅ Consider adjusting tool configurations
- ✅ Add code comments explaining why it's safe (if applicable)

## 📈 Best Practices

### **For Individual Developers**
1. **Create PRs** for all changes (triggers automatic scanning)
2. **Fix critical issues** immediately
3. **Review scan results** before requesting code review
4. **Use manual scans** for comprehensive security audits

### **For Teams**
1. **Set repository variables** for consistent tool selection
2. **Establish security policies** (e.g., no merging with critical issues)
3. **Regular security reviews** using manual comprehensive scans
4. **Use artifacts** for security documentation and compliance

## 🎓 Example: Complete User Journey

**Sarah, a C++ developer, wants to add a new feature:**

1. **Forks the repository**
   ```bash
   git clone https://github.com/sarah/FYP_AutoVulRepair.git
   cd FYP_AutoVulRepair
   ```

2. **Adds her C++ project**
   ```bash
   cp -r ~/my-cpp-app/* src/
   git add .
   git commit -m "Add my C++ application"
   ```

3. **Creates a feature branch**
   ```bash
   git checkout -b feature/user-authentication
   # Writes new authentication code
   git add .
   git commit -m "Add user authentication module"
   git push origin feature/user-authentication
   ```

4. **Creates a Pull Request**
   - GitHub automatically runs the vulnerability scan
   - PR comment shows: "2 critical vulnerabilities found"
   - Critical vulnerabilities file is generated

5. **Fixes the issues**
   ```bash
   # Reviews the critical vulnerabilities
   # Fixes buffer overflow in authentication code
   git add .
   git commit -m "Fix buffer overflow in auth module"
   git push origin feature/user-authentication
   ```

6. **Scan passes, PR approved**
   - New scan shows: "0 critical vulnerabilities"
   - PR is approved and merged
   - Code is now secure!

---

**🎉 That's it! You now have automated vulnerability scanning with zero setup required. The system will catch security issues early and provide detailed guidance for fixes.**
