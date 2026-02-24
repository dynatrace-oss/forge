# Troubleshooting Guide

This document provides  troubleshooting guidance for common issues encountered when using FORGE for vulnerability research.

## 🔍 Quick Diagnostic Commands

Before diving into specific issues, run these commands to gather system information:

```bash
# System health check
python src/main.py health-check

# Environment information
python --version
podman --version || docker --version
python -c "import sys; print(f'Python Path: {sys.executable}')"

# Container runtime status
podman info | head -20
podman ps -a

# Network connectivity
ping -c 3 azure.openai.com
curl -I https://osv.dev/vulnerabilities

# Resource usage
df -h
free -h
ps aux | grep python | grep main.py
```

## ⚠️ Common Issues and Solutions

### Exploit Generation Issues

#### Issue: Exploit Scripts Generate Wrong Payloads (Python Recursion Errors)

**Symptoms:**

```bash
2025-10-14 13:32:14 - INFO - Creating malicious payload...
Traceback (most recent call last):
  File "exploit.py", line 87, in <module>
    tester.run_test()
  File "exploit.py", line 76, in run_test
    payload = self.create_malicious_payload()
RecursionError: maximum recursion depth exceeded
```

**Log Indicators:**

- "Successfully extracted PoC from commit/..." (fix commits being treated as PoC code)
- "Using PoC-enhanced generation" but exploit doesn't match vulnerability type
- Scripts with 10,000-level nested structures (`for _ in range(10000):`)

**Root Cause:**

- GitHub fix commits (showing how to PREVENT vulnerabilities) were being classified as "PoC code"
- LLM received fix code (e.g., "add 100k limit") and incorrectly generated deeply nested structures
- Example: CVE-2021-46877 fix added `LONGEST_EAGER_ALLOC = 100_000` → LLM generated 10,000-level nested JSON

**Solution (Fixed in v3 2025-10-14):**

1. Clear PoC cache to force re-extraction with new classification:

   ```bash
   rm -rf data/cache/poc_extraction_*
   ```

2. Check logs for proper fix commit classification:

   ```bash
   grep "Classified.*as FIX COMMIT" logs/gyros_*.log
   grep "Identified.*fix commits" logs/gyros_*.log
   ```

3. Verify GitHub context is being passed:

   ```bash
   grep "Added fix commit analysis to GitHub context" logs/gyros_*.log
   grep "FIX COMMIT ANALYSIS" logs/gyros_*.log
   ```

4. If issues persist, check:
   - Is the commit properly classified? Look for fix keywords in commit message
   - Is LLM receiving the GitHub context? Check "GITHUB REFERENCE CONTEXT" in logs
   - Review generated exploit script to see if it matches vulnerability mechanism

**Prevention:**

- New commit classification system automatically detects fix vs exploit commits
- Fix commits stored in `fix_commits_context` (not `poc_data_list`)
- LLM receives explicit guidance: "⚠️ This shows what was ADDED/CHANGED to prevent the vulnerability"

**Related Files:**

- [src/services/exploit_generation/poc_extraction_service.py:356-427](../src/services/exploit_generation/poc_extraction_service.py#L356-L427)
- [src/services/exploit_generation/exploit_script_generation_service.py:129-164](../src/services/exploit_generation/exploit_script_generation_service.py#L129-L164)
- [src/models/poc_data.py:137](../src/models/poc_data.py#L137)

---

### Container Build and Runtime Issues(Version)

#### Issue: Container Build Fails with "invalid target release: 17"

**Symptoms:**

```txt
Fatal error compiling: error: invalid target release: 17
openjdk version "11.0.x"
```

**Log Indicators:**

- "invalid target release" in Maven compiler errors
- POM specifies Java 17 but Containerfile uses Java 11 base image
- Affects Spring Framework 6.x packages (requires Java 17+)

**Root Cause:**

- Containerfile hardcoded Java 11, but POM correctly specified Java 17 for newer packages
- Spring Framework 6.x (org.springframework:spring-web 6.x) requires Java 17+
- Maven compiler inside Java 11 container tried to compile Java 17 code

**Solution (Fixed in v4.2 2025-10-15):**
The framework now automatically determines the correct Java version:

1. **For new builds**, the fix is automatic - framework uses correct Java version from package requirements
2. **For existing failed containers**, clean up and regenerate:

   ```bash
   # Remove old container directories
   rm -rf data/containers/vulnapp-*spring-web*

   # Remove old blueprints to force regeneration
   rm -f data/blueprints/*.json

   # Re-run the process command
   poetry run python src/main.py process --packages org.springframework:spring-web --cve-ids <CVE-ID> --auto-run
   ```

**Technical Details:**

- [src/templates/manager.py:1363-1384](../src/templates/manager.py#L1363-L1384) - Determines Java version via `_determine_spring_boot_version()`
- [src/templates/universal_containerfile.txt:5-6](../src/templates/universal_containerfile.txt#L5-L6) - Uses `${java_version}` variable
- [src/templates/core/standalone_jar.xml:81-82](../src/templates/core/standalone_jar.xml#L81-L82) - Compiler plugin uses variables

---

#### Issue: Container Build Fails with "manifest unknown: openjdk:17-jre-slim"

**Symptoms:**

```log
reading manifest 17-jre-slim in docker.io/library/openjdk: manifest unknown
Error: creating build container: initializing source docker://openjdk:17-jre-slim
```

**Log Indicators:**

- "manifest unknown" errors for openjdk Docker images
- Affects Java 17+ containers
- Build fails at container image pull stage

**Root Cause:**

- OpenJDK official Docker images were deprecated after Java 11
- Framework used `openjdk:17-jre-slim` which no longer exists on Docker Hub
- Docker Hub removed these images in 2021

**Solution (Fixed in v4.2 2025-10-15):**
The framework now uses Eclipse Temurin (maintained by Eclipse Adoptium):

1. **For new builds**, the fix is automatic - framework uses `eclipse-temurin` images
2. **For existing failed containers**, clean up and regenerate (same steps as above)

**Technical Details:**

- Java 17+: Uses `maven:3.9-eclipse-temurin-${java_version}` and `eclipse-temurin:${java_version}-jre`
- Java 8/11: Still uses `openjdk` images (still available)
- [src/templates/universal_containerfile.txt:5-6, 54-56](../src/templates/universal_containerfile.txt#L5-L56)
- [src/templates/manager.py:538-540](../src/templates/manager.py#L538-L540)

---

#### Issue: Maven Build Fails with "Could not find artifact io.undertow:undertow-core:jar:1.0.0"

**Symptoms:**

```log
[WARNING] The POM for io.undertow:undertow-core:jar:1.0.0 is missing, no dependency information available
Downloading from central: https://repo1.maven.org/maven2/io/undertow/undertow-core/1.0.0/undertow-core-1.0.0.jar
Downloaded from central: 404 Not Found
[ERROR] Failed to execute goal... Could not resolve dependencies
```

**Log Indicators:**

- "Using actual OSV version 1.0.0" for packages where 1.0.0 doesn't exist
- Maven 404 errors during dependency resolution
- OSV database returns invalid/non-existent version numbers

**Root Cause:**

- OSV (Open Source Vulnerabilities) database can contain invalid version data
- Example: `io.undertow:undertow-core` OSV returned "1.0.0" (doesn't exist - real versions are 2.x.x)
- Framework extracted versions from OSV without validating they exist in Maven Central
- This is a **data quality issue** in OSV, but framework should handle gracefully

**Solution (Fixed in v4.2 2025-10-15):**
The framework now validates all OSV versions against Maven Central with fallback strategies:

1. **Automatic Recovery** - Framework detects invalid versions and finds valid alternatives:

   ```txt
   Version 1.0.0 from OSV does NOT exist in Maven Central for io.undertow:undertow-core
   Attempting fallback version resolution strategies...
   Fallback resolution found valid version: 1.0.19.Final (via: match_major)
   ```

2. **Manual Override** (if automatic recovery fails):

   ```bash
   # Specify a known-good version manually
   poetry run python src/main.py process --packages io.undertow:undertow-core --version 2.2.25.Final --cve-ids <CVE-ID>
   ```

3. **Report to OSV** - If OSV data is consistently wrong:
   - Check OSV database manually: <https://osv.dev/>
   - Report data quality issues to OSV maintainers

**Validation Strategies** (in priority order):

1. **OSV versions array** → Validate with `maven_resolver.version_exists()` → Fallback to `resolve_version(strategy="match_major")`
2. **OSV ranges** → Extract introduced version → Validate exists
3. **Text parsing** → Extract from vulnerability description → Validate exists
4. **Last resort** → Use `MavenVersionResolver.resolve_version(strategy="latest")` (with warning)

**Technical Details:**

- [src/utils/support/osv_client.py:821-1030](../src/utils/support/osv_client.py#L821-L1030) - Version extraction with validation
- [src/services/dependency/maven_version_resolver.py:149-176](../src/services/dependency/maven_version_resolver.py#L149-L176) - Maven Central validation

**Example Recovery:**

- **Input**: OSV suggests `io.undertow:undertow-core:1.0.0` (invalid)
- **Validation**: Framework checks Maven Central → NOT FOUND
- **Fallback**: `MavenVersionResolver` finds matching major version `1.0.19.Final`
- **Result**: Container builds with valid version

---

#### Issue: Container Exits Immediately After Start

**Symptoms:**

```txt
Starting container for validation...
Failed to start container: Container exited immediately after start
Container vulnapp-xxx exited immediately after start
```

**Log Indicators:**

- Container builds successfully but exits immediately when run
- No application logs captured
- `podman ps -a` shows container in "Exited" state

**Root Cause Hypothesis:**
Based on analysis of spring-web 6.2.0 container:

1. **Spring Boot / Spring Framework Version Incompatibility:**
   - POM uses Spring Boot 2.7.15 (requires Java 8/11, Spring Framework 5.x)
   - BUT includes `spring-web:6.2.0` (Spring Framework 6.x, requires Java 17+ AND Spring Boot 3.x)
   - **Incompatibility**: Spring Framework 6.x cannot run with Spring Boot 2.x
   - Application fails at startup with classpath/dependency conflicts

2. **Other Possible Causes:**
   - Missing main class or incorrect `@SpringBootApplication` annotation
   - Port binding issues (port already in use)
   - Application configuration errors
   - Java version mismatch between build and runtime

**Solution (Framework Improvement Needed):**

**Immediate Workaround**:

```bash
# Check container logs for actual error
podman logs <container-name>

# Try running container manually to see startup errors
podman run --rm -p 8080:8080 <image-name>

# Inspect container for build artifacts
podman run --rm --entrypoint /bin/sh <image-name> -c "ls -la /app && java -version"
```

**Framework Fix Needed** (Not yet implemented):

1. **Version Compatibility Validation** - Check Spring Boot version matches Spring Framework version:
   - Spring Framework 6.x requires Spring Boot 3.x (Java 17+)
   - Spring Framework 5.x requires Spring Boot 2.x (Java 8/11/17)
   - Add validation in `_determine_spring_boot_version()` to ensure compatibility

2. **Enhanced Error Capture** - Capture container startup logs before container exits:
   - Modify container startup to keep container running even if app fails
   - Add `tail -f /dev/null` fallback in entrypoint script
   - Save startup logs to persistent volume

3. **Health Check Improvements** - Better startup failure detection:
   - Add startup timeout (currently 30s may be too short for some apps)
   - Capture and display application error traces
   - Provide actionable error messages

**Related Issues:**

- Similar to Java version mismatch issue (fixed)
- Similar to Docker image deprecation issue (fixed)
- **This issue remains UNFIXED** - containers build but don't run

**Technical Files:**

- [src/services/deployment/container_service.py](../src/services/deployment/container_service.py) - Container management
- [src/templates/universal_containerfile.txt:82-106](../src/templates/universal_containerfile.txt#L82-L106) - Entrypoint script
- [src/templates/manager.py:_determine_spring_boot_version()](../src/templates/manager.py) - Version determination logic

---

### Installation and Setup Issues

#### Issue: Poetry Installation Fails

**Symptoms:**

```bash
$ poetry install
Installing dependencies from lock file

Package operations: 45 installs, 0 updates, 0 removals

  • Installing ...
  [Errno 13] Permission denied: '/usr/local/lib/python3.x/site-packages'
```

**Solutions:**

```bash
# Solution 1: Use Python user directory
export POETRY_VENV_IN_PROJECT=true
poetry install

# Solution 2: Check Python permissions
which python3
ls -la $(which python3)

# Solution 3: Use virtual environment
python3 -m venv gyros-env
source gyros-env/bin/activate
pip install poetry
poetry install
```

#### Issue: LLM API Configuration Error

**Symptoms:**

```bash
$ python src/main.py process -p org.yaml:snakeyaml
ERROR: Azure OpenAI API key not configured
```

**Solutions:**

```bash
# Check environment variables
echo $AZURE_OPENAI_API_KEY
echo $AZURE_OPENAI_ENDPOINT

# Copy and configure .env file
cp .env.template .env
# Edit .env with your API credentials

# Verify API connectivity
curl -H "Authorization: Bearer $AZURE_OPENAI_API_KEY" \
     -H "Content-Type: application/json" \
     "$AZURE_OPENAI_ENDPOINT/openai/deployments?api-version=2023-05-15"
```

### Container Build and Runtime Issues

#### Issue: Container Build Timeout

**Symptoms:**

```bash
$ python src/main.py workflow --packages org.yaml:snakeyaml --auto-run
Building container for blueprint...
ERROR: Container build timeout after 300 seconds
```

**Solutions:**

```bash
# Solution 1: Increase build timeout via environment variable
export CONTAINER_BUILD_TIMEOUT=600
python src/main.py workflow --packages org.yaml:snakeyaml --auto-run

# Solution 2: Check container build logs
python src/main.py container --id <blueprint-id> --auto-run

# Solution 3: Manual build for debugging
cd data/blueprints/<blueprint-id>/
podman build -t debug-build .

# Solution 4: Clean up build cache
podman system prune -a -f
```

#### Issue: Port Already in Use

**Symptoms:**

```bash
$ python src/main.py container --id abc123 --run
ERROR: Port 8080 is already in use
```

**Solutions:**

```bash
# Check what's using the port
netstat -tuln | grep 8080
lsof -i :8080

# Use different port range
python src/main.py workflow --packages org.yaml:snakeyaml --auto-run --ports 8090-8100

# Stop conflicting containers
python src/main.py stop-all
podman stop --all
```

#### Issue: Container Fails to Start

**Symptoms:**

```bash
$ python src/main.py container --id abc123 --run
Container started but health check failed
```

**Solutions:**

```bash
# Manual container inspection
podman ps -a
podman logs <container-name>

# Debug container interactively
podman run -it --rm <image-name> /bin/bash

# Check container resource limits
podman stats <container-name>
```

### LLM and Content Generation Issues

#### Issue: LLM Generation Timeout

**Symptoms:**

```bash
$ python src/main.py process --packages org.yaml:snakeyaml
ERROR: LLM request timeout after 60 seconds
```

**Solutions:**

```bash
# Increase LLM timeout via environment variable
export LLM_EXPLOITATION_TIMEOUT=120
python src/main.py process --packages org.yaml:snakeyaml

# Check LLM service status
curl -I https://azure.openai.com/

# Test with simpler package
python src/main.py process --packages commons-io:commons-io --limit 1

# Enable debug mode for detailed logs
python src/main.py --debug process --packages org.yaml:snakeyaml
```

#### Issue: Invalid Generated Code

**Symptoms:**

```bash
$ python src/main.py workflow -p org.yaml:snakeyaml --auto-run
Container build failed: Compilation error in VulnApplication.java
```

**Solutions:**

```bash
# Check generated code
cat data/blueprints/<blueprint-id>/VulnApplication.java

# Validate template syntax
python src/main.py validate-templates

# Re-generate with different framework
python src/main.py process --packages org.yaml:snakeyaml --framework-type spring-boot

# Manual code review and correction
cd data/blueprints/<blueprint-id>/
# Edit Java files manually
podman build -t manual-fix .
```

#### Issue: Unknown Vulnerability Type

**Symptoms:**

- Logs show: `vulnerability_type: unknown`
- Validation confidence score very low (< 0.4)
- Message: "No patterns available for vulnerability type: unknown"
- Container builds and deploys successfully
- Exploit script executes but validation reports low confidence

**Log Indicators:**

```bash
WARNING - No patterns available for vulnerability type: unknown
INFO - Validation confidence: 0.25
DEBUG - vulnerability_type: unknown
```

**Root Cause:**

The CVE's CWE ID is not mapped in [src/utils/core/common.py:42-74](../src/utils/core/common.py#L42-L74). FORGE uses CWE-to-vulnerability-type mapping to select appropriate validation patterns and exploitation strategies.

**Solution:**

Check if the CWE is already mapped:

```bash
# Check current CWE mappings
grep "CWE-" src/utils/core/common.py | head -20

# Example output:
# if "CWE-502" in cwe_ids:  # Deserialization
# elif "CWE-113" in cwe_ids:  # HTTP Response Splitting
```

If not mapped, add custom mapping:

1. Edit [src/utils/core/common.py](../src/utils/core/common.py):

    ```python
    def extract_vulnerability_type_from_blueprint(blueprint) -> str:
        """Extract vulnerability type from blueprint CWE IDs."""

        if hasattr(blueprint, 'cwe_ids') and blueprint.cwe_ids:
            cwe_ids = blueprint.cwe_ids

            # ... existing mappings ...

            # Add your new mapping
            elif "CWE-XXX" in cwe_ids:  # Replace XXX with actual CWE number
                return "your_vulnerability_type"
    ```

2. Add patterns to [src/config/vulnerability_patterns.yaml](../src/config/vulnerability_patterns.yaml):

    ```yaml
    osv_patterns:
      your_vulnerability_type:
        - "pattern 1 from vulnerability descriptions"
        - "pattern 2 from CVE summaries"

    exploitation_indicators:
      your_vulnerability_type:
        - "indicator 1 from successful exploits"
        - "indicator 2 from logs"

    log_patterns:
      your_vulnerability_type:
        - "log.*pattern.*1"
        - "error.*pattern.*2"
    ```

3. Add validation context to [src/services/system/llm_validation_service.py](../src/services/system/llm_validation_service.py):

    ```python
    self.vulnerability_contexts = {
        # ... existing contexts ...

        "your_vulnerability_type": {
            "description": "Brief description of the vulnerability",
            "analysis_guidance": [
                "What to check for in execution results",
                "How to distinguish success from failure",
                "What evidence indicates trigger vs block"
            ],
            "key_question": "Main question to determine if vulnerability was demonstrated"
        }
    }
    ```

**Example: Adding CWE-843 (Type Confusion)**:

```python
# In src/utils/core/common.py
elif "CWE-843" in cwe_ids:
    return "type_confusion"

# In src/config/vulnerability_patterns.yaml
osv_patterns:
  type_confusion:
    - "type confusion"
    - "type safety"
    - "casting vulnerability"

exploitation_indicators:
  type_confusion:
    - "ClassCastException"
    - "type mismatch"
    - "unexpected type"
```

---

#### Issue: Header-Based Validation Failures

**Symptoms:**

- Container responds successfully (HTTP 200)
- Exploit script executes without errors
- Validation reports: `vulnerability_triggered: false`
- Logs: "HTTP response body contains benign content"
- Low confidence score despite successful HTTP request

**Log Indicators:**

```bash
INFO - HTTP Response: 200 OK
INFO - Response body: "File upload successful"
WARNING - No vulnerability indicators found in response body
DEBUG - vulnerability_triggered: false
DEBUG - confidence_score: 0.3
```

**Root Cause:**

The vulnerability manifests in HTTP **response headers**, not the response body. Common scenarios:

| Vulnerability | Header Location | What to Check |
|--------------|----------------|---------------|
| **RFD (Reflected File Download)** | Content-Disposition | Malicious filename reflection |
| **Session Fixation** | Set-Cookie | Session ID manipulation |
| **Open Redirect** | Location | Unvalidated redirect URL |
| **CRLF Injection** | Any header | \\r\\n sequences |

**Example: RFD Vulnerability**:

Incorrect validation (checks body):

```python
def check_vulnerability_indicators(self, response_content):
    if "Vulnerability triggered" in response_content:  # WRONG
        return True
    return False
```

**Solution:**

1. **Verify CWE-113 Mapping**:

    ```bash
    # Check if CWE is properly mapped
    grep "CWE-113" src/utils/core/common.py

    # Should return:
    # elif "CWE-113" in cwe_ids:  # Improper Neutralization of CRLF Sequences
    #     return "http_response_splitting"
    ```

2. **Check Validation Patterns**:

    ```bash
    # Verify header-specific patterns exist
    grep -A 5 "http_response_splitting:" src/config/vulnerability_patterns.yaml

    # Should include patterns like:
    # - "Content-Disposition"
    # - "attachment; filename="
    # - "CRLF injection"
    ```

3. **Verify LLM Validation Context**:

    The [LLM Validation Service](../src/services/system/llm_validation_service.py) includes header-specific guidance:

    ```python
    "http_response_splitting": {
        "analysis_guidance": [
            "CRITICAL: This vulnerability manifests in HTTP RESPONSE HEADERS, not the response body",
            "Check if user-controlled input appears in HTTP response headers",
            "For RFD: Verify if malicious filename is reflected in Content-Disposition header",
            "HTTP 200 status with benign body content is expected - focus on header manipulation"
        ]
    }
    ```

4. **Manual Fix for Exploit Script**:

If automated validation fails, manually edit the exploit script to check headers:

```bash
# Find exploit script
find data/exploit_scripts -name "CVE-*.py" -type f | sort -r | head -1

# Edit to check response headers
nano data/exploit_scripts/CVE-XXXX-XXXXX.py
```

Update script to inspect headers before body:

```python
# Check response headers first
content_disposition = response.headers.get('Content-Disposition', '')
if 'malicious' in content_disposition:
    print(f"Vulnerability triggered: {content_disposition}")
    return True

# Check Set-Cookie for session fixation
set_cookie = response.headers.get('Set-Cookie', '')
if malicious_session_id in set_cookie:
    print(f"Session fixation: {set_cookie}")
    return True

# Check Location for open redirect
location = response.headers.get('Location', '')
if malicious_redirect_url in location:
    print(f"Open redirect: {location}")
    return True
```

**Verification:**

Re-run validation and check for header analysis:

```bash
# Run validation with debug logging
python src/main.py --debug validate-exploit --id <blueprint-id>

# Check logs for header inspection
grep -i "header" logs/gyros_*.log | tail -20
grep -i "Content-Disposition" logs/gyros_*.log

# Success indicators:
# - "Analyzing response headers for vulnerability indicators"
# - "Found malicious filename in Content-Disposition"
# - "vulnerability_triggered: true"
```

**Prevention:**

When implementing new HTTP-based vulnerability types:

1. Always add header-specific guidance to LLM validation contexts
2. Include header patterns in [vulnerability_patterns.yaml](../src/config/vulnerability_patterns.yaml)
3. Update exploit script templates to check headers before body
4. Test with actual HTTP responses that have malicious headers

---

#### Issue: API Version Mismatch

**Symptoms:**

- Build failures with "API not found in version X" errors
- Import statements failing during compilation
- Struts or Spring version-specific compilation errors
- Logs show: "No API guidance found for version X.X.X"

**Log Indicators:**

```bash
WARNING - No API guidance found for package version 6.5.0
ERROR - Compilation error: cannot find symbol UploadedFile
ERROR - package org.apache.struts2.dispatcher.multipart does not exist
```

**Root Cause:**

The version-specific API guidance is missing or incorrect in the API reference YAML files. FORGE uses version-specific imports and patterns that changed between framework versions (e.g., Struts 6.3 vs 6.4+, Spring Framework 5.x vs 6.x).

**Solution:**

1. **Check Available API References**:

    ```bash
    # List available API reference files
    ls -la src/config/api_references/

    # Should show:
    # struts_version_apis.yaml
    # spring_version_apis.yaml
    ```

2. **Verify Version Coverage**:

    ```bash
    # Check which versions are covered for Struts
    grep -E "^\"[0-9]" src/config/api_references/struts_version_apis.yaml

    # Example output:
    # "6.0-6.3":    # Covered
    # "6.4+":       # Covered
    ```

3. **Add Missing Version Guidance**:

    Edit the appropriate API reference file [src/config/api_references/struts_version_apis.yaml](../src/config/api_references/struts_version_apis.yaml):

    ```yaml
    # Example: Adding Struts 6.5 specific APIs
    "6.5+":  # Matches 6.5.0 and above
    imports:
        - "org.apache.struts2.action.UploadedFilesAware"
        - "org.apache.struts2.dispatcher.HttpParameters"
    example_code: |
        // Struts 6.5+ file upload handling
        public class UploadAction implements UploadedFilesAware {
            private List<UploadedFile> uploadedFiles;

            @Override
            public void withUploadedFiles(List<UploadedFile> files) {
                this.uploadedFiles = files;
            }
        }
    notes: |
        - Struts 6.5+ uses UploadedFilesAware interface
        - HttpParameters replaces older parameter handling
    ```

4. **Verify APIReferenceLoader Integration**:

    ```python
    # Test API reference loading
    python -c "
    from utils.api_references.api_reference_loader import APIReferenceLoader

    loader = APIReferenceLoader()
    guidance = loader.get_version_guidance('org.apache.struts:struts2-core', '6.5.0')
    print(f'Guidance found: {guidance is not None}')
    print(f'Guidance content: {guidance[:200] if guidance else \"None\"}...')
    "
    ```

**Version Range Format:**

The API reference loader supports these version range formats:

| Format | Example | Matches |
|--------|---------|---------|
| Exact | "6.2.0" | Only 6.2.0 |
| Range | "6.0-6.3" | 6.0.x, 6.1.x, 6.2.x, 6.3.x |
| Plus | "6.4+" | 6.4.0 and all higher versions |
| Wildcard | "6.x" | All 6.x.x versions |

**Fallback Behavior:**

If no exact version match exists, the loader:

1. Checks for range matches (e.g., "6.0-6.3" includes 6.2.5)
2. Checks for plus matches (e.g., "6.4+" includes 6.5.0)
3. Falls back to closest lower version
4. Returns None if no guidance available

**Verification:**

Re-run blueprint generation and check logs:

```bash
# Run with debug logging
python src/main.py --debug process --packages org.apache.struts:struts2-core --limit 1

# Check for API guidance loading
grep "API guidance" logs/gyros_*.log | tail -10

# Success indicators:
# - "Loaded API guidance for Struts version 6.5.0"
# - "Using version-specific imports: UploadedFilesAware"
# - Compilation succeeds without import errors

# Failure indicators:
# - "No API guidance found for version 6.5.0"
# - "Using generic template without version-specific guidance"
```

**Quick Fix for Immediate Needs:**

If you need to proceed without waiting for API reference updates:

```bash
# Option 1: Use a supported version
python src/main.py process --packages org.apache.struts:struts2-core --version 6.3.0

# Option 2: Disable version-specific guidance temporarily
# (System will fall back to generic templates)
```

**Reference:**

- API Reference Loader: [src/utils/api_references/api_reference_loader.py](../src/utils/api_references/api_reference_loader.py)
- Struts API References: [src/config/api_references/struts_version_apis.yaml](../src/config/api_references/struts_version_apis.yaml)
- Spring API References: [src/config/api_references/spring_version_apis.yaml](../src/config/api_references/spring_version_apis.yaml)

---

#### Issue: Framework Detection Failure

**Symptoms:**

```bash
$ python src/main.py process --packages org.springframework:spring-core
WARNING: Could not determine optimal framework, using default
```

**Solutions:**

```bash
# Force framework type
python src/main.py process --packages org.springframework:spring-core --framework-type spring-boot

# Check framework detection patterns
cat src/templates/framework/detection_patterns.txt

# Enable debug logging
export LOG_LEVEL=DEBUG
python src/main.py --debug process --packages org.springframework:spring-core

# Test framework intelligence service
python -c "
from services.blueprint_management.framework_intelligence_service import FrameworkIntelligenceService
service = FrameworkIntelligenceService()
patterns = service._load_detection_patterns()
print(f'Loaded patterns: {list(patterns.keys())}')
"
```

### Validation and Exploit Issues

#### Issue: Validation Always Fails

**Symptoms:**

```bash
$ python src/main.py validate-exploit --id abc123
Validation completed: vulnerability_demonstrated = False
No security indicators found
```

**Solutions:**

```bash
# Check container accessibility
curl http://localhost:8080/
curl http://localhost:8080/health

# Test vulnerable endpoint manually
curl -X POST http://localhost:8080/api/vulnerable \
     -H "Content-Type: text/plain" \
     -d "test: data"

# Review generated exploit script
cat data/exploit_scripts/CVE-*-abc123.py

# Run exploit script manually
python3 data/exploit_scripts/CVE-*-abc123.py http://localhost:8080

# Debug validation service  
python src/main.py --debug validate-exploit --id abc123
```

#### Issue: Exploit Script Safety Violations

**Symptoms:**

```bash
$ python src/main.py validate-exploit --id abc123
ERROR: Generated script contains unsafe operations: subprocess
```

**Solutions:**

```bash
# Review safety validation rules
grep -r "subprocess" src/services/exploit_validation_service.py

# Check script content
cat data/exploit_scripts/CVE-*-abc123.py

# Manually review and edit script
# Remove unsafe operations
sed -i 's/subprocess\.//g' data/exploit_scripts/CVE-*-abc123.py

# Re-run validation
python src/main.py validate-exploit --id abc123
```

#### Issue: 405 Method Not Allowed Errors

**Symptoms:**

```bash
# Exploit execution logs show:
ERROR: HTTPError: 405 - Method Not Allowed
# Container appears to be running but exploit fails
# Validation reports: "No security indicators found"
```

**Root Cause:**

Exploit script is targeting the wrong endpoint due to endpoint extraction failures. Common scenarios:

1. Complex Spring Boot annotations with multiple parameters not being parsed correctly
2. Exploit targets root `/` when vulnerable endpoint is elsewhere (e.g., `/vulnerable`, `/api/exploit`)
3. Wrong HTTP method used (GET instead of POST, or vice versa)

**Diagnostic Steps:**

```bash
# 1. Check what endpoints were extracted
grep "Extracted.*endpoints from blueprint" logs/gyros_*.log | tail -1

# Expected: "Extracted 3 endpoints from blueprint: ['/vulnerable', '/', '/api/health']"
# Problem: "Extracted 2 endpoints from blueprint: ['/', '/api/health']" (missing /vulnerable!)

# 2. Examine the generated Java controller
find data/containers/vulnapp-* -name "*Controller.java" -exec cat {} \;

# Look for @PostMapping or @GetMapping annotations with 'value =' parameter

# 3. Check exploit script target URL
grep -n "url.*=" data/exploit_scripts/CVE-*.py | head -5

# 4. Test endpoints manually
CONTAINER_PORT=$(podman port $(podman ps -q --filter name=vulnapp) 2>/dev/null | cut -d: -f2 | head -1)
curl http://localhost:${CONTAINER_PORT}/
curl http://localhost:${CONTAINER_PORT}/api/health
curl -X POST http://localhost:${CONTAINER_PORT}/vulnerable \
     -H "Content-Type: application/json" \
     -d '{"test": "data"}'
```

**Solutions:**

**Immediate Fix** - Manually correct exploit script:

```bash
# Find and edit the exploit script
SCRIPT=$(find data/exploit_scripts -name "CVE-*.py" -type f | sort -r | head -1)
nano $SCRIPT

# Update the target URL line (typically around line 40-45):
# OLD: url = self.target_url
# NEW: url = self.target_url + "/vulnerable"

# Also check Content-Type header matches the endpoint requirements
```

**System Fix** - The framework should now automatically handle complex annotations. If issues persist:

```bash
# Check if you're running the latest version with endpoint extraction fixes
grep -A 5 "Endpoint Extraction Regex Enhancement" CHANGELOG.md

# If section exists, fixes are applied. If still seeing issues:
# 1. Clean rebuild
rm -rf data/containers/*
rm -f data/exploit_scripts/*

# 2. Re-run with debug logging
python src/main.py process --packages "your:package" --cve-ids "CVE-XXXX-YYYY" --limit 1 --validate --debug

# 3. Verify endpoint extraction in logs
grep -E "Extracted.*endpoints|extract.*endpoint|@PostMapping|@GetMapping" logs/gyros_*.log | tail -20
```

**Prevention:**

- Check logs immediately after blueprint creation for endpoint extraction warnings
- Look for: `No endpoints extracted from blueprint` warning
- Verify extracted endpoints include the vulnerable endpoint path
- Endpoint list should match the `@Mapping` annotations in generated Java files

**Related Issues:**

- See [Issue #285: Validation Always Fails](#issue-validation-always-fails)
- See [docs/poc-integration.md](./poc-integration.md) for endpoint detection details
- See CHANGELOG.md [2025-10-14-v2] for endpoint extraction enhancement details

#### Issue: PoC Extraction Fails

**Symptoms:**

```bash
$ python src/main.py workflow -p org.yaml:snakeyaml --auto-run
WARNING: No PoCs found for CVE-2022-1471
Using generic exploit generation
```

**Solutions:**

```bash
# Check GitHub API rate limits
curl -H "Authorization: token $GITHUB_TOKEN" \
     https://api.github.com/rate_limit

# Test PoC extraction manually
python -c "
import asyncio
from src.services.poc_extraction_service import PocExtractionService
from src.services.llm_service import LLMService

async def test_poc():
    llm_service = LLMService()
    poc_service = PocExtractionService(llm_service)
    print('PoC extraction service initialized')
    print(f'Available methods: {[m for m in dir(poc_service) if not m.startswith(\"_\")]}')

asyncio.run(test_poc())
"

# Check network connectivity to PoC sources
curl -I https://api.github.com/search/repositories
curl -I https://www.exploit-db.com/
```

#### Issue: GitHub Metadata Extraction Failures

**Symptoms:**

```bash
WARNING: Failed to extract PoC from https://github.com/.../issues/3328: 'CircuitBreaker' object does not support the asynchronous context manager protocol
ERROR: object NoneType can't be used in 'await' expression
```

**Root Cause (Fixed 2025-10-14):**

The CircuitBreaker was incorrectly used as an async context manager (`async with self.circuit_breaker:`) instead of calling the `call()` method. This caused ALL GitHub requests to fail with protocol errors.

**Verification After Fix:**

```bash
# Check if fix is applied in your version
grep -n "circuit_breaker.call" src/services/exploit_generation/poc_extraction_service.py

# Should show:
# 323:            return await self.circuit_breaker.call(fetch_and_parse)
# 337:            return await self.circuit_breaker.call(fetch_metadata)
```

**Manual Testing:**

```bash
# Test GitHub metadata extraction functionality
python -c "
import asyncio
from src.services.exploit_generation.poc_extraction_service import PocExtractionService
from src.services.system.llm_service import LLMService

async def test():
    try:
        llm_service = LLMService()
        poc_service = PocExtractionService(llm_service)
        print('GitHub metadata extraction service initialized successfully')
        print(f'Circuit breaker available: {hasattr(poc_service, \"circuit_breaker\")}')
    except Exception as e:
        print(f'Error: {e}')

asyncio.run(test())
"

# Expected output:
# ✅ GitHub metadata extraction service initialized successfully
# Circuit breaker available: True
```

**Check Logs for Success:**

```bash
# View recent logs for GitHub metadata extraction
tail -100 logs/gyros_*.log | grep -i "github metadata"

# Should see:
# INFO - Extracted GitHub metadata from [URL]: github_issue
# INFO - Collected N GitHub reference metadata items for context
# INFO - Providing GitHub reference context to LLM
```

**Solutions if Still Failing:**

```bash
# Solution 1: Check FORGE version
git log --oneline -1 | grep "2025-10-14"
# Should show recent commit with GitHub fixes

# Solution 2: Clear PoC cache to force re-extraction
rm -rf data/poc_cache/*
python src/main.py process --packages com.fasterxml.jackson.core:jackson-databind --limit 1

# Solution 3: Verify CircuitBreaker implementation
python -c "
from src.services.system.reliability_service import CircuitBreaker
import inspect

cb = CircuitBreaker(failure_threshold=3, recovery_timeout=30)
print(f'Has call method: {hasattr(cb, \"call\")}')
print(f'Has __aenter__: {hasattr(cb, \"__aenter__\")}')
print(f'Is async context manager: {hasattr(cb, \"__aenter__\") and hasattr(cb, \"__aexit__\")}')
"

# Expected output:
# Has call method: True
# Has __aenter__: False
# Is async context manager: False
```

#### Issue: Exploit Scripts with Python Recursion Errors

**Symptoms:**

```bash
ERROR - An unexpected error occurred: maximum recursion depth exceeded while encoding a JSON object
ERROR - An unexpected error occurred: maximum recursion depth exceeded while calling a Python object
```

**Root Cause (Fixed 2025-10-14):**

The LLM generated exploit scripts with deeply nested structures (10,000+ levels) because it didn't understand the actual vulnerability mechanism. This happened when:

1. GitHub context was not available (due to CircuitBreaker errors)
2. LLM guessed the vulnerability mechanism incorrectly
3. No explicit recursion limits in prompt template

**Solution Applied:**

Enhanced prompt template with explicit guidelines:

- Recursion limit: Keep nested structures under 100 levels maximum
- Understand vulnerability MECHANISM from GitHub context - don't guess
- Specific guidance for JDK serialization and other vulnerability types

**Verification:**

```bash
# Check generated exploit scripts for recursion issues
find data/exploit_scripts/ -name "*.py" -exec grep -l "for.*range.*1000" {} \;

# Should return empty (no scripts with excessive loops)

# Inspect a recent exploit script
cat data/exploit_scripts/CVE-*.py | head -50

# Should NOT see patterns like:
# for _ in range(10000):  # BAD
#     nested = {"nested": nested}

# Should see reasonable patterns like:
# for _ in range(50):  # GOOD
#     nested = {"data": nested}
```

**Check Prompt Template:**

```bash
# Verify enhanced guidelines are present
grep -A 5 "CRITICAL.*recursion" src/config/prompts/llm_poc_generation.txt

# Should show:
# - CRITICAL: Avoid Python recursion errors - keep nested structures under 100 levels maximum
# - CRITICAL: Understand the vulnerability MECHANISM from GitHub context and references - don't guess
# - CRITICAL: For JDK serialization vulnerabilities, don't create deeply nested JSON
```

**Test with Previously Failing CVE:**

```bash
# Test CVE-2021-46877 which previously caused recursion errors
python src/main.py process \
  --packages "com.fasterxml.jackson.core:jackson-databind" \
  --cve-ids "com.fasterxml.jackson.core:jackson-databind:CVE-2021-46877" \
  --limit 1 \
  --validate

# Check logs
tail -200 logs/gyros_*.log | grep -E "(recursion|GitHub metadata|Collected.*context)"

# Should see:
# Collected 2 GitHub reference metadata items for context
# Providing GitHub reference context to LLM
# NO "maximum recursion depth exceeded" errors
```

**Solutions if Still Failing:**

```bash
# Solution 1: Clear PoC cache and regenerate
rm -rf data/poc_cache/*
rm -rf data/exploit_scripts/*
python src/main.py process --packages [package] --validate

# Solution 2: Verify GitHub metadata is being extracted
python src/main.py --debug process --packages [package] --limit 1 2>&1 | \
  grep -A 3 "GitHub reference context"

# Solution 3: Manually edit problematic exploit script
# Find and reduce excessive loop iterations
sed -i 's/range(10000)/range(50)/g' data/exploit_scripts/CVE-*.py
```

#### Issue: File Upload Exploit Validation Failures

**Symptoms:**
- Logs show: `"CWE IDs: []"` when blueprint should have CWEs
- Logs show: `"Type: path_traversal"` for file upload CVEs
- Logs show: `"GitHub context extraction completed: 0 issues, 0 fix commits"`
- Generated vulnerable code uses relative paths like `"uploaded_files/"`
- Container logs show: `"Permission denied"` or `"FileNotFoundException"`
- Exploit output: `"Vulnerability not triggered"`
- Validation result: `vulnerability_triggered: false`

**Root Causes:**

1. **GitHub API Returns 403 (No Authentication)**
   - GitHub API requests fail without GITHUB_TOKEN
   - LLM receives zero vulnerability context from issues/commits/advisories
   - Reduces exploit generation accuracy significantly

2. **CWE IDs Not Extracted from Blueprint**
   - Blueprint stores CWEs in `metadata.osv_data.database_specific.cwe_ids`
   - If not extracted, vulnerability type classification fails
   - Results in wrong exploitation approach (e.g., path_traversal instead of file_upload)

3. **Generated Code Uses Non-Writable Paths**
   - LLM generates vulnerable code with relative paths like `"uploaded_files/"`
   - These paths require container-specific directory creation with permissions
   - Application fails when trying to create directories

**Solutions:**

1. **Set GitHub Token** (CRITICAL for proper context):
   ```bash
   # Get token from: https://github.com/settings/tokens
   # Required scope: public_repo (for public repositories)

   # Add to .env file
   echo "GITHUB_TOKEN=ghp_your_token_here" >> .env

   # Verify it loads
   source .env && echo $GITHUB_TOKEN

   # Test GitHub API access
   curl -H "Authorization: Bearer $GITHUB_TOKEN" \
     https://api.github.com/repos/apache/struts/commits/1ecfbae46543a83e131404f8dcc84b3d0d554854

   # Expected: 200 OK with commit JSON (not 403)
   ```

2. **Clear GitHub Context Cache** (if previously ran without token):
   ```bash
   rm -rf data/github_context_cache/*
   ```

   Cached 403 errors prevent re-fetching even after adding token!

3. **Verify CWE Extraction in Logs**:
   Look for these log lines:
   ```
   ✅ Extracted CWE IDs from blueprint metadata: ['CWE-22', 'CWE-434', 'CWE-915']
   ❌ CWE IDs: [] (WRONG - indicates extraction failed)
   ```

4. **Check Generated Code Uses /tmp/uploads/**:
   ```bash
   cat data/containers/vulnapp-*/src/main/java/com/vuln/*.java | grep -A 3 "File uploadDir"

   # Expected:
   ✅ File uploadDir = new File("/tmp/uploads");
   ❌ File savedFile = new File("uploaded_files/" ... (WRONG)
   ```

5. **Rebuild from Scratch** (after fixes):
   ```bash
   # Clear ALL cached data
   rm -rf data/blueprints/*
   rm -rf data/containers/*
   rm -rf data/exploit_scripts/*
   rm -rf data/github_context_cache/*
   rm -rf data/monitoring/*
   podman rm -f $(podman ps -aq)

   # Rebuild
   poetry run python src/main.py process \
     --packages org.apache.struts:struts2-core \
     --cve-ids org.apache.struts:struts2-core:GHSA-43mq-6xmg-29vm \
     --framework-type struts \
     --auto-run \
     --ports 8080 \
     --validate
   ```

**Success Indicators:**
- ✅ Logs: `"GitHub context extraction completed: 3 issues, 2 fix commits, 1 advisory"`
- ✅ Logs: `"Extracted CWE IDs from blueprint metadata: ['CWE-22', 'CWE-434', 'CWE-915']"`
- ✅ Logs: `"Type: file_upload"` (not path_traversal)
- ✅ Generated code uses `/tmp/uploads/` path
- ✅ Validation: `vulnerability_triggered: true` with confidence >0.7

---

## 🐛 Advanced Debugging

### Debug Mode Operation

**Enable comprehensive debugging:**

```bash
# Set debug environment
export LOG_LEVEL=DEBUG

# Run with debug output
python src/main.py --debug workflow --packages org.yaml:snakeyaml --auto-run --validate

# Monitor debug logs in real-time
tail -f logs/gyros_*.log
```

### Service-Level Debugging

**Debug specific services:**

```python
# Debug LLM Service connectivity
python -c "
from src.services.llm_service import LLMService

service = LLMService()
try:
    print(f'LLM Service initialized: {service.provider}')
    print(f'Model: {service.model}')
except Exception as e:
    print(f'LLM Service Error: {e}')
"

# Debug Container Service
python -c "
from src.services.container_service import ContainerService

service = ContainerService()
try:
    print(f'Container Service initialized')
    print(f'Available methods: {[m for m in dir(service) if not m.startswith(\"_\")]}')
except Exception as e:
    print(f'Container Service Error: {e}')
"

# Debug Framework Intelligence
python -c "
from src.services.framework_intelligence_service import FrameworkIntelligenceService

service = FrameworkIntelligenceService()
patterns = service._load_detection_patterns()
print(f'Loaded {len(patterns)} framework patterns')
for fw in patterns.keys():
    print(f'Framework: {fw}')
"
```

### Network Debugging

**Diagnose network connectivity issues:**

```bash
# Test LLM endpoint connectivity
curl -v https://azure.openai.com/

# Test with proxy if behind corporate firewall
export https_proxy=http://proxy.company.com:8080
curl -v https://azure.openai.com/

# Check DNS resolution
nslookup azure.openai.com
dig azure.openai.com

# Test container network isolation
podman run --rm --network=none alpine ping -c 1 google.com
# Should fail with network isolation

# Check container port mapping
podman port <container-name>
netstat -tuln | grep <port>
```

## 📊 Performance Profiling

### CPU and Memory Profiling

**Profile Python execution:**

```bash
# Install profiling tools
pip install py-spy memory-profiler

# CPU profiling
py-spy record -o profile.svg -- python src/main.py workflow -p org.yaml:snakeyaml --auto-run

# Memory profiling
mprof run python src/main.py workflow -p org.yaml:snakeyaml --auto-run
mprof plot
```

### Container Performance Analysis

**Analyze container resource usage:**

```bash
# Continuous monitoring
podman stats --format "table {{.Container}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.NetIO}}\t{{.BlockIO}}"

# Historical analysis
podman logs --timestamps <container-name> | tail -100

# Resource limit testing
podman run --memory=512m --cpus=1.0 <image-name>
```

## 🔧 Configuration Troubleshooting

### Configuration File Issues

**Validate configuration files:**

```bash
# Check YAML syntax
python -c "
import yaml
with open('src/config/framework_adaptation.yaml') as f:
    try:
        yaml.safe_load(f)
        print('YAML syntax valid')
    except yaml.YAMLError as e:
        print(f'YAML error: {e}')
"

# Validate schema files
python -c "
import yaml
with open('src/config/llm_schemas.yaml') as f:
    try:
        yaml.safe_load(f)
        print('Schema file valid')
    except Exception as e:
        print(f'Schema error: {e}')
"

# Check file permissions
ls -la src/config/
ls -la .env
```

### Environment Variable Issues

**Debug environment configuration:**

```bash
# List all relevant environment variables
env | grep -E "(AZURE|LLM|LOG_LEVEL|CONTAINER|CIRCUIT)"

# Check Python path
python -c "import sys; print('\n'.join(sys.path))"

# Verify package installations
python -c "
import pkg_resources
packages = ['poetry', 'click', 'pydantic', 'aiohttp']
for pkg in packages:
    try:
        version = pkg_resources.get_distribution(pkg).version
        print(f'{pkg}: {version}')
    except:
        print(f'{pkg}: NOT INSTALLED')
"
```

## 📞 Getting Help

### Log Collection for Root-cause Analysis

**Collect comprehensive diagnostic information:**

```bash
#!/bin/bash
# collect-diagnostics.sh

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
DIAG_DIR="diagnostics_$TIMESTAMP"

mkdir -p "$DIAG_DIR"

# System information
uname -a > "$DIAG_DIR/system_info.txt"
python --version > "$DIAG_DIR/python_version.txt"
podman version > "$DIAG_DIR/container_version.txt" 2>&1

# Environment
env | grep -E "(AZURE|LLM|LOG_LEVEL|CONTAINER|CIRCUIT)" > "$DIAG_DIR/environment.txt"

# Recent logs
cp logs/gyros_*.log "$DIAG_DIR/" 2>/dev/null || echo "No logs found"

# Configuration (sanitized)
cp src/config/*.yaml "$DIAG_DIR/" 2>/dev/null
sed -i 's/api[_-]key.*/api_key: [REDACTED]/' "$DIAG_DIR/"*.yaml

# Container information
podman ps -a > "$DIAG_DIR/containers.txt" 2>&1
podman images > "$DIAG_DIR/images.txt" 2>&1

# Network information
ip addr show > "$DIAG_DIR/network.txt" 2>&1
netstat -tuln > "$DIAG_DIR/ports.txt" 2>&1

# Resource usage
free -h > "$DIAG_DIR/memory.txt"
df -h > "$DIAG_DIR/disk.txt"

# Health check
python src/main.py health-check > "$DIAG_DIR/health_check.txt" 2>&1

# Create archive
tar -czf "gyros_diagnostics_$TIMESTAMP.tar.gz" "$DIAG_DIR"
rm -rf "$DIAG_DIR"

echo "Diagnostic information collected: gyros_diagnostics_$TIMESTAMP.tar.gz"
```
