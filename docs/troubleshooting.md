# Troubleshooting

## Quick diagnostics

```bash
python src/main.py health-check
podman ps -a
python --version
podman --version || docker --version
```

---

## Exploit generation

### Wrong payloads / recursion errors

**Symptom**: Exploit scripts produce `RecursionError: maximum recursion depth exceeded` or generate deeply nested structures (10,000+ levels).

**Cause**: Fix commits were misclassified as PoC code. The LLM saw fix code like "add 100k limit" and generated 10,000-level nested JSON.

**Fix** (resolved in v3):

```bash
# Clear PoC cache to force reclassification
rm -rf data/cache/poc_extraction_*

# Verify fix commit classification
grep "Classified.*as FIX COMMIT" logs/forge_*.log
grep "Added fix commit analysis to GitHub context" logs/forge_*.log
```

The commit classification system now separates fix commits (`fix_commits_context`) from PoC data.

**Related**: [poc_extraction_service.py:356-427](../src/services/exploit_generation/poc_extraction_service.py#L356-L427), [exploit_script_generation_service.py:129-164](../src/services/exploit_generation/exploit_script_generation_service.py#L129-L164)

---

## Container build failures

### Invalid Java target release

**Symptom**: `Fatal error compiling: error: invalid target release: 17` with a Java 11 base image.

**Cause**: POM specifies Java 17 but the Containerfile uses a Java 11 image. Spring Framework 6.x requires Java 17+.

**Fix** (resolved in v4.2): Automatic Java version detection. For existing failed containers:

```bash
rm -rf data/containers/vulnapp-*spring-web*
rm -f data/blueprints/*.json
poetry run python src/main.py process --packages org.springframework:spring-web --cve-ids <CVE-ID> --auto-run
```

### Deprecated Docker images

**Symptom**: `manifest unknown: openjdk:17-jre-slim` -- OpenJDK images were deprecated after Java 11.

**Fix** (resolved in v4.2): Framework now uses `eclipse-temurin` images. For Java 17+: `maven:3.9-eclipse-temurin-${java_version}` and `eclipse-temurin:${java_version}-jre`.

### Invalid OSV versions

**Symptom**: `Could not find artifact io.undertow:undertow-core:jar:1.0.0` -- OSV database returned a non-existent version.

**Fix** (resolved in v4.2): Automatic version validation against Maven Central with fallback strategies (`match_major`, `latest`). If automatic recovery fails:

```bash
poetry run python src/main.py process --packages io.undertow:undertow-core --version 2.2.25.Final --cve-ids <CVE-ID>
```

### Container exits immediately

**Symptom**: Container builds but exits on start. Usually a Spring Boot / Spring Framework version incompatibility (e.g., Spring Framework 6.x with Spring Boot 2.x).

**Diagnose**:

```bash
podman logs <container-name>
podman run --rm -p 8080:8080 <image-name>
podman run --rm --entrypoint /bin/sh <image-name> -c "ls -la /app && java -version"
```

> **Note**: This issue is not fully resolved. The framework needs version compatibility validation between Spring Boot and Spring Framework.

### Build timeout

```bash
export CONTAINER_BUILD_TIMEOUT=600
python src/main.py workflow --packages org.yaml:snakeyaml --auto-run

# Or debug manually
cd data/blueprints/<blueprint-id>/
podman build -t debug-build .
```

### Port already in use

```bash
lsof -i :8080
python src/main.py workflow --packages org.yaml:snakeyaml --auto-run --ports 8090-8100
python src/main.py stop-all
```

---

## Installation

### Poetry permission denied

```bash
# Use project-local virtualenv
export POETRY_VENV_IN_PROJECT=true
poetry install

# Or create a venv manually
python3 -m venv forge-env
source forge-env/bin/activate
pip install poetry
poetry install
```

### API configuration error

```bash
echo $AZURE_OPENAI_API_KEY
echo $AZURE_OPENAI_ENDPOINT

# Copy template and fill in credentials
cp .env.template .env
```

---

## LLM issues

### Generation timeout

```bash
export LLM_EXPLOITATION_TIMEOUT=120
python src/main.py --debug process --packages org.yaml:snakeyaml
```

### Invalid generated code

```bash
cat data/blueprints/<blueprint-id>/VulnApplication.java
python src/main.py validate-templates
python src/main.py process --packages org.yaml:snakeyaml --framework-type spring-boot
```

### Unknown vulnerability type

**Symptom**: `vulnerability_type: unknown` with low confidence scores. The CVE's CWE ID is not mapped.

Check and extend the mapping:

```bash
grep "CWE-" src/utils/core/common.py | head -20
```

To add a new CWE mapping:

1. Add the CWE check in [src/utils/core/common.py](../src/utils/core/common.py):

   ```python
   elif "CWE-843" in cwe_ids:
       return "type_confusion"
   ```

2. Add patterns in [src/config/vulnerability_patterns.yaml](../src/config/vulnerability_patterns.yaml):

   ```yaml
   osv_patterns:
     type_confusion:
       - "type confusion"
       - "type safety"
   exploitation_indicators:
     type_confusion:
       - "ClassCastException"
       - "type mismatch"
   ```

3. Add a validation context in [llm_validation_service.py](../src/services/system/llm_validation_service.py):

   ```python
   "type_confusion": {
       "description": "Brief description",
       "analysis_guidance": ["What to check for"],
       "key_question": "Was the type confusion triggered?"
   }
   ```

---

## Validation issues

### Header-based validation failures

**Symptom**: HTTP 200 response, exploit runs without errors, but `vulnerability_triggered: false`. Common for HTTP response splitting, RFD, session fixation, and CRLF injection.

**Cause**: Validation checked the response body instead of headers.

**Verify**:

```bash
grep "CWE-113" src/utils/core/common.py
grep -A 5 "http_response_splitting:" src/config/vulnerability_patterns.yaml
```

The LLM validation context for `http_response_splitting` explicitly states: *"CRITICAL: This vulnerability manifests in HTTP RESPONSE HEADERS, not the response body."*

If the generated exploit script checks the body, edit it to inspect headers:

```python
content_disp = response.headers.get('Content-Disposition', '')
if 'malicious' in content_disp:
    return True
```

### API version mismatch

**Symptom**: Compilation errors like `cannot find symbol UploadedFile` -- version-specific APIs changed between framework releases.

Check version coverage:

```bash
grep -E "^\"[0-9]" src/config/api_references/struts_version_apis.yaml
```

Add missing versions to the appropriate file in `src/config/api_references/`. Supported range formats:

| Format | Example | Matches |
| --- | --- | --- |
| Exact | `"6.2.0"` | Only 6.2.0 |
| Range | `"6.0-6.3"` | 6.0.x through 6.3.x |
| Plus | `"6.4+"` | 6.4.0 and above |

Workaround: pin to a supported version:

```bash
python src/main.py process --packages org.apache.struts:struts2-core --version 6.3.0
```

### Framework detection failure

```bash
# Force framework type
python src/main.py process --packages org.springframework:spring-core --framework-type spring-boot

# Debug detection
python src/main.py --debug process --packages org.springframework:spring-core
```

### Validation always fails

```bash
# Check container is reachable
curl http://localhost:8080/
curl http://localhost:8080/health

# Test vulnerable endpoint manually
curl -X POST http://localhost:8080/api/vulnerable \
  -H "Content-Type: text/plain" -d "test: data"

# Run exploit script manually
python3 data/exploit_scripts/CVE-*-abc123.py http://localhost:8080

# Debug validation
python src/main.py --debug validate-exploit --id abc123
```

### 405 Method Not Allowed

**Cause**: Exploit script targets the wrong endpoint or HTTP method due to endpoint extraction failures.

```bash
# Check extracted endpoints
grep "Extracted.*endpoints from blueprint" logs/forge_*.log | tail -1

# Test endpoints manually
curl http://localhost:$PORT/
curl -X POST http://localhost:$PORT/vulnerable -H "Content-Type: application/json" -d '{"test": "data"}'
```

Fix: edit the exploit script to target the correct endpoint path and method.

### PoC extraction fails

```bash
# Check GitHub rate limits
curl -H "Authorization: token $GITHUB_TOKEN" https://api.github.com/rate_limit

# Verify network connectivity
curl -I https://api.github.com/search/repositories
```

### GitHub metadata extraction failures

**Symptom**: `'CircuitBreaker' object does not support the asynchronous context manager protocol`

**Fix** (resolved): The CircuitBreaker now uses `call()` instead of `async with`. Verify:

```bash
grep -n "circuit_breaker.call" src/services/exploit_generation/poc_extraction_service.py
```

### File upload exploit failures

Common causes and solutions:

1. **No GitHub token**: Set `GITHUB_TOKEN` in `.env` (scope: `public_repo`). Without it, GitHub API returns 403 and the LLM gets no vulnerability context.

2. **Stale cache**: If you previously ran without a token, clear the cache:

   ```bash
   rm -rf data/github_context_cache/*
   ```

3. **CWE not extracted**: Check logs for `CWE IDs: []`. The CWE should appear in `metadata.osv_data.database_specific.cwe_ids`.

4. **Non-writable paths**: Generated code should use `/tmp/uploads`, not relative paths like `uploaded_files/`.

Full rebuild after fixing:

```bash
rm -rf data/blueprints/* data/containers/* data/exploit_scripts/* data/github_context_cache/* data/monitoring/*
podman rm -f $(podman ps -aq)
poetry run python src/main.py process \
  --packages org.apache.struts:struts2-core \
  --cve-ids org.apache.struts:struts2-core:GHSA-43mq-6xmg-29vm \
  --framework-type struts --auto-run --ports 8080 --validate
```

---

## Debugging

### Debug mode

```bash
export LOG_LEVEL=DEBUG
python src/main.py --debug workflow --packages org.yaml:snakeyaml --auto-run --validate
tail -f logs/forge_*.log
```

### Configuration validation

```bash
python -c "
import yaml
with open('src/config/framework_adaptation.yaml') as f:
    yaml.safe_load(f)
    print('Valid')
"
```

### Environment check

```bash
env | grep -E "(AZURE|LLM|LOG_LEVEL|CONTAINER|CIRCUIT)"
```
