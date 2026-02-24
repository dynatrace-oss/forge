import logging
import re
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from shared.constants import (
    IOC_APPLICATION_PATTERNS_ENABLED,
    IOC_BEHAVIORAL_PATTERNS_ENABLED,
    IOC_COLLECTION_ENABLED,
    IOC_FILESYSTEM_PATTERNS_ENABLED,
    IOC_MAX_IOCS_PER_TYPE,
    IOC_MIN_CONFIDENCE_THRESHOLD,
    IOC_NETWORK_PATTERNS_ENABLED,
    IOC_PROCESS_PATTERNS_ENABLED,
    IOC_TIMING_PATTERNS_ENABLED,
)
from shared.types import (
    IoC,
    IoCCategory,
    IoCCollection,
    IoCConfidenceLevel,
    IoCExtractionResult,
    IoCType,
)
from utils.core.loader import ConfigLoader, TemplateLoader

logger = logging.getLogger(__name__)


class IndicatorGenerator:
    """Centralized exploitation indicator generation service."""

    def __init__(self, config_loader: Optional[ConfigLoader] = None, template_loader: Optional[TemplateLoader] = None):
        """Initialize the indicator generator with configuration and template loaders."""
        self.config_loader = config_loader or ConfigLoader()
        self.template_loader = template_loader or TemplateLoader(Path("src/templates"))
        self._indicators_cache = {}
        self._load_patterns()

    def _load_patterns(self):
        """Load indicator patterns from configuration files."""
        try:
            # Load vulnerability patterns configuration
            self.patterns_config = self.config_loader.load_config_safe("vulnerability_patterns", default={})

            # Extract indicator patterns
            self.exploitation_indicators = self.patterns_config.get("exploitation_indicators", {})
            self.log_patterns = self.patterns_config.get("log_patterns", {})
            self.template_mappings = self.patterns_config.get("template_mappings", {})

        except Exception as e:
            logger.warning(f"Failed to load indicator patterns: {e}. Using minimal defaults.")
            self._initialize_minimal_defaults()

    def _initialize_minimal_defaults(self):
        """Initialize minimal default patterns if configuration loading fails."""
        self.exploitation_indicators = {}
        self.log_patterns = {}
        self.template_mappings = {}

    def get_expected_indicators(self, vulnerability_type: str) -> List[str]:
        """
        Get expected exploitation indicators using dynamic template loading and caching.

        Args:
            vulnerability_type: Type of vulnerability to get indicators for

        Returns:
            List of expected exploitation indicators
        """
        # Check cache first
        if vulnerability_type in self._indicators_cache:
            return self._indicators_cache[vulnerability_type]

        # Try to load indicators from template system
        template_indicators = self._load_indicators_from_templates(vulnerability_type)
        if template_indicators:
            self._indicators_cache[vulnerability_type] = template_indicators
            return template_indicators

        # Generate indicators dynamically based on vulnerability type patterns
        indicators = self._generate_dynamic_indicators(vulnerability_type)

        # Cache the result
        self._indicators_cache[vulnerability_type] = indicators
        return indicators

    def _generate_dynamic_indicators(self, vulnerability_type: str) -> List[str]:
        """Generate indicators dynamically based on vulnerability type patterns using configuration."""
        base_indicators = ["vulnerability", "exploit", "error", "exception"]

        # Use configured indicators if available
        if vulnerability_type in self.exploitation_indicators:
            return base_indicators + self.exploitation_indicators[vulnerability_type]

        # Fallback patterns for basic vulnerability types
        fallback_patterns = {
            "dos_vulnerability": ["StackOverflowError", "OutOfMemoryError", "denial", "resource", "memory"],
            "injection_vulnerability": ["injection", "payload", "malicious", "inject"],
            "overflow_vulnerability": ["overflow", "buffer", "memory", "crash"],
            "deserialization_vulnerability": [
                "deserialization",
                "serialized",
                "object",
                "ObjectInputStream",
                "deserialize",
            ],
        }

        # Check fallback patterns
        for pattern_type, indicators in fallback_patterns.items():
            if pattern_type in vulnerability_type:
                return base_indicators + indicators

        return base_indicators

    def _load_indicators_from_templates(self, vulnerability_type: str) -> List[str]:
        """Load exploitation indicators from template system if available."""
        try:
            template_name = self.template_mappings.get(vulnerability_type)
            if not template_name:
                return []

            # Try to read indicators from template comments or metadata
            return self._extract_indicators_from_template_content(template_name)

        except Exception as e:
            logger.debug(f"Could not load indicators from templates: {e}")
            return []

    def _extract_indicators_from_template_content(self, template_name: str) -> List[str]:
        """Extract indicators from template file content."""
        try:
            # Check vulnerability template directory
            template_path = Path("src/templates/vulnerability") / f"{template_name}.txt"
            if template_path.exists():
                content = template_path.read_text()
                return self._parse_indicators_from_content(content)

        except Exception as e:
            logger.debug(f"Error reading template {template_name}: {e}")

        return []

    def _parse_indicators_from_content(self, content: str) -> List[str]:
        """Parse exploitation indicators from template content."""
        indicators = []

        # Look for common vulnerability patterns in code
        patterns = [
            r"import\s+([\w\.]+)",  # Import statements
            r"@(\w+)",  # Annotations
            r"(\w*Exception)",  # Exception types
            r'"([^"]*(?:jndi|ldap|rmi|lookup)[^"]*?)"',  # JNDI patterns
            r'"([^"]*(?:@class|@type)[^"]*?)"',  # Deserialization patterns
        ]

        for pattern in patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                if isinstance(match, tuple):
                    indicators.extend([m for m in match if m])
                else:
                    indicators.append(match)

        # Filter and clean indicators
        cleaned_indicators = []
        for indicator in indicators:
            if len(indicator) > 2 and not indicator.isdigit():
                cleaned_indicators.append(indicator.lower())

        return list(set(cleaned_indicators))

    def check_vulnerability_specific_patterns(self, container_logs: str, vulnerability_type: str) -> List[str]:
        """Check for vulnerability-specific patterns in container logs using configuration."""
        indicators = []
        logs_lower = container_logs.lower()

        # Use configured log patterns if available
        vuln_patterns = self.log_patterns.get(vulnerability_type, [])
        for pattern in vuln_patterns:
            if pattern in logs_lower:
                indicators.append(f"vuln_specific_{pattern.replace(' ', '_')}")

        # Check for generic exploitation patterns
        generic_patterns = ["error", "exception", "failure", "crash", "abort"]
        for pattern in generic_patterns:
            if pattern in logs_lower:
                indicators.append(f"generic_{pattern}")

        return indicators

    def analyze_exploit_response_indicators(self, execution_result, vulnerability_type: str) -> List[str]:
        """
        Analyze exploit execution results for vulnerability-specific indicators.
        Focuses on actual exploitation evidence rather than generic noise.
        
        Args:
            execution_result: ExploitExecutionResult with response data
            vulnerability_type: Type of vulnerability being tested
            
        Returns:
            List of relevant exploitation indicators
        """
        indicators = []
        
        # Analyze stdout/stderr for exploitation evidence
        all_output = f"{execution_result.stdout}\n{execution_result.stderr}".lower()
        
        # Vulnerability-specific patterns
        vuln_patterns = {
            "deserialization": {
                "high": ["deserialized", "unmarshall", "object instantiation", "gadget chain"],
                "medium": ["serialization", "object", "class loading", "deserialization"],
                "low": ["jackson", "fastjson", "snakeyaml", "pickle"]
            },
            "injection": {
                "high": ["command executed", "payload executed", "injected successfully"],
                "medium": ["injection", "executed", "sql error", "query executed"],
                "low": ["error", "syntax", "mysql", "postgresql"]
            },
            "rce": {
                "high": ["remote code execution", "command injection", "shell spawned"],
                "medium": ["process created", "runtime.exec", "system command"],
                "low": ["command", "process", "runtime"]
            },
            "xxe": {
                "high": ["external entity", "xml entity resolved", "dtd processed"],
                "medium": ["xml parsing", "entity", "DOCTYPE"],
                "low": ["xml", "parser", "entity"]
            }
        }
        
        # Check for vulnerability-specific indicators
        vuln_type = vulnerability_type.lower()
        for pattern_type, patterns in vuln_patterns.items():
            if pattern_type in vuln_type:
                for confidence, pattern_list in patterns.items():
                    for pattern in pattern_list:
                        if pattern in all_output:
                            indicators.append(f"{confidence}_confidence_{pattern_type}:{pattern}")
        
        # Analyze HTTP responses for exploitation indicators
        for response in execution_result.http_responses:
            response_indicators = self._analyze_http_response_for_exploitation(
                response, vulnerability_type
            )
            indicators.extend(response_indicators)
        
        # Check for error patterns that indicate exploitation attempts
        exploitation_errors = [
            "stack overflow", "out of memory", "access violation",
            "segmentation fault", "null pointer", "buffer overflow"
        ]
        
        for error_pattern in exploitation_errors:
            if error_pattern in all_output:
                indicators.append(f"exploitation_error:{error_pattern}")
        
        # Remove duplicates and filter noise
        unique_indicators = list(set(indicators))
        return self._filter_exploit_indicators(unique_indicators, vulnerability_type)

    def _analyze_http_response_for_exploitation(self, response: dict, vulnerability_type: str) -> List[str]:
        """Analyze HTTP response for exploitation-specific indicators."""
        indicators = []
        
        status_code = response.get("status_code", 0)
        response_text = response.get("response_text", "").lower()
        headers = response.get("headers", {})
        
        # Status code analysis
        if 200 <= status_code < 300:
            indicators.append("http_success_response")
        elif 400 <= status_code < 500:
            indicators.append(f"client_error_{status_code}")
        elif 500 <= status_code < 600:
            indicators.append(f"server_error_{status_code}")
        
        # Response content analysis for exploitation
        exploit_patterns = {
            "deserialization": ["deserialized", "object", "serialization", "unmarshall"],
            "injection": ["injected", "executed", "query result", "command output"],
            "rce": ["command executed", "process output", "shell response"],
            "xxe": ["entity resolved", "xml parsed", "external content"]
        }
        
        vuln_type = vulnerability_type.lower()
        for pattern_type, patterns in exploit_patterns.items():
            if pattern_type in vuln_type:
                for pattern in patterns:
                    if pattern in response_text:
                        indicators.append(f"http_exploitation_indicator:{pattern_type}:{pattern}")
        
        # Check for successful exploitation evidence in headers
        security_bypass_headers = [
            "x-powered-by", "server", "x-debug-token"
        ]
        
        for header in security_bypass_headers:
            if header in headers:
                indicators.append(f"security_header_disclosure:{header}")
        
        return indicators

    def _filter_exploit_indicators(self, indicators: List[str], vulnerability_type: str) -> List[str]:
        """Filter out noise indicators and keep only exploitation-relevant ones."""
        filtered = []
        
        # Remove generic noise patterns
        noise_patterns = [
            "missing_security_headers",  # Too generic
            "generic_error",             # Not specific enough
            "connection_established",    # Just connectivity
            "http_200"                   # Just successful request
        ]
        
        for indicator in indicators:
            # Skip noise patterns
            if any(noise in indicator for noise in noise_patterns):
                continue
                
            # Keep high-confidence exploitation indicators
            if any(conf in indicator for conf in ["high_confidence", "exploitation_", "injected", "executed"]):
                filtered.append(indicator)
                continue
                
            # Keep vulnerability-specific indicators
            if vulnerability_type.lower() in indicator.lower():
                filtered.append(indicator)
                continue
                
            # Keep medium confidence indicators if they're relevant
            if "medium_confidence" in indicator:
                filtered.append(indicator)
        
        return filtered

    def analyze_logs_for_indicators(self, logs: str) -> List[str]:
        """Analyze container logs for exploitation indicators."""
        indicators = []
        log_lines = logs.lower().split("\n")

        # Common exploitation indicators - could be moved to configuration
        exploitation_patterns = [
            "exception",
            "error",
            "warning",
            "jndi",
            "ldap",
            "rmi",
            "deserialization",
            "serialized",
            "@class",
            "@type",
            "scriptenginemanager",
            "urlclassloader",
            "runtime.exec",
            "process",
            "command",
            "exploit",
        ]

        for line in log_lines:
            for pattern in exploitation_patterns:
                if pattern in line:
                    indicators.append(f"log_indicator_{pattern}")

        return indicators

    def get_supported_vulnerability_types(self) -> List[str]:
        """Get list of supported vulnerability types from configuration."""
        return list(self.exploitation_indicators.keys())

    def collect_vulnerability_specific_iocs(
        self, logs: str, vulnerability_type: str, patterns: List[str]
    ) -> IoCExtractionResult:
        """
        Collect only vulnerability-specific IoCs using focused patterns.

        Args:
            logs: Container logs to analyze
            vulnerability_type: Type of vulnerability being tested
            patterns: Specific patterns to match for this vulnerability

        Returns:
            IoCExtractionResult with only relevant vulnerability indicators
        """
        start_time = time.time()
        all_iocs = []

        if not logs or not logs.strip():
            return IoCExtractionResult(
                success=False,
                total_iocs_extracted=0,
                iocs=[],
                extraction_time_seconds=time.time() - start_time,
                error_message="No logs provided for analysis"
            )

        try:
            # Only search for vulnerability-specific patterns
            for pattern in patterns:
                try:
                    matches = re.finditer(pattern, logs, re.IGNORECASE | re.MULTILINE)
                    for match in matches:
                        ioc = IoC(
                            ioc_type=IoCType.APPLICATION,
                            category=IoCCategory.VULNERABILITY_INDICATOR,
                            value=match.group(0),
                            description=f"Vulnerability evidence: {match.group(0)}",
                            confidence=0.9,  # High confidence for explicit patterns
                            confidence_level=IoCConfidenceLevel.HIGH,
                            timestamp=datetime.now(),
                            source_line=match.group(0),
                            context={
                                "pattern": pattern,
                                "full_match": match.group(0),
                                "vulnerability_type": vulnerability_type
                            }
                        )
                        all_iocs.append(ioc)
                except re.error as e:
                    logger.warning(f"Invalid regex pattern '{pattern}': {e}")
                    continue

            extraction_time = time.time() - start_time
            logger.info(f"Vulnerability-specific IoC extraction completed: {len(all_iocs)} IoCs in {extraction_time:.2f}s")

            return IoCExtractionResult(
                success=True,
                total_iocs_extracted=len(all_iocs),
                iocs=all_iocs,
                extraction_time_seconds=extraction_time
            )

        except Exception as e:
            logger.error(f"Error during vulnerability-specific IoC collection: {e}")
            return IoCExtractionResult(
                success=False,
                total_iocs_extracted=0,
                iocs=[],
                extraction_time_seconds=time.time() - start_time,
                error_message=str(e)
            )

    def collect_comprehensive_iocs(
        self, logs: str, vulnerability_type: str
    ) -> IoCExtractionResult:
        """
        Collect comprehensive IoCs from container logs using all available extraction methods.

        Args:
            logs: Container logs to analyze
            vulnerability_type: Type of vulnerability being tested
            blueprint_id: Blueprint ID for context (optional)
            container_id: Container ID for context (optional)

        Returns:
            IoCExtractionResult with all collected IoCs
        """
        start_time = time.time()
        
        if not IOC_COLLECTION_ENABLED:
            logger.info("IoC collection is disabled")
            return IoCExtractionResult(
                success=False,
                total_iocs_extracted=0,
                iocs=[],
                extraction_time_seconds=0.0,
                error_message="IoC collection disabled in configuration"
            )

        try:
            logger.info(f"Starting comprehensive IoC collection for vulnerability type: {vulnerability_type}")
            all_iocs = []

            # Extract IoCs by type if enabled
            if IOC_NETWORK_PATTERNS_ENABLED:
                network_iocs = self._extract_network_indicators(logs)
                all_iocs.extend(network_iocs)

            if IOC_FILESYSTEM_PATTERNS_ENABLED:
                filesystem_iocs = self._extract_filesystem_indicators(logs)
                all_iocs.extend(filesystem_iocs)

            if IOC_PROCESS_PATTERNS_ENABLED:
                # Skip process pattern matching for web applications to avoid Spring Boot false positives
                # Focus on LLM-determined indicators which are more accurate for web vulnerabilities
                if not self._is_web_application_context(logs):
                    process_iocs = self._extract_process_indicators(logs)
                    all_iocs.extend(process_iocs)

            if IOC_APPLICATION_PATTERNS_ENABLED:
                application_iocs = self._extract_application_indicators(logs, vulnerability_type)
                all_iocs.extend(application_iocs)

            if IOC_TIMING_PATTERNS_ENABLED:
                timing_iocs = self._extract_timing_indicators(logs)
                all_iocs.extend(timing_iocs)

            if IOC_BEHAVIORAL_PATTERNS_ENABLED:
                behavioral_iocs = self._extract_behavioral_indicators(logs)
                all_iocs.extend(behavioral_iocs)

            # Filter by confidence threshold
            filtered_iocs = [
                ioc for ioc in all_iocs 
                if ioc.confidence >= IOC_MIN_CONFIDENCE_THRESHOLD
            ]

            # Limit IoCs per type if configured
            final_iocs = self._limit_iocs_per_type(filtered_iocs)

            extraction_time = time.time() - start_time
            
            logger.info(f"IoC collection completed: {len(final_iocs)} IoCs extracted in {extraction_time:.2f}s")

            return IoCExtractionResult(
                success=True,
                total_iocs_extracted=len(final_iocs),
                iocs=final_iocs,
                extraction_time_seconds=extraction_time,
                source_data_size=len(logs)
            )

        except Exception as e:
            extraction_time = time.time() - start_time
            logger.error(f"Error during IoC collection: {e}")
            return IoCExtractionResult(
                success=False,
                total_iocs_extracted=0,
                iocs=[],
                extraction_time_seconds=extraction_time,
                error_message=str(e),
                source_data_size=len(logs)
            )

    def _extract_network_indicators(self, logs: str) -> List[IoC]:
        """Extract network-related IoCs from logs."""
        network_iocs = []
        timestamp = datetime.now()

        # Network patterns to detect
        network_patterns = {
            IoCCategory.HTTP_REQUEST: [
                r'(?:GET|POST|PUT|DELETE|HEAD|OPTIONS)\s+([^\s]+)',
                r'HTTP/\d\.\d\s+(\d{3})',
                r'(?:http://|https://)([\w.-]+)',
            ],
            IoCCategory.DNS_LOOKUP: [
                r'dns.*?lookup.*?([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})',
                r'resolving.*?([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})',
                r'nslookup.*?([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})',
            ],
            IoCCategory.NETWORK_CONNECTION: [
                r'connect(?:ing|ed).*?(?:to|at)\s+([0-9.]+):(\d+)',
                r'(?:tcp|udp).*?connection.*?([0-9.]+):(\d+)',
                r'socket.*?connect.*?([0-9.]+):(\d+)',
            ],
            IoCCategory.URL_ACCESS: [
                r'(?:jndi|ldap|rmi)://([^/\s\)]+)',
                r'(?:accessing|fetching|downloading).*?(https?://[^\s]+)',
                r'url.*?(?:=|:)\s*(https?://[^\s]+)',
            ],
        }

        for category, patterns in network_patterns.items():
            for pattern in patterns:
                matches = re.finditer(pattern, logs, re.IGNORECASE | re.MULTILINE)
                for match in matches:
                    # Extract the main value
                    value = match.group(1) if match.groups() else match.group(0)
                    
                    # Calculate confidence based on pattern specificity
                    confidence = self._calculate_network_confidence(category, value, match.group(0))
                    
                    if confidence >= IOC_MIN_CONFIDENCE_THRESHOLD:
                        ioc = IoC(
                            ioc_type=IoCType.NETWORK,
                            category=category,
                            value=value,
                            description=f"Network {category.value} detected: {value}",
                            confidence=confidence,
                            confidence_level=IoCConfidenceLevel.LOW,  # Will be auto-set in __post_init__
                            timestamp=timestamp,
                            source_line=match.group(0),
                            context={"pattern": pattern, "full_match": match.group(0)}
                        )
                        network_iocs.append(ioc)

        return network_iocs

    def _extract_filesystem_indicators(self, logs: str) -> List[IoC]:
        """Extract filesystem-related IoCs from logs."""
        filesystem_iocs = []
        timestamp = datetime.now()

        filesystem_patterns = {
            IoCCategory.FILE_CREATION: [
                r'(?:creating|created|writing|wrote).*?file.*?([/\w.-]+)',
                r'(?:touch|mktemp|tempfile).*?([/\w.-]+)',
                r'file.*?created.*?(?:at|in)\s+([/\w.-]+)',
            ],
            IoCCategory.FILE_DELETION: [
                r'(?:deleting|deleted|removing|removed).*?file.*?([/\w.-]+)',
                r'(?:rm|unlink).*?([/\w.-]+)',
                r'file.*?(?:deleted|removed).*?([/\w.-]+)',
            ],
            IoCCategory.TEMP_FILE_USAGE: [
                r'(?:temporary|temp).*?(?:file|directory).*?([/\w.-]+)',
                r'/tmp/([^/\s]+)',
                r'java\.io\.tmpdir.*?([/\w.-]+)',
            ],
            IoCCategory.DIRECTORY_TRAVERSAL: [
                r'(?:\.\./){2,}([/\w.-]*)',
                r'(?:path|directory).*?traversal.*?([/\w.-]+)',
                r'(?:accessing|reading).*?(?:\.\./)+([/\w.-]*)',
            ],
            IoCCategory.PERMISSION_CHANGE: [
                r'(?:chmod|chown|permissions?).*?(?:changed|modified).*?([/\w.-]+)',
                r'(?:access|permission).*?(?:denied|granted).*?([/\w.-]+)',
            ],
        }

        for category, patterns in filesystem_patterns.items():
            for pattern in patterns:
                matches = re.finditer(pattern, logs, re.IGNORECASE | re.MULTILINE)
                for match in matches:
                    value = match.group(1) if match.groups() else match.group(0)
                    confidence = self._calculate_filesystem_confidence(category, value, match.group(0))
                    
                    if confidence >= IOC_MIN_CONFIDENCE_THRESHOLD:
                        ioc = IoC(
                            ioc_type=IoCType.FILESYSTEM,
                            category=category,
                            value=value,
                            description=f"Filesystem {category.value} detected: {value}",
                            confidence=confidence,
                            confidence_level=IoCConfidenceLevel.LOW,
                            timestamp=timestamp,
                            source_line=match.group(0),
                            context={"pattern": pattern, "full_match": match.group(0)}
                        )
                        filesystem_iocs.append(ioc)

        return filesystem_iocs

    def _extract_process_indicators(self, logs: str) -> List[IoC]:
        """Extract process-related IoCs from logs."""
        process_iocs = []
        timestamp = datetime.now()

        process_patterns = {
            IoCCategory.COMMAND_EXECUTION: [
                r'(?:executing|executed|running|ran).*?command.*?([^\n\r]+)',
                r'(?:runtime\.exec|processbuilder).*?([^\n\r]+)',
                r'(?:cmd|command).*?(?:=|:)\s*([^\n\r]+)',
            ],
            IoCCategory.PROCESS_CREATION: [
                r'(?:starting|started|spawning|spawned).*?process.*?([^\n\r]+)',
                r'(?:fork|exec|spawn).*?([^\n\r]+)',
                r'process.*?(?:created|launched).*?([^\n\r]+)',
            ],
            IoCCategory.ENVIRONMENT_MODIFICATION: [
                r'(?:environment|env).*?(?:variable|var).*?([A-Z_]+)=([^\s]+)',
                r'(?:setenv|export).*?([A-Z_]+)=([^\s]+)',
                r'(?:path|classpath).*?(?:modified|changed|set).*?([^\n\r]+)',
            ],
            IoCCategory.SYSTEM_CALL: [
                r'(?:syscall|system\s+call).*?([a-zA-Z_]+)',
                r'(?:native|jni).*?(?:call|invoke).*?([a-zA-Z_]+)',
            ],
            IoCCategory.PRIVILEGE_ESCALATION: [
                r'(?:sudo|su|admin|root|privilege).*?([^\n\r]+)',
                r'(?:escalat|elevat).*?privilege.*?([^\n\r]+)',
                r'(?:permission|access).*?(?:escalat|elevat).*?([^\n\r]+)',
            ],
        }

        for category, patterns in process_patterns.items():
            for pattern in patterns:
                matches = re.finditer(pattern, logs, re.IGNORECASE | re.MULTILINE)
                for match in matches:
                    value = match.group(1) if match.groups() else match.group(0)
                    confidence = self._calculate_process_confidence(category, value, match.group(0))
                    
                    if confidence >= IOC_MIN_CONFIDENCE_THRESHOLD:
                            
                        ioc = IoC(
                            ioc_type=IoCType.PROCESS,
                            category=category,
                            value=value.strip(),
                            description=f"Process {category.value} detected: {value.strip()}",
                            confidence=confidence,
                            confidence_level=IoCConfidenceLevel.LOW,
                            timestamp=timestamp,
                            source_line=match.group(0),
                            context={"pattern": pattern, "full_match": match.group(0)}
                        )
                        process_iocs.append(ioc)

        return process_iocs

    def _is_web_application_context(self, logs: str) -> bool:
        """Detect if logs are from a web application context to skip process pattern matching."""
        # Simple detection for web frameworks to avoid false positives
        web_indicators = [
            "spring boot",
            "tomcat",
            "webapplicationcontext",
            "servlet",
            "port 8080",
            "port 8081",
            "http"
        ]
        
        logs_lower = logs.lower()
        return any(indicator in logs_lower for indicator in web_indicators)

    def _extract_application_indicators(self, logs: str, vulnerability_type: str) -> List[IoC]:
        """Extract application-specific IoCs from logs."""
        application_iocs = []
        timestamp = datetime.now()

        application_patterns = {
            IoCCategory.FRAMEWORK_ERROR: [
                r'(?:spring|struts|hibernate|jackson).*?(?:error|exception|fail).*?([^\n\r]+)',
                r'(?:servlet|jsp|web).*?(?:error|exception).*?([^\n\r]+)',
                r'(?:framework|container).*?(?:error|fail).*?([^\n\r]+)',
            ],
            IoCCategory.SECURITY_EXCEPTION: [
                r'(?:security|access|permission).*?(?:exception|error|denied).*?([^\n\r]+)',
                r'(?:unauthorized|forbidden|access\s+denied).*?([^\n\r]+)',
                r'(?:authentication|authorization).*?(?:fail|error).*?([^\n\r]+)',
            ],
            IoCCategory.DESERIALIZATION_ATTEMPT: [
                r'(?:deserializ|serializ).*?(?:attempt|trying|processing).*?([^\n\r]+)',
                r'(?:@class|@type).*?([^\n\r\s}]+)',
                r'(?:objectinputstream|readobject).*?([^\n\r]+)',
            ],
            IoCCategory.INJECTION_PATTERN: [
                r'(?:jndi|ldap|rmi).*?(?:injection|lookup|exploit).*?([^\n\r]+)',
                r'(?:sql|code|command).*?injection.*?([^\n\r]+)',
                r'(?:script|expression).*?(?:injection|evaluation).*?([^\n\r]+)',
            ],
            IoCCategory.LIBRARY_LOADING: [
                r'(?:loading|loaded|importing|import).*?(?:library|class|jar).*?([^\n\r\s]+)',
                r'(?:classloader|loadclass).*?([^\n\r\s]+)',
                r'(?:reflection|invoke).*?([^\n\r\s]+)',
            ],
            IoCCategory.CONFIGURATION_CHANGE: [
                r'(?:configuration|config|setting).*?(?:changed|modified|updated).*?([^\n\r]+)',
                r'(?:property|parameter).*?(?:set|changed).*?([^\n\r]+)',
            ],
        }

        # Add vulnerability-specific patterns
        if vulnerability_type:
            vuln_specific_patterns = self._get_vulnerability_specific_patterns(vulnerability_type)
            for category, patterns in vuln_specific_patterns.items():
                if category in application_patterns:
                    application_patterns[category].extend(patterns)
                else:
                    application_patterns[category] = patterns

        for category, patterns in application_patterns.items():
            for pattern in patterns:
                matches = re.finditer(pattern, logs, re.IGNORECASE | re.MULTILINE)
                for match in matches:
                    value = match.group(1) if match.groups() else match.group(0)
                    confidence = self._calculate_application_confidence(category, value, match.group(0), vulnerability_type)
                    
                    if confidence >= IOC_MIN_CONFIDENCE_THRESHOLD:
                        ioc = IoC(
                            ioc_type=IoCType.APPLICATION,
                            category=category,
                            value=value.strip(),
                            description=f"Application {category.value} detected: {value.strip()}",
                            confidence=confidence,
                            confidence_level=IoCConfidenceLevel.LOW,
                            timestamp=timestamp,
                            source_line=match.group(0),
                            context={
                                "pattern": pattern,
                                "full_match": match.group(0),
                                "vulnerability_type": vulnerability_type
                            }
                        )
                        application_iocs.append(ioc)

        return application_iocs

    def _extract_timing_indicators(self, logs: str) -> List[IoC]:
        """Extract timing-related IoCs from logs."""
        timing_iocs = []
        timestamp = datetime.now()

        timing_patterns = {
            IoCCategory.EXECUTION_DELAY: [
                r'(?:delay|sleep|wait).*?(\d+).*?(?:ms|millisecond|second)',
                r'(?:took|elapsed|duration).*?(\d+).*?(?:ms|sec|minute)',
                r'(?:timeout|timed\s+out).*?(\d+)',
            ],
            IoCCategory.TIMEOUT_PATTERN: [
                r'(?:connection|request|operation).*?(?:timeout|timed\s+out).*?(\d+)',
                r'(?:socket|network).*?timeout.*?(\d+)',
                r'(?:read|write).*?timeout.*?(\d+)',
            ],
            IoCCategory.RESPONSE_TIME_ANOMALY: [
                r'(?:response|processing).*?time.*?(\d+).*?(?:ms|millisecond)',
                r'(?:slow|delayed).*?(?:response|request).*?(\d+)',
                r'(?:performance|latency).*?(?:issue|problem).*?(\d+)',
            ],
        }

        for category, patterns in timing_patterns.items():
            for pattern in patterns:
                matches = re.finditer(pattern, logs, re.IGNORECASE | re.MULTILINE)
                for match in matches:
                    value = match.group(1) if match.groups() else match.group(0)
                    confidence = self._calculate_timing_confidence(value)
                    
                    if confidence >= IOC_MIN_CONFIDENCE_THRESHOLD:
                        ioc = IoC(
                            ioc_type=IoCType.TIMING,
                            category=category,
                            value=value,
                            description=f"Timing {category.value} detected: {value}",
                            confidence=confidence,
                            confidence_level=IoCConfidenceLevel.LOW,
                            timestamp=timestamp,
                            source_line=match.group(0),
                            context={"pattern": pattern, "full_match": match.group(0)}
                        )
                        timing_iocs.append(ioc)

        return timing_iocs

    def _extract_behavioral_indicators(self, logs: str) -> List[IoC]:
        """Extract behavioral IoCs from logs."""
        behavioral_iocs = []
        timestamp = datetime.now()

        # Analyze log patterns for behavioral indicators
        log_lines = logs.split('\n')
        
        # Error frequency analysis
        error_count = len([line for line in log_lines if re.search(r'(?:error|exception|fail)', line, re.IGNORECASE)])
        if error_count > 5:  # Threshold for high error frequency
            confidence = min(0.7, error_count / len(log_lines) * 10)  # Scale confidence
            ioc = IoC(
                ioc_type=IoCType.BEHAVIORAL,
                category=IoCCategory.ERROR_FREQUENCY,
                value=str(error_count),
                description=f"High error frequency detected: {error_count} errors",
                confidence=confidence,
                confidence_level=IoCConfidenceLevel.LOW,
                timestamp=timestamp,
                context={"total_lines": len(log_lines), "error_ratio": error_count / len(log_lines)}
            )
            behavioral_iocs.append(ioc)

        # Resource consumption patterns
        resource_patterns = [
            r'(?:memory|heap|cpu).*?(?:usage|consumption|utilization).*?(\d+)',
            r'(?:out\s+of\s+memory|memory\s+leak|heap\s+space)',
            r'(?:high\s+cpu|cpu\s+spike|resource\s+exhaustion)',
        ]

        for pattern in resource_patterns:
            matches = list(re.finditer(pattern, logs, re.IGNORECASE | re.MULTILINE))
            if matches:
                for match in matches:
                    value = match.group(1) if match.groups() else "detected"
                    confidence = 0.6  # Medium confidence for resource issues
                    
                    ioc = IoC(
                        ioc_type=IoCType.BEHAVIORAL,
                        category=IoCCategory.RESOURCE_CONSUMPTION,
                        value=value,
                        description=f"Resource consumption pattern detected: {match.group(0)}",
                        confidence=confidence,
                        confidence_level=IoCConfidenceLevel.LOW,
                        timestamp=timestamp,
                        source_line=match.group(0),
                        context={"pattern": pattern}
                    )
                    behavioral_iocs.append(ioc)

        return behavioral_iocs

    def _calculate_network_confidence(self, category: IoCCategory, value: str, full_match: str) -> float:
        """Calculate confidence score for network IoCs."""
        base_confidence = 0.5
        
        # Increase confidence for specific patterns
        if category == IoCCategory.URL_ACCESS and any(proto in value.lower() for proto in ['jndi', 'ldap', 'rmi']):
            base_confidence = 0.8
        elif category == IoCCategory.HTTP_REQUEST and any(method in full_match.upper() for method in ['GET', 'POST']):
            base_confidence = 0.7
        elif category == IoCCategory.NETWORK_CONNECTION and re.match(r'\d+\.\d+\.\d+\.\d+', value):
            base_confidence = 0.6
        
        return min(base_confidence, 1.0)

    def _calculate_filesystem_confidence(self, category: IoCCategory, value: str, full_match: str) -> float:
        """Calculate confidence score for filesystem IoCs."""
        base_confidence = 0.4
        
        # Increase confidence for specific patterns
        if category == IoCCategory.TEMP_FILE_USAGE and '/tmp/' in value:
            base_confidence = 0.7
        elif category == IoCCategory.DIRECTORY_TRAVERSAL and '../' in value:
            base_confidence = 0.9
        elif category == IoCCategory.FILE_CREATION and any(word in full_match.lower() for word in ['created', 'writing']):
            base_confidence = 0.6
        
        return min(base_confidence, 1.0)

    def _calculate_process_confidence(self, category: IoCCategory, value: str, full_match: str) -> float:
        """Calculate confidence score for process IoCs."""
        base_confidence = 0.5
        
        # Increase confidence for specific patterns
        if category == IoCCategory.COMMAND_EXECUTION and any(cmd in value.lower() for cmd in ['exec', 'runtime']):
            base_confidence = 0.8
        elif category == IoCCategory.PRIVILEGE_ESCALATION and any(word in value.lower() for word in ['sudo', 'root', 'admin']):
            base_confidence = 0.9
        elif category == IoCCategory.PROCESS_CREATION and 'process' in full_match.lower():
            base_confidence = 0.6
        
        return min(base_confidence, 1.0)

    def _calculate_application_confidence(self, category: IoCCategory, value: str, full_match: str, vulnerability_type: str) -> float:
        """Calculate confidence score for application IoCs."""
        base_confidence = 0.5
        
        # Increase confidence for specific patterns
        if category == IoCCategory.DESERIALIZATION_ATTEMPT and '@class' in value:
            base_confidence = 0.9
        elif category == IoCCategory.INJECTION_PATTERN and 'jndi' in value.lower():
            base_confidence = 0.8
        elif category == IoCCategory.SECURITY_EXCEPTION and 'security' in full_match.lower():
            base_confidence = 0.7
        
        # Boost confidence if related to specific vulnerability type
        if vulnerability_type and vulnerability_type.lower() in full_match.lower():
            base_confidence = min(base_confidence + 0.2, 1.0)
        
        return min(base_confidence, 1.0)

    def _calculate_timing_confidence(self,value: str) -> float:
        """Calculate confidence score for timing IoCs."""
        base_confidence = 0.3
        
        try:
            # Increase confidence for longer delays
            time_value = int(value)
            if time_value > 1000:  # > 1 second
                base_confidence = 0.6
            elif time_value > 5000:  # > 5 seconds
                base_confidence = 0.8
        except ValueError:
            pass
        
        return min(base_confidence, 1.0)

    def _get_vulnerability_specific_patterns(self, vulnerability_type: str) -> Dict[IoCCategory, List[str]]:
        """Get vulnerability-specific patterns for enhanced application IoC detection."""
        patterns = {}
        
        if 'deserialization' in vulnerability_type.lower():
            patterns[IoCCategory.DESERIALIZATION_ATTEMPT] = [
                r'ObjectInputStream.*?readObject',
                r'@class.*?com\.sun\.',
                r'ysoserial.*?payload',
            ]
        
        if 'injection' in vulnerability_type.lower() or 'jndi' in vulnerability_type.lower():
            patterns[IoCCategory.INJECTION_PATTERN] = [
                r'\$\{jndi:.*?\}',
                r'ldap://.*?/exploit',
                r'rmi://.*?/exploit',
            ]
        
        if 'log4j' in vulnerability_type.lower():
            patterns[IoCCategory.INJECTION_PATTERN] = [
                r'\$\{.*?:.*?\}',
                r'log4j.*?lookup',
                r'jndi.*?exploit',
            ]
        
        return patterns

    def _limit_iocs_per_type(self, iocs: List[IoC]) -> List[IoC]:
        """Limit the number of IoCs per type based on configuration."""
        if IOC_MAX_IOCS_PER_TYPE <= 0:
            return iocs
        
        iocs_by_type = {}
        for ioc in iocs:
            if ioc.ioc_type not in iocs_by_type:
                iocs_by_type[ioc.ioc_type] = []
            iocs_by_type[ioc.ioc_type].append(ioc)
        
        # Sort by confidence and limit per type
        limited_iocs = []
        for ioc_type, type_iocs in iocs_by_type.items():
            # Sort by confidence (highest first)
            sorted_iocs = sorted(type_iocs, key=lambda x: x.confidence, reverse=True)
            limited_iocs.extend(sorted_iocs[:IOC_MAX_IOCS_PER_TYPE])
        
        return limited_iocs

    def build_ioc_collection(
        self, iocs: List[IoC], blueprint_id: str, container_id: str, vulnerability_type: str
    ) -> IoCCollection:
        """Build an organized IoC collection from extracted IoCs."""
        timestamp = datetime.now()
        
        # Organize IoCs by type and category
        iocs_by_type = {}
        iocs_by_category = {}
        confidence_summary = dict.fromkeys(IoCConfidenceLevel, 0)
        
        for ioc in iocs:
            # By type
            if ioc.ioc_type not in iocs_by_type:
                iocs_by_type[ioc.ioc_type] = []
            iocs_by_type[ioc.ioc_type].append(ioc)
            
            # By category
            if ioc.category not in iocs_by_category:
                iocs_by_category[ioc.category] = []
            iocs_by_category[ioc.category].append(ioc)
            
            # Confidence summary
            confidence_summary[ioc.confidence_level] += 1
        
        collection_metadata = {
            "extraction_method": "comprehensive_pattern_matching",
            "total_types_detected": len(iocs_by_type),
            "total_categories_detected": len(iocs_by_category),
            "high_confidence_count": confidence_summary[IoCConfidenceLevel.HIGH] + confidence_summary[IoCConfidenceLevel.CRITICAL],
        }
        
        return IoCCollection(
            blueprint_id=blueprint_id,
            container_id=container_id,
            vulnerability_type=vulnerability_type,
            collection_timestamp=timestamp,
            total_iocs=len(iocs),
            iocs_by_type=iocs_by_type,
            iocs_by_category=iocs_by_category,
            confidence_summary=confidence_summary,
            collection_metadata=collection_metadata
        )
