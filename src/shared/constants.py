import os
from pathlib import Path

# Import configuration manager for template-driven behavior
try:
    from utils.core.config_manager import get_setting
    CONFIG_MANAGER_AVAILABLE = True
except ImportError:
    CONFIG_MANAGER_AVAILABLE = False

# Base paths
PROJECT_ROOT = Path(__file__).parent.parent.parent
SRC_DIR = PROJECT_ROOT

# LLM Service defaults
DEFAULT_LLM_CONFIG = {
    "provider": "azure",
    "api_key": "",
    "api_version": "2023-05-15",
    "azure_endpoint": "",
    "azure_deployment": "",
    "model": "gpt-4",
    "temperature": 0.1,
    "max_tokens": 8000,
    "prompts_dir": "config/prompts",
}

# Data storage defaults
DEFAULT_DATA_DIR = SRC_DIR / "data"

# Blueprint Repository defaults
DEFAULT_BLUEPRINT_STORAGE_DIR = DEFAULT_DATA_DIR / "blueprints"

# Container Service defaults
DEFAULT_CONTAINER_DIR = DEFAULT_DATA_DIR / "containers"
DEFAULT_CONTAINER_NAME_PREFIX = "vulnapp"
DEFAULT_CONTAINER_NAME_PATTERN = r"^[a-z][a-z0-9_.-]{2,}$"
DEFAULT_CONTAINER_TIMEOUT = 60  # seconds

# System Integration defaults
DEFAULT_CONFIG_PATH = SRC_DIR / "src" / "config" / "llm_config.yaml"

# Error severity levels
INFO = "INFO"
WARNING = "WARNING"
ERROR = "ERROR"
CRITICAL = "CRITICAL"

# Error categories
CONFIGURATION_ERROR = "CONFIGURATION"
TEMPLATE_ERROR = "TEMPLATE"
CODE_GENERATION_ERROR = "CODE_GENERATION"
CONTAINER_BUILD_ERROR = "CONTAINER_BUILD"
DEPENDENCY_ERROR = "DEPENDENCY"
NETWORK_ERROR = "NETWORK"
PERMISSION_ERROR = "PERMISSION"
LLM_ERROR = "LLM"
VALIDATION_ERROR = "VALIDATION"
RESOURCE_ERROR = "RESOURCE"
UNKNOWN_ERROR = "UNKNOWN"

# File paths for templates
TEMPLATES_BASE_DIR = SRC_DIR / "src" / "templates"
JAVA_TEMPLATES_DIR = TEMPLATES_BASE_DIR / "container" / "java"
PYTHON_TEMPLATES_DIR = TEMPLATES_BASE_DIR / "container" / "python"
TEMPLATE_RESOURCES_DIR = TEMPLATES_BASE_DIR / "resources"

# Template subdirectories
TEMPLATE_CONTAINER_DIR = "container"
TEMPLATE_JAVA_DIR = "java"  # This is the key addition
TEMPLATE_POM_DIR = "pom"
TEMPLATE_REPOS_DIR = "repos"
TEMPLATE_CONTAINERFILE_DIR = "containerfile"
TEMPLATE_README_DIR = "readme"

# Default template sections
TEMPLATE_SECTIONS = [
    "METADATA",
    "IMPORTS",
    "DEMO_CODE",
    "RESOURCES",
    "EXPLOITATION",
    "MITIGATION",
    "DEPENDENCIES",
    "CONTAINER_CONFIG",
]

# Supported vulnerability categories
VULNERABILITY_CATEGORIES = ["xxe", "xss", "insecure_deserialization", "sql_injection", "command_injection", "other"]

# Port mapping settings
MIN_PORT = 1024
MAX_PORT = 65535
DEFAULT_PORT_MAPPING = "8080:8080"

# File size limits
MAX_FILE_SIZE = 1024 * 1024 * 10  # 10 MB

# Standard Java packages used in exploits
COMMON_JAVA_IMPORTS = [
    "import java.io.*;",
    "import java.util.*;",
    "import java.net.*;",
    "import java.security.*;",
    "import javax.script.*;",
    "import java.lang.reflect.*;",
]

# Package-specific available libraries for HTTP-based vulnerability demonstrations
# Maps package names to their available libraries for web application context
PACKAGE_AVAILABLE_LIBRARIES = {
    # Base libraries always available for web applications
    "_base": [
        "**Basic Java I/O**: java.io.* (File, InputStream, IOException, etc.) - but NOT java.nio.file.*",
        "**Java Utilities**: java.util.* (List, Map, Set, ArrayList, HashMap, etc.)",
        "**Java Lang**: java.lang.* (String, Integer, System, etc.)",
        "**Logging**: org.slf4j.* (Logger, LoggerFactory)",
        "**Spring Boot Web**: org.springframework.web.bind.annotation.* (RestController, RequestMapping, etc.)",
        "**Spring Boot Core**: org.springframework.boot.* (SpringApplication, etc.)",
        "**HTTP Servlet**: javax.servlet.http.* (HttpServletRequest, HttpServletResponse, etc.)",
    ],
    # Package-specific libraries
    "com.google.guava:guava": [
        "**Guava I/O**: com.google.common.io.* (Files, Resources, ByteStreams, etc.)",
        "**Guava Collections**: com.google.common.collect.* (Lists, Maps, Sets, etc.)",
        "**Guava Cache**: com.google.common.cache.* (Cache, CacheBuilder, etc.)",
        "**Guava Base**: com.google.common.base.* (Preconditions, Strings, etc.)",
        "**CRITICAL**: Use com.google.common.io.Files for file operations, NOT java.nio.file.Files",
    ],
    "com.fasterxml.jackson.core:jackson-databind": [
        "**Jackson JSON**: com.fasterxml.jackson.databind.* (ObjectMapper, JsonNode, etc.)",
        "**Jackson Core**: com.fasterxml.jackson.core.* (JsonParser, JsonGenerator, etc.)",
        "**Jackson Annotations**: com.fasterxml.jackson.annotation.* (JsonProperty, JsonIgnore, etc.)",
    ],
    "org.springframework:spring-core": [
        "**Spring Core**: org.springframework.* (BeanFactory, ApplicationContext, etc.)",
        "**Spring Boot**: org.springframework.boot.* (SpringApplication, autoconfigure, etc.)",
        "**Spring Web**: org.springframework.web.* (Controller, RequestMapping, etc.)",
        "**Spring MVC**: org.springframework.web.servlet.* (ModelAndView, etc.)",
    ],
    "org.springframework.boot:spring-boot": [
        "**Spring Boot Core**: org.springframework.boot.* (SpringApplication, autoconfigure, etc.)",
        "**Spring Web**: org.springframework.web.* (Controller, RequestMapping, etc.)",
        "**Spring Security**: org.springframework.security.* (SecurityFilterChain, HttpSecurity, etc.)",
        "**Spring Actuator**: org.springframework.boot.actuate.* (Endpoint, Health, etc.)",
        "**Spring Context**: org.springframework.context.* (Bean, Configuration, etc.)",
        "**IMPORTANT**: This is Spring Boot version 1.0.0 - use simple, basic APIs only",
        "**VERSION CONSTRAINT**: Avoid advanced features - stick to basic @SpringBootApplication and simple web endpoints",
        "**API GUIDANCE**: Use older Spring Security patterns like WebSecurityConfigurerAdapter if needed",
    ],
    "commons-collections:commons-collections": [
        "**Commons Collections**: org.apache.commons.collections.* (CollectionUtils, MapUtils, etc.)",
        "**Commons Collections4**: org.apache.commons.collections4.* (CollectionUtils, MapUtils, etc.)",
    ],
    "org.yaml:snakeyaml": ["**SnakeYAML**: org.yaml.snakeyaml.* (Yaml, Constructor, Representer, etc.)"],
    "org.apache.logging.log4j:log4j-core": ["**Log4j2**: org.apache.logging.log4j.* (Logger, LogManager, etc.)"],
    "com.alibaba:fastjson": ["**FastJSON**: com.alibaba.fastjson.* (JSON, JSONObject, JSONArray, etc.)"],
    "org.json:json": ["**JSON**: org.json.* (JSONObject, JSONArray, etc.)"],
    "org.apache.struts:struts2-core": [
        "**Basic Java I/O**: java.io.* (File, FileInputStream, FileOutputStream, InputStream, etc.)",
        "**Java Utilities**: java.util.* (List, Map, Set, ArrayList, HashMap, etc.)",
        "**HTTP Servlet**: javax.servlet.http.* (HttpServletRequest, HttpServletResponse, etc.)",
        "**Spring Web**: org.springframework.web.bind.annotation.* (RestController, RequestMapping, RequestParam, RequestBody, etc.)",
        "**Logging**: org.slf4j.* (Logger, LoggerFactory)",
        "**IMPORTANT**: Use ONLY basic Java I/O for file operations - avoid external file upload libraries",
        "**FILE HANDLING**: Use java.io.File, java.io.InputStream, java.io.OutputStream for file operations",
        "**NO EXTERNAL DEPS**: Do NOT use org.apache.commons.fileupload.* or other external file upload libraries",
    ],
}

# GitHub API Configuration
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")

# Reliability Configuration
CIRCUIT_BREAKER_FAILURE_THRESHOLD = int(os.getenv("CIRCUIT_BREAKER_FAILURE_THRESHOLD", "5"))
CIRCUIT_BREAKER_RECOVERY_TIMEOUT = int(os.getenv("CIRCUIT_BREAKER_RECOVERY_TIMEOUT", "60"))

# Framework Detection
FORCE_FRAMEWORK_TYPE = os.getenv("FORCE_FRAMEWORK_TYPE", "").lower()
ENABLE_GUIDED_PROCESS = os.getenv("ENABLE_GUIDED_PROCESS", "true").lower() == "true"

# Container Management
MAX_CONCURRENT_CONTAINERS = int(os.getenv("MAX_CONCURRENT_CONTAINERS", "5"))
CONTAINER_BUILD_TIMEOUT = int(os.getenv("CONTAINER_BUILD_TIMEOUT", "300"))
CONTAINER_HEALTH_CHECK_INTERVAL = int(os.getenv("CONTAINER_HEALTH_CHECK_INTERVAL", "30"))

# Dependency Management
DEFAULT_ADDITIONAL_DEPENDENCIES = (
    os.getenv("DEFAULT_ADDITIONAL_DEPENDENCIES", "").split(",") if os.getenv("DEFAULT_ADDITIONAL_DEPENDENCIES") else []
)

# LLM Enhancement Feature Flags
ENABLE_LLM_EXPLOITATION_GUIDANCE = os.getenv("ENABLE_LLM_EXPLOITATION_GUIDANCE", "true").lower() == "true"
ENABLE_LLM_SIMILARITY_ANALYSIS = os.getenv("ENABLE_LLM_SIMILARITY_ANALYSIS", "true").lower() == "true"
ENABLE_LLM_FRAMEWORK_DETECTION = os.getenv("ENABLE_LLM_FRAMEWORK_DETECTION", "false").lower() == "true"

# LLM Enhancement Timeouts
LLM_EXPLOITATION_TIMEOUT = int(os.getenv("LLM_EXPLOITATION_TIMEOUT", "120"))

# Template-Driven Configuration Constants
# These constants use the configuration manager when available, otherwise fall back to environment variables

def get_template_driven_setting(config_path: str, env_var: str, default_value, value_type=str):
    """Get setting from config manager or environment variable with type conversion."""
    if CONFIG_MANAGER_AVAILABLE:
        try:
            value = get_setting(config_path, os.getenv(env_var, default_value))
        except Exception:
            value = os.getenv(env_var, default_value)
    else:
        value = os.getenv(env_var, default_value)
    
    # Type conversion
    if value_type is bool:
        return str(value).lower() in ('true', '1', 'yes', 'on')
    elif value_type is int:
        try:
            return int(value)
        except (ValueError, TypeError):
            return int(default_value) if isinstance(default_value, (int, str)) else default_value
    elif value_type is float:
        try:
            return float(value)
        except (ValueError, TypeError):
            return float(default_value) if isinstance(default_value, (int, float, str)) else default_value
    else:
        return value

# Container Service Template-Driven Constants
CONTAINER_BUILD_TIMEOUT_SECONDS = lambda: get_template_driven_setting(
    'container_service.build.timeout_seconds', 'CONTAINER_BUILD_TIMEOUT', 300, int
)
CONTAINER_MAX_RETRIES = lambda: get_template_driven_setting(
    'container_service.build.max_retries', 'CONTAINER_MAX_RETRIES', 3, int
)
CONTAINER_ENABLE_LOG_FILTERING = lambda: get_template_driven_setting(
    'container_service.logging.enable_filtered_output', 'CONTAINER_ENABLE_LOG_FILTERING', True, bool
)
CONTAINER_MIN_DISK_SPACE_MB = lambda: get_template_driven_setting(
    'container_service.resources.min_disk_space_mb', 'CONTAINER_MIN_DISK_SPACE_MB', 100, int
)

# LLM Service Template-Driven Constants  
LLM_ENABLE_JSON_VALIDATION = lambda: get_template_driven_setting(
    'llm_service.response_processing.enable_json_validation', 'LLM_ENABLE_JSON_VALIDATION', True, bool
)
LLM_ENABLE_RESPONSE_CACHING = lambda: get_template_driven_setting(
    'llm_service.response_processing.enable_response_caching', 'LLM_ENABLE_RESPONSE_CACHING', True, bool
)
LLM_DEFAULT_TEMPERATURE = lambda: get_template_driven_setting(
    'llm_service.models.default_temperature', 'LLM_DEFAULT_TEMPERATURE', 0.1, float
)
LLM_DEFAULT_MAX_TOKENS = lambda: get_template_driven_setting(
    'llm_service.models.default_max_tokens', 'LLM_DEFAULT_MAX_TOKENS', 4000, int
)
LLM_MAX_CONCURRENT_REQUESTS = lambda: get_template_driven_setting(
    'llm_service.performance.max_concurrent_requests', 'LLM_MAX_CONCURRENT_REQUESTS', 10, int
)

# Error Recovery Template-Driven Constants
ERROR_RECOVERY_ENABLED = lambda: get_template_driven_setting(
    'error_recovery_service.recovery.enabled', 'ERROR_RECOVERY_ENABLED', True, bool
)
ERROR_RECOVERY_MAX_ATTEMPTS = lambda: get_template_driven_setting(
    'error_recovery_service.recovery.max_attempts_per_error', 'ERROR_RECOVERY_MAX_ATTEMPTS', 3, int
)
ERROR_RECOVERY_LLM_ENABLED = lambda: get_template_driven_setting(
    'error_recovery_service.recovery.enable_llm_analysis', 'ERROR_RECOVERY_LLM_ENABLED', True, bool
)
ERROR_RECOVERY_LOG_FILTERING = lambda: get_template_driven_setting(
    'error_recovery_service.log_processing.enable_filtered_analysis', 'ERROR_RECOVERY_LOG_FILTERING', True, bool
)

# Framework Adaptation Template-Driven Constants
FRAMEWORK_ADAPTATION_ENABLED = lambda: get_template_driven_setting(
    'framework_adaptation_service.adaptation.enabled', 'FRAMEWORK_ADAPTATION_ENABLED', True, bool
)
FRAMEWORK_LLM_SELECTION_ENABLED = lambda: get_template_driven_setting(
    'framework_adaptation_service.adaptation.enable_llm_driven_selection', 'FRAMEWORK_LLM_SELECTION_ENABLED', True, bool
)
FRAMEWORK_ADAPTATION_TIMEOUT = lambda: get_template_driven_setting(
    'framework_adaptation_service.performance.adaptation_timeout_seconds', 'FRAMEWORK_ADAPTATION_TIMEOUT', 120, int
)

# Performance Template-Driven Constants
MAX_MEMORY_USAGE_MB = lambda: get_template_driven_setting(
    'performance.memory.max_memory_usage_mb', 'MAX_MEMORY_USAGE_MB', 4096, int
)
MAX_CONCURRENT_OPERATIONS = lambda: get_template_driven_setting(
    'performance.concurrency.max_concurrent_operations', 'MAX_CONCURRENT_OPERATIONS', 5, int
)

# Reliability Template-Driven Constants
CIRCUIT_BREAKER_ENABLED = lambda: get_template_driven_setting(
    'reliability.circuit_breakers.enabled', 'CIRCUIT_BREAKER_ENABLED', True, bool
)
CIRCUIT_BREAKER_DEFAULT_FAILURE_THRESHOLD = lambda: get_template_driven_setting(
    'reliability.circuit_breakers.default_failure_threshold', 'CIRCUIT_BREAKER_FAILURE_THRESHOLD', 5, int
)
CIRCUIT_BREAKER_DEFAULT_RECOVERY_TIMEOUT = lambda: get_template_driven_setting(
    'reliability.circuit_breakers.default_recovery_timeout_seconds', 'CIRCUIT_BREAKER_RECOVERY_TIMEOUT', 60, int
)

# Security Template-Driven Constants
INPUT_VALIDATION_ENABLED = lambda: get_template_driven_setting(
    'security.input_validation.enabled', 'INPUT_VALIDATION_ENABLED', True, bool
)
MAX_INPUT_SIZE_MB = lambda: get_template_driven_setting(
    'security.input_validation.max_input_size_mb', 'MAX_INPUT_SIZE_MB', 50, int
)

# Debug Template-Driven Constants
VERBOSE_LOGGING_ENABLED = lambda: get_template_driven_setting(
    'debug.logging.enable_verbose_logging', 'VERBOSE_LOGGING_ENABLED', False, bool
)
PERFORMANCE_METRICS_ENABLED = lambda: get_template_driven_setting(
    'debug.logging.log_performance_metrics', 'PERFORMANCE_METRICS_ENABLED', True, bool
)

# Backward compatibility - keep existing constants as lambda functions for lazy evaluation
def _update_legacy_constants():
    """Update legacy constants to use template-driven values."""
    global CIRCUIT_BREAKER_FAILURE_THRESHOLD, CIRCUIT_BREAKER_RECOVERY_TIMEOUT
    
    # Only update if config manager is available
    if CONFIG_MANAGER_AVAILABLE:
        try:
            CIRCUIT_BREAKER_FAILURE_THRESHOLD = CIRCUIT_BREAKER_DEFAULT_FAILURE_THRESHOLD()
            CIRCUIT_BREAKER_RECOVERY_TIMEOUT = CIRCUIT_BREAKER_DEFAULT_RECOVERY_TIMEOUT()
        except Exception:
            # Keep existing values if config manager fails
            pass

# Initialize legacy constants
_update_legacy_constants()
LLM_SIMILARITY_TIMEOUT = int(os.getenv("LLM_SIMILARITY_TIMEOUT", "45"))
LLM_FRAMEWORK_TIMEOUT = int(os.getenv("LLM_FRAMEWORK_TIMEOUT", "20"))

# IoC Collection Configuration
IOC_COLLECTION_ENABLED = os.getenv("IOC_COLLECTION_ENABLED", "true").lower() == "true"
IOC_COLLECTION_DIR = DEFAULT_DATA_DIR / "monitoring" / "ioc_collection"
IOC_STRUCTURED_STORAGE_ENABLED = os.getenv("IOC_STRUCTURED_STORAGE_ENABLED", "true").lower() == "true"

# IoC Storage Subdirectories
IOC_NETWORK_DIR = IOC_COLLECTION_DIR / "network"
IOC_FILESYSTEM_DIR = IOC_COLLECTION_DIR / "filesystem"
IOC_PROCESS_DIR = IOC_COLLECTION_DIR / "process"
IOC_APPLICATION_DIR = IOC_COLLECTION_DIR / "application"
IOC_TIMING_DIR = IOC_COLLECTION_DIR / "timing"
IOC_BEHAVIORAL_DIR = IOC_COLLECTION_DIR / "behavioral"

# IoC Collection Settings
IOC_MIN_CONFIDENCE_THRESHOLD = float(os.getenv("IOC_MIN_CONFIDENCE_THRESHOLD", "0.1"))
IOC_MAX_IOCS_PER_TYPE = int(os.getenv("IOC_MAX_IOCS_PER_TYPE", "100"))
IOC_COLLECTION_TIMEOUT = int(os.getenv("IOC_COLLECTION_TIMEOUT", "30"))
IOC_ENABLE_DETAILED_EXTRACTION = os.getenv("IOC_ENABLE_DETAILED_EXTRACTION", "true").lower() == "true"

# IoC Pattern Matching Configuration
IOC_NETWORK_PATTERNS_ENABLED = os.getenv("IOC_NETWORK_PATTERNS_ENABLED", "true").lower() == "true"
IOC_FILESYSTEM_PATTERNS_ENABLED = os.getenv("IOC_FILESYSTEM_PATTERNS_ENABLED", "true").lower() == "true"
IOC_PROCESS_PATTERNS_ENABLED = os.getenv("IOC_PROCESS_PATTERNS_ENABLED", "true").lower() == "true"
IOC_APPLICATION_PATTERNS_ENABLED = os.getenv("IOC_APPLICATION_PATTERNS_ENABLED", "true").lower() == "true"
IOC_TIMING_PATTERNS_ENABLED = os.getenv("IOC_TIMING_PATTERNS_ENABLED", "true").lower() == "true"
IOC_BEHAVIORAL_PATTERNS_ENABLED = os.getenv("IOC_BEHAVIORAL_PATTERNS_ENABLED", "true").lower() == "true"

# Error Recovery Configuration
ERROR_RECOVERY_ENABLED = os.getenv("ERROR_RECOVERY_ENABLED", "true").lower() == "true"
ERROR_RECOVERY_DIR = DEFAULT_DATA_DIR / "error_patterns"
ERROR_RECOVERY_ATTEMPTS_DIR = DEFAULT_DATA_DIR / "recovery_attempts"

# Error Recovery Storage Subdirectories
ERROR_PATTERNS_CACHE_DIR = ERROR_RECOVERY_DIR / "patterns_cache"
ERROR_FIXES_CACHE_DIR = ERROR_RECOVERY_DIR / "fixes_cache"
ERROR_LEARNING_DATA_DIR = ERROR_RECOVERY_DIR / "learning_data"
OSV_REFERENCES_CACHE_DIR = ERROR_RECOVERY_DIR / "osv_references"

# Error Recovery Settings
ERROR_RECOVERY_MAX_ATTEMPTS = int(os.getenv("ERROR_RECOVERY_MAX_ATTEMPTS", "3"))
ERROR_RECOVERY_TIMEOUT = int(os.getenv("ERROR_RECOVERY_TIMEOUT", "600"))

# Error Recovery LLM Settings
ERROR_RECOVERY_LLM_ENABLED = os.getenv("ERROR_RECOVERY_LLM_ENABLED", "true").lower() == "true"
ERROR_RECOVERY_LLM_TEMPERATURE = float(os.getenv("ERROR_RECOVERY_LLM_TEMPERATURE", "0.3"))
ERROR_RECOVERY_LLM_MAX_TOKENS = int(os.getenv("ERROR_RECOVERY_LLM_MAX_TOKENS", "2000"))

# Note: Complex error recovery settings removed - now using simple configuration in the service
