import logging
import os
import re
import time
from dataclasses import dataclass
from pathlib import Path
from threading import Lock
from typing import Any, Dict, List, Optional

import yaml

from shared.constants import PROJECT_ROOT

logger = logging.getLogger(__name__)

@dataclass
class ConfigValidationResult:
    """Result of configuration validation."""
    is_valid: bool
    errors: List[str]
    warnings: List[str]

class ConfigurationManager:
    """Centralized configuration manager for all FORGE services."""
    
    _instance = None
    _lock = Lock()
    
    def __new__(cls, config_path: Optional[str] = None):
        """Singleton pattern implementation."""
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._initialized = False
            return cls._instance
    
    def __init__(self, config_path: Optional[str] = None):
        """Initialize configuration manager."""
        if self._initialized:
            return
            
        if config_path is None:
            config_path = PROJECT_ROOT / "src" / "config" / "service_config.yaml"
        
        self.config_path = config_path
        self.config_cache = {}
        self.last_reload = {}
        self.cache_ttl = 300  # 5 minutes
        
        self._load_configuration()
        self._initialized = True
    
    def _load_configuration(self) -> None:
        """Load configuration from YAML file."""
        try:
            with open(self.config_path, 'r') as f:
                self.config = yaml.safe_load(f)
            
            # Apply environment variable substitutions
            self.config = self._substitute_env_vars(self.config)
            
            # Validate configuration
            validation_result = self._validate_configuration()
            if not validation_result.is_valid:
                logger.error(f"Configuration validation failed: {validation_result.errors}")
                # Use default configuration
                self.config = self._get_default_configuration()
            elif validation_result.warnings:
                for warning in validation_result.warnings:
                    logger.warning(f"Configuration warning: {warning}")
            
            logger.info(f"Configuration loaded successfully from {self.config_path}")
            
        except Exception as e:
            logger.error(f"Failed to load configuration: {e}")
            self.config = self._get_default_configuration()
    
    def _substitute_env_vars(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Substitute environment variables in configuration values."""
        def substitute_value(value):
            if isinstance(value, str):
                # Handle ${VAR_NAME} and ${VAR_NAME:default_value} patterns
                def replace_env_var(match):
                    var_part = match.group(1)
                    if ':' in var_part:
                        var_name, default_value = var_part.split(':', 1)
                        return os.getenv(var_name, default_value)
                    else:
                        return os.getenv(var_part, match.group(0))  # Return original if not found
                
                return re.sub(r'\$\{([^}]+)\}', replace_env_var, value)
            elif isinstance(value, dict):
                return {k: substitute_value(v) for k, v in value.items()}
            elif isinstance(value, list):
                return [substitute_value(item) for item in value]
            else:
                return value
        
        return substitute_value(config)
    
    def _validate_configuration(self) -> ConfigValidationResult:
        """Validate configuration structure and values."""
        errors = []
        warnings = []
        
        # Required top-level services
        required_services = [
            'container_service', 'llm_service', 'error_recovery_service',
            'framework_adaptation_service', 'template_manager',
            'exploit_validation_service', 'deployment_agent'
        ]
        
        for service in required_services:
            if service not in self.config:
                errors.append(f"Missing required service configuration: {service}")
        
        # Validate specific configuration sections
        self._validate_container_service_config(warnings)
        self._validate_llm_service_config(errors, warnings)
        self._validate_paths_config(warnings)
        
        return ConfigValidationResult(
            is_valid=len(errors) == 0,
            errors=errors,
            warnings=warnings
        )

    def _validate_container_service_config(self, warnings: List[str]) -> None:
        """Validate container service configuration."""
        if 'container_service' not in self.config:
            return
        
        container_config = self.config['container_service']
        
        # Validate timeout values
        build_timeout = container_config.get('build', {}).get('timeout_seconds', 0)
        if build_timeout <= 0 or build_timeout > 3600:
            warnings.append("Container build timeout should be between 1 and 3600 seconds")
        
        # Validate resource limits
        min_disk_space = container_config.get('resources', {}).get('min_disk_space_mb', 0)
        if min_disk_space < 10:
            warnings.append("Minimum disk space should be at least 10MB")
    
    def _validate_llm_service_config(self, errors: List[str], warnings: List[str]) -> None:
        """Validate LLM service configuration."""
        if 'llm_service' not in self.config:
            return
        
        llm_config = self.config['llm_service']
        
        # Validate temperature values
        temperature = llm_config.get('models', {}).get('default_temperature', 0.1)
        if not 0 <= temperature <= 2.0:
            errors.append("LLM temperature must be between 0 and 2.0")
        
        # Validate max tokens
        max_tokens = llm_config.get('models', {}).get('default_max_tokens', 4000)
        if max_tokens <= 0 or max_tokens > 32000:
            warnings.append("LLM max_tokens should be between 1 and 32000")

    def _validate_paths_config(self, warnings: List[str]) -> None:
        """Validate file paths in configuration."""
        # Check if referenced configuration files exist
        llm_config = self.config.get('llm_service', {})
        schemas_path = llm_config.get('json_validation', {}).get('schemas_config_path')
        if schemas_path and not Path(schemas_path).exists():
            warnings.append(f"LLM schemas config file not found: {schemas_path}")
        
        # Check log filtering config
        container_config = self.config.get('container_service', {})
        log_filter_path = container_config.get('logging', {}).get('log_filter_config_path')
        if log_filter_path and not Path(log_filter_path).exists():
            warnings.append(f"Log filtering config file not found: {log_filter_path}")
    
    def _get_default_configuration(self) -> Dict[str, Any]:
        """Get default configuration when loading fails."""
        return {
            'container_service': {
                'build': {'timeout_seconds': 300, 'max_retries': 3},
                'logging': {'enable_filtered_output': True},
                'resources': {'min_disk_space_mb': 100}
            },
            'llm_service': {
                'response_processing': {'enable_json_validation': True},
                'json_validation': {'enable_automatic_repair': True},
                'models': {'default_temperature': 0.1, 'default_max_tokens': 4000}
            },
            'error_recovery_service': {
                'recovery': {'enabled': True, 'max_attempts_per_error': 3},
                'log_processing': {'enable_filtered_analysis': True}
            },
            'framework_adaptation_service': {
                'adaptation': {'enabled': True, 'enable_llm_driven_selection': True}
            },
            'performance': {
                'memory': {'max_memory_usage_mb': 4096},
                'concurrency': {'max_concurrent_operations': 5}
            },
            'reliability': {
                'circuit_breakers': {'enabled': True, 'default_failure_threshold': 5}
            }
        }
    
    def get_service_config(self, service_name: str, use_cache: bool = True) -> Dict[str, Any]:
        """
        Get configuration for a specific service.
        
        Args:
            service_name: Name of the service
            use_cache: Whether to use cached configuration
            
        Returns:
            Service configuration dictionary
        """
        if use_cache and service_name in self.config_cache:
            cache_entry = self.config_cache[service_name]
            if time.time() - cache_entry['timestamp'] < self.cache_ttl:
                return cache_entry['config']
        
        # Get service configuration
        service_config = self.config.get(service_name, {})
        
        # Apply global settings if applicable
        service_config = self._apply_global_settings(service_config)
        
        # Cache the result
        if use_cache:
            self.config_cache[service_name] = {
                'config': service_config,
                'timestamp': time.time()
            }
        
        return service_config
    
    def _apply_global_settings(self, service_config: Dict[str, Any]) -> Dict[str, Any]:
        """Apply global settings to service configuration."""
        # Apply global performance settings
        if 'performance' in self.config:
            global_perf = self.config['performance']
            
            # Apply memory settings if not overridden
            if 'memory' not in service_config.get('performance', {}):
                if 'performance' not in service_config:
                    service_config['performance'] = {}
                service_config['performance']['memory'] = global_perf.get('memory', {})
        
        # Apply global reliability settings
        if 'reliability' in self.config:
            global_reliability = self.config['reliability']
            
            # Apply circuit breaker settings if not overridden
            if 'circuit_breakers' not in service_config.get('reliability', {}):
                if 'reliability' not in service_config:
                    service_config['reliability'] = {}
                service_config['reliability']['circuit_breakers'] = global_reliability.get('circuit_breakers', {})
        
        return service_config
    
    def get_setting(self, path: str, default: Any = None) -> Any:
        """
        Get a specific setting using dot notation.
        
        Args:
            path: Dot-separated path to the setting (e.g., 'llm_service.models.default_temperature')
            default: Default value if setting not found
            
        Returns:
            Setting value or default
        """
        try:
            value = self.config
            for key in path.split('.'):
                value = value[key]
            return value
        except (KeyError, TypeError):
            return default
    
    def set_setting(self, path: str, value: Any) -> None:
        """
        Set a specific setting using dot notation.
        
        Args:
            path: Dot-separated path to the setting
            value: Value to set
        """
        keys = path.split('.')
        config = self.config
        
        # Navigate to the parent of the target key
        for key in keys[:-1]:
            if key not in config:
                config[key] = {}
            config = config[key]
        
        # Set the value
        config[keys[-1]] = value
        
        # Clear cache for affected service
        service_name = keys[0]
        if service_name in self.config_cache:
            del self.config_cache[service_name]
    
    def reload_configuration(self, force: bool = False) -> bool:
        """
        Reload configuration from file.
        
        Args:
            force: Force reload even if file hasn't changed
            
        Returns:
            True if configuration was reloaded
        """
        try:
            # Check if file has been modified
            file_mtime = os.path.getmtime(self.config_path)
            last_reload = self.last_reload.get('config', 0)
            
            if not force and file_mtime <= last_reload:
                return False
            
            # Reload configuration
            self._load_configuration()
            self.last_reload['config'] = file_mtime
            
            # Clear all caches
            self.config_cache.clear()
            
            logger.info("Configuration reloaded successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to reload configuration: {e}")
            return False
    
    def get_all_services(self) -> List[str]:
        """Get list of all configured services."""
        excluded_keys = {'performance', 'reliability', 'security', 'debug'}
        return [key for key in self.config.keys() if key not in excluded_keys]
    
    def validate_service_config(self, service_name: str) -> ConfigValidationResult:
        """Validate configuration for a specific service."""
        errors = []
        warnings = []
        
        if service_name not in self.config:
            errors.append(f"Service '{service_name}' not found in configuration")
            return ConfigValidationResult(False, errors, warnings)
        
        # Service-specific validation
        if service_name == 'container_service':
            self._validate_container_service_config(warnings)
        elif service_name == 'llm_service':
            self._validate_llm_service_config(errors, warnings)
        
        return ConfigValidationResult(len(errors) == 0, errors, warnings)
    
    def export_configuration(self, file_path: str, include_defaults: bool = False) -> bool:
        """
        Export current configuration to a file.
        
        Args:
            file_path: Path to export file
            include_defaults: Whether to include default values
            
        Returns:
            True if export was successful
        """
        try:
            config_to_export = self.config.copy()
            
            if not include_defaults:
                # Remove default values (implementation depends on requirements)
                pass
            
            with open(file_path, 'w') as f:
                yaml.dump(config_to_export, f, default_flow_style=False, indent=2)
            
            logger.info(f"Configuration exported to {file_path}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to export configuration: {e}")
            return False

# Global configuration manager instance
config_manager = ConfigurationManager()

# Convenience functions for easy access
def get_service_config(service_name: str) -> Dict[str, Any]:
    """Get configuration for a service."""
    return config_manager.get_service_config(service_name)

def get_setting(path: str, default: Any = None) -> Any:
    """Get a specific setting using dot notation."""
    return config_manager.get_setting(path, default)

def set_setting(path: str, value: Any) -> None:
    """Set a specific setting using dot notation."""
    config_manager.set_setting(path, value)

def reload_config() -> bool:
    """Reload configuration from file."""
    return config_manager.reload_configuration()

# Service-specific convenience functions
def get_container_config() -> Dict[str, Any]:
    """Get container service configuration."""
    return get_service_config('container_service')

def get_llm_config() -> Dict[str, Any]:
    """Get LLM service configuration."""
    return get_service_config('llm_service')

def get_error_recovery_config() -> Dict[str, Any]:
    """Get error recovery service configuration."""
    return get_service_config('error_recovery_service')

def get_framework_adaptation_config() -> Dict[str, Any]:
    """Get framework adaptation service configuration."""
    return get_service_config('framework_adaptation_service')