import logging
import re
from collections import defaultdict
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

import yaml

from shared.constants import PROJECT_ROOT

logger = logging.getLogger(__name__)

@dataclass
class LogFilterResult:
    """Result of log filtering operation."""
    filtered_output: str
    summary: Dict[str, Any]
    error_indicators: List[Dict[str, str]]
    statistics: Dict[str, int]
    original_line_count: int
    filtered_line_count: int

@dataclass
class ErrorIndicator:
    """Represents an error found in logs."""
    type: str
    message: str
    line_number: int
    context_before: List[str]
    context_after: List[str]
    severity: str

class LogProcessor:
    """Intelligent log processor with template-driven filtering."""
    
    def __init__(self, config_path: Optional[str] = None):
        """Initialize log processor with configuration."""
        if config_path is None:
            config_path = PROJECT_ROOT / "src" / "config" / "log_filtering.yaml"
        
        self.config_path = config_path
        self.config = self._load_config()
        self._compile_patterns()
        
    def _load_config(self) -> Dict[str, Any]:
        """Load log filtering configuration from YAML file."""
        try:
            with open(self.config_path, 'r') as f:
                config = yaml.safe_load(f)
            
            # Validate patterns if enabled in config (not self.config which doesn't exist yet)
            if config.get('debug', {}).get('validate_patterns', True):
                self._validate_patterns(config)
                
            return config
        except Exception as e:
            logger.warning(f"Failed to load log filtering config: {e}")
            return self._get_default_config()
    
    def _get_default_config(self) -> Dict[str, Any]:
        """Get default configuration if config file fails to load."""
        return {
            'build_log_filters': {
                'maven': {
                    'exclude_patterns': [
                        r'^Progress \(\d+\):',
                        r'^Downloaded from central:',
                        r'^Downloading from central:'
                    ],
                    'include_patterns': [
                        r'\[ERROR\]',
                        r'\[WARN\]',
                        r'BUILD FAILURE',
                        r'BUILD SUCCESS'
                    ],
                    'summarize': {
                        'dependency_downloads': True,
                        'progress_indicators': False
                    },
                    'max_context_lines': 200,
                    'error_context_lines': {
                        'before': 2,
                        'after': 3
                    }
                },
                'container': {
                    'exclude_patterns': [
                        r'^STEP \d+/\d+:',
                        r'^--> Using cache',
                        r'^--> [a-f0-9]{12}$'
                    ],
                    'include_patterns': [
                        r'ERROR',
                        r'WARN',
                        r'FAILED'
                    ],
                    'max_context_lines': 200,
                    'error_context_lines': {'before': 2, 'after': 3}
                }
            }
        }
    
    def _validate_patterns(self, config: Dict[str, Any]) -> None:
        """Validate regex patterns in configuration."""
        def validate_pattern_list(patterns: List[str], context: str):
            for pattern in patterns:
                try:
                    re.compile(pattern)
                except re.error as e:
                    logger.error(f"Invalid regex pattern in {context}: '{pattern}' - {e}")
                    raise ValueError(f"Invalid regex pattern: {pattern}")
        
        for filter_type, filters in config.get('build_log_filters', {}).items():
            validate_pattern_list(
                filters.get('exclude_patterns', []), 
                f"build_log_filters.{filter_type}.exclude_patterns"
            )
            validate_pattern_list(
                filters.get('include_patterns', []), 
                f"build_log_filters.{filter_type}.include_patterns"
            )
    
    def _compile_patterns(self) -> None:
        """Compile regex patterns for performance."""
        self.compiled_patterns = {}
        
        for filter_type, filters in self.config.get('build_log_filters', {}).items():
            self.compiled_patterns[filter_type] = {
                'exclude': [re.compile(pattern) for pattern in filters.get('exclude_patterns', [])],
                'include': [re.compile(pattern) for pattern in filters.get('include_patterns', [])],
                'critical': [re.compile(pattern) for pattern in 
                           self.config.get('error_recovery', {}).get('critical_patterns', {}).get(filter_type, [])]
            }
    
    def filter_build_output(self, raw_output: str, build_type: str = 'maven') -> LogFilterResult:
        """
        Filter build output using template-driven rules.
        
        Args:
            raw_output: Raw build output string
            build_type: Type of build (maven, container, etc.)
            
        Returns:
            LogFilterResult with filtered output and metadata
        """
        if not raw_output or not raw_output.strip():
            return LogFilterResult(
                filtered_output="",
                summary={},
                error_indicators=[],
                statistics={'original_lines': 0, 'filtered_lines': 0},
                original_line_count=0,
                filtered_line_count=0
            )
        
        lines = raw_output.split('\n')
        original_line_count = len(lines)
        
        # Get filter configuration for this build type
        filter_config = self.config.get('build_log_filters', {}).get(build_type, {})
        if not filter_config:
            logger.warning(f"No filter configuration found for build type: {build_type}")
            return self._create_unfiltered_result(raw_output, lines)
        
        # Apply filtering
        filtered_lines, error_indicators, stats = self._apply_filters(
            lines, build_type
        )
        
        # Apply context preservation around errors
        final_lines = self._apply_error_context(lines, filtered_lines, error_indicators, filter_config)
        
        # Generate summary
        summary = self._generate_summary(lines, filtered_lines, build_type, filter_config)
        
        # Ensure we don't exceed max context lines
        max_lines = filter_config.get('max_context_lines', 200)
        if len(final_lines) > max_lines:
            final_lines = self._prioritize_important_lines(final_lines, max_lines)
        
        return LogFilterResult(
            filtered_output='\n'.join(final_lines),
            summary=summary,
            error_indicators=[error.to_dict() for error in error_indicators],
            statistics=stats,
            original_line_count=original_line_count,
            filtered_line_count=len(final_lines)
        )
    
    def _apply_filters(self, lines: List[str], build_type: str) -> Tuple[List[str], List[ErrorIndicator], Dict[str, int]]:
        """Apply include/exclude filters to log lines."""
        filtered_lines = []
        error_indicators = []
        stats = defaultdict(int)
        
        exclude_patterns = self.compiled_patterns.get(build_type, {}).get('exclude', [])
        include_patterns = self.compiled_patterns.get(build_type, {}).get('include', [])
        
        for line_num, line in enumerate(lines):
            line = line.rstrip()
            if not line:
                stats['empty_lines'] += 1
                continue
                
            # Check for errors first
            error_indicator = self._check_for_errors(line, line_num)
            if error_indicator:
                error_indicators.append(error_indicator)
                filtered_lines.append(line)
                stats['error_lines'] += 1
                continue
            
            # Check include patterns (high priority)
            if any(pattern.search(line) for pattern in include_patterns):
                filtered_lines.append(line)
                stats['included_lines'] += 1
                continue
            
            # Check exclude patterns
            if any(pattern.search(line) for pattern in exclude_patterns):
                stats['excluded_lines'] += 1
                continue
            
            # Default: include if no patterns match
            filtered_lines.append(line)
            stats['default_included'] += 1
        
        stats['total_processed'] = len(lines)
        return filtered_lines, error_indicators, dict(stats)
    
    def _check_for_errors(self, line: str, line_num: int) -> Optional[ErrorIndicator]:
        """Check if line contains error indicators."""
        error_patterns = self.config.get('error_recovery', {}).get('critical_patterns', {})
        
        for error_type, patterns in error_patterns.items():
            for pattern in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    severity = 'ERROR' if 'error' in line.lower() else 'WARNING'
                    return ErrorIndicator(
                        type=error_type,
                        message=line.strip(),
                        line_number=line_num,
                        context_before=[],
                        context_after=[],
                        severity=severity
                    )
        
        return None
    
    def _apply_error_context(self, original_lines: List[str], filtered_lines: List[str], 
                           error_indicators: List[ErrorIndicator], config: Dict[str, Any]) -> List[str]:
        """Add context lines around errors."""
        if not error_indicators:
            return filtered_lines
        
        context_config = config.get('error_context_lines', {'before': 2, 'after': 3})
        before_lines = context_config.get('before', 2)
        after_lines = context_config.get('after', 3)
        
        # Build set of line numbers to include
        include_line_nums = set()
        
        for error in error_indicators:
            line_num = error.line_number
            # Add context before
            for i in range(max(0, line_num - before_lines), line_num):
                include_line_nums.add(i)
            # Add error line itself
            include_line_nums.add(line_num)
            # Add context after
            for i in range(line_num + 1, min(len(original_lines), line_num + after_lines + 1)):
                include_line_nums.add(i)
        
        # Add context to error indicators
        for error in error_indicators:
            line_num = error.line_number
            error.context_before = [
                original_lines[i] for i in range(max(0, line_num - before_lines), line_num)
                if i < len(original_lines)
            ]
            error.context_after = [
                original_lines[i] for i in range(line_num + 1, min(len(original_lines), line_num + after_lines + 1))
                if i < len(original_lines)
            ]
        
        # Merge with filtered lines (preserve filtered lines, add missing context)
        result_lines = []
        filtered_set = set(filtered_lines)
        
        for i, line in enumerate(original_lines):
            if line in filtered_set or i in include_line_nums:
                result_lines.append(line)
        
        return result_lines
    
    def _prioritize_important_lines(self, lines: List[str], 
                                   max_lines: int) -> List[str]:
        """Prioritize most important lines when over the limit."""
        if len(lines) <= max_lines:
            return lines
        
        # Priority scoring
        line_scores = {}
        for i, line in enumerate(lines):
            score = 0
            
            # High priority for errors and warnings
            if any(keyword in line.lower() for keyword in ['error', 'failed', 'exception']):
                score += 100
            elif any(keyword in line.lower() for keyword in ['warning', 'warn']):
                score += 50
            
            # Medium priority for build indicators
            if any(keyword in line for keyword in ['BUILD', 'Building', 'Scanning']):
                score += 25
            
            # Lower priority for info messages
            if '[INFO]' in line:
                score += 5
            
            line_scores[i] = score
        
        # Sort by score and take top lines
        sorted_indices = sorted(line_scores.keys(), key=lambda x: line_scores[x], reverse=True)
        top_indices = sorted(sorted_indices[:max_lines])
        
        return [lines[i] for i in top_indices]
    
    def _generate_summary(self, original_lines: List[str], filtered_lines: List[str], 
                         build_type: str, config: Dict[str, Any]) -> Dict[str, Any]:
        """Generate summary of filtering operation."""
        summary = {
            'original_line_count': len(original_lines),
            'filtered_line_count': len(filtered_lines),
            'reduction_percentage': round((1 - len(filtered_lines) / max(len(original_lines), 1)) * 100, 2),
            'build_type': build_type
        }
        
        # Add build-specific summaries
        summarize_config = config.get('summarize', {})
        
        if summarize_config.get('dependency_downloads', False):
            download_count = sum(1 for line in original_lines if 'Downloaded from' in line)
            summary['dependency_downloads'] = download_count
        
        if summarize_config.get('download_sizes', False):
            total_size = self._calculate_download_sizes(original_lines)
            summary['total_download_size'] = total_size
        
        if summarize_config.get('timing_info', False):
            timing = self._extract_timing_info(original_lines)
            summary['build_timing'] = timing
        
        return summary
    
    def _calculate_download_sizes(self, lines: List[str]) -> str:
        """Calculate total download sizes from log lines."""
        total_kb = 0
        for line in lines:
            # Look for patterns like "Downloaded from central: ... (123 kB at 456 kB/s)"
            match = re.search(r'\((\d+(?:\.\d+)?)\s*kB\s+at', line)
            if match:
                total_kb += float(match.group(1))
        
        if total_kb > 1024:
            return f"{total_kb/1024:.1f} MB"
        else:
            return f"{total_kb:.1f} kB"
    
    def _extract_timing_info(self, lines: List[str]) -> Dict[str, str]:
        """Extract build timing information."""
        timing = {}
        for line in lines:
            if 'Total time:' in line:
                match = re.search(r'Total time:\s*(.+)', line)
                if match:
                    timing['total_time'] = match.group(1).strip()
            elif 'Finished at:' in line:
                match = re.search(r'Finished at:\s*(.+)', line)
                if match:
                    timing['finished_at'] = match.group(1).strip()
        return timing
    
    def _create_unfiltered_result(self, raw_output: str, lines: List[str]) -> LogFilterResult:
        """Create result for unfiltered output (fallback)."""
        return LogFilterResult(
            filtered_output=raw_output,
            summary={
                'original_line_count': len(lines),
                'filtered_line_count': len(lines),
                'reduction_percentage': 0.0,
                'filtering_applied': False
            },
            error_indicators=[],
            statistics={'total_processed': len(lines), 'unfiltered': len(lines)},
            original_line_count=len(lines),
            filtered_line_count=len(lines)
        )
    
    def extract_error_summary(self, log_output: str, build_type: str = 'maven') -> Dict[str, Any]:
        """
        Extract structured error summary for error recovery system.
        
        Args:
            log_output: Raw log output
            build_type: Type of build process
            
        Returns:
            Structured error summary suitable for LLM error analysis
        """
        filter_result = self.filter_build_output(log_output, build_type)
        
        error_config = self.config.get('error_recovery', {}).get('error_summary', {})
        max_errors = error_config.get('max_errors_per_type', 5)
        
        # Group errors by type
        errors_by_type = defaultdict(list)
        for error_dict in filter_result.error_indicators:
            error_type = error_dict.get('type', 'unknown')
            errors_by_type[error_type].append(error_dict)
        
        # Limit errors per type
        for error_type in errors_by_type:
            errors_by_type[error_type] = errors_by_type[error_type][:max_errors]
        
        return {
            'build_type': build_type,
            'total_errors': len(filter_result.error_indicators),
            'errors_by_type': dict(errors_by_type),
            'filtered_log': filter_result.filtered_output,
            'summary': filter_result.summary,
            'critical_lines': self._extract_critical_lines(filter_result.filtered_output),
            'error_context': self._build_error_context(errors_by_type)
        }
    
    def _extract_critical_lines(self, filtered_output: str) -> List[str]:
        """Extract most critical lines for error analysis."""
        lines = filtered_output.split('\n')
        critical_lines = []
        
        critical_keywords = ['ERROR', 'FAILED', 'Exception', 'BUILD FAILURE', 'compilation failure']
        
        for line in lines:
            if any(keyword in line for keyword in critical_keywords):
                critical_lines.append(line.strip())
        
        return critical_lines[:10]  # Limit to top 10 critical lines
    
    def _build_error_context(self, errors_by_type: Dict[str, List[Dict]]) -> Dict[str, str]:
        """Build concise error context for each error type."""
        context = {}

        for error_type, errors in errors_by_type.items():
            if not errors:
                continue

            # Get most representative error message
            messages = [error.get('message', '') for error in errors]
            context[error_type] = {
                'count': len(errors),
                'sample_message': messages[0] if messages else '',
                'all_unique_messages': list(set(messages))[:3]  # Up to 3 unique messages
            }

        return context

    def analyze_build_error(self, error_output: str) -> str:
        """
        Analyze build error output for user-friendly error messages.

        Args:
            error_output: Error output from build process

        Returns:
            User-friendly error message
        """
        original_error = error_output
        error_output_lower = error_output.lower()

        logger.info(f"Analyzing build error output ({len(error_output)} characters)")
        logger.debug(f"Error output preview: {error_output[:500]}...")

        # Check for Maven compilation errors first
        if "exit status 1" in error_output_lower and "mvn" in error_output_lower:
            return self.extract_maven_failure(original_error)
        elif "compilation failed" in error_output_lower or "maven-compiler-plugin" in error_output_lower:
            return self.extract_compilation_errors(original_error)
        elif "network timeout" in error_output_lower:
            return "Network timeout while downloading dependencies. Check your internet connection."
        elif "not found" in error_output_lower and "dependency" in error_output_lower:
            dep_match = re.search(r"dependency[^'\"]*['\"]([^'\"]+)['\"]", error_output_lower)
            if dep_match:
                dep_name = dep_match.group(1)
                return f"Maven dependency '{dep_name}' not found. The specified version may not be available."

            version_match = re.search(r"version[^'\"]*['\"]([^'\"]+)['\"]", error_output_lower)
            if version_match:
                version = version_match.group(1)
                return (
                    f"Maven dependency version '{version}' not found. This version may not exist in the repositories."
                )

            return "Maven dependency resolution failed. Package version may not be available."
        elif "no such file" in error_output_lower:
            return "File not found error during build. Check resource paths."
        elif "compilation failed" in error_output_lower:
            return "Java compilation failed. Generated code may have syntax errors."
        elif "out of memory" in error_output_lower:
            return "Build process ran out of memory. Try increasing available memory."
        elif "could not resolve host" in error_output_lower:
            return "Network connectivity issue. Unable to resolve host during dependency download."
        elif "unauthorized" in error_output_lower:
            return "Authorization error accessing Maven repository. Check network settings."
        else:
            error_lines = original_error.splitlines()
            relevant_lines = [line for line in error_lines if "error" in line.lower()]
            if relevant_lines:
                return f"Build error: {relevant_lines[0]}"

            return f"Container build failed: {original_error[:200]}..." if len(original_error) > 200 else original_error

    def extract_maven_failure(self, error_output: str) -> str:
        """
        Extract detailed Maven build failure information when Maven exits with status 1.

        Args:
            error_output: Raw error output from Maven build

        Returns:
            Detailed error message explaining the Maven build failure
        """
        logger.info("Extracting Maven build failure details")

        if "compilation failed" in error_output.lower() or "maven-compiler-plugin" in error_output.lower():
            return self.extract_compilation_errors(error_output)

        error_lines = error_output.split('\n')

        for line in error_lines:
            line_lower = line.lower()
            if "[error]" in line_lower:
                error_content = line.strip()
                logger.info(f"Found Maven error line: {error_content}")
                return f"Maven build failed: {error_content}"
            elif "failed to execute goal" in line_lower:
                return f"Maven goal execution failed: {line.strip()}"
            elif "build failure" in line_lower:
                return f"Maven build failure: {line.strip()}"

        logger.warning("Could not extract specific Maven error details from output")
        return f"Maven build failed with exit code 1. Check Maven logs for details. Error output: {error_output[:300]}..."

    def extract_compilation_errors(self, error_output: str) -> str:
        """
        Extract Java compilation error details from Maven compiler output.

        Args:
            error_output: Raw error output from Maven compilation

        Returns:
            Detailed compilation error message
        """
        logger.info("Extracting Java compilation error details")

        compilation_errors = []
        error_lines = error_output.split('\n')

        for i, line in enumerate(error_lines):
            line_lower = line.lower()

            if any(pattern in line_lower for pattern in [
                "cannot find symbol",
                "package does not exist",
                "cannot be resolved to a type",
                "method is undefined",
                "the import cannot be resolved",
                "syntax error",
                "duplicate class"
            ]):
                context_lines = []
                for j in range(max(0, i-2), min(len(error_lines), i+3)):
                    context_lines.append(error_lines[j].strip())

                error_context = " | ".join([line for line in context_lines if line])
                compilation_errors.append(error_context)
                logger.info(f"Found Java compilation error: {error_context}")

        if compilation_errors:
            primary_error = compilation_errors[0]
            additional_count = len(compilation_errors) - 1

            result = f"Java compilation failed: {primary_error}"
            if additional_count > 0:
                result += f" (and {additional_count} more compilation errors)"

            return result

        for line in error_lines:
            if "compilation failed" in line.lower():
                return f"Java compilation failed: {line.strip()}"

        logger.warning("Could not extract specific Java compilation error details")
        return f"Java compilation failed. Check Maven logs for details. Error output: {error_output[:300]}..."

    def format_error_by_type(self, error_type: str, errors: list) -> str:
        """
        Format error message based on error type and context.

        Args:
            error_type: Type of error (dependency_issues, compilation_errors, etc.)
            errors: List of error objects

        Returns:
            Formatted error message
        """
        if not errors:
            return "Build failed with unknown error"

        first_error = errors[0]
        error_message = first_error.get('message', '') if isinstance(first_error, dict) else str(first_error)

        if error_type == 'dependency_issues':
            if 'could not resolve' in error_message.lower():
                return "Maven dependency resolution failed. Check package name and version availability."
            elif 'not found' in error_message.lower():
                return "Maven dependency not found. The specified version may not exist in repositories."
            else:
                return "Dependency resolution error during build."

        elif error_type == 'compilation_errors':
            if 'cannot find symbol' in error_message.lower():
                return "Java compilation failed: Symbol not found. Check imports and dependencies."
            elif 'package does not exist' in error_message.lower():
                return "Java compilation failed: Package not found. Check dependencies and imports."
            else:
                return "Java compilation failed. Check generated code for syntax errors."

        elif error_type == 'container_errors':
            if 'no such file' in error_message.lower():
                return "Container build failed: File not found. Check resource paths in container."
            elif 'permission denied' in error_message.lower():
                return "Container build failed: Permission denied. Check file permissions."
            else:
                return "Container build error occurred."

        elif error_type == 'runtime_errors':
            return "Runtime error during container build process."

        return f"Build error ({error_type}): {error_message[:150]}..."

    def analyze_error_summary(self, error_summary: dict) -> str:
        """
        Analyze filtered build error summary for user-friendly error messages.

        Args:
            error_summary: Structured error summary from log processor

        Returns:
            User-friendly error message
        """
        try:
            errors_by_type = error_summary.get('errors_by_type', {})
            critical_lines = error_summary.get('critical_lines', [])

            error_priority = [
                'compilation_errors',
                'dependency_issues',
                'container_errors',
                'runtime_errors'
            ]

            for error_type in error_priority:
                if error_type in errors_by_type and errors_by_type[error_type]:
                    errors = errors_by_type[error_type]
                    return self.format_error_by_type(error_type, errors)

            if critical_lines:
                return f"Build failed: {critical_lines[0]}"

            filtered_log = error_summary.get('filtered_log', '')
            if filtered_log:
                lines = [line.strip() for line in filtered_log.split('\n') if line.strip()]
                if lines:
                    return f"Build error: {lines[0]}"

            return "Container build failed with unknown error"

        except Exception as e:
            logger.warning(f"Error analyzing filtered build error: {e}")
            filtered_log = error_summary.get('filtered_log', '')
            return f"Build failed: {filtered_log[:200]}..." if len(filtered_log) > 200 else "Container build failed"

# Add to ErrorIndicator class
class ErrorIndicator:
    """Represents an error found in logs."""
    
    def __init__(self, type: str, message: str, line_number: int, 
                 context_before: List[str] = None, context_after: List[str] = None, 
                 severity: str = 'ERROR'):
        self.type = type
        self.message = message
        self.line_number = line_number
        self.context_before = context_before or []
        self.context_after = context_after or []
        self.severity = severity
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            'type': self.type,
            'message': self.message,
            'line_number': self.line_number,
            'context_before': self.context_before,
            'context_after': self.context_after,
            'severity': self.severity
        }

# Convenience function for easy usage
def filter_build_log(raw_output: str, build_type: str = 'maven', config_path: Optional[str] = None) -> LogFilterResult:
    """
    Convenience function to filter build logs.
    
    Args:
        raw_output: Raw build output
        build_type: Type of build (maven, container, etc.)
        config_path: Optional path to config file
        
    Returns:
        Filtered log result
    """
    processor = LogProcessor(config_path)
    return processor.filter_build_output(raw_output, build_type)