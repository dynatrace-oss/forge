import asyncio
import logging
import threading
import time
import weakref
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from shared.constants import DEFAULT_DATA_DIR, PROJECT_ROOT

logger = logging.getLogger(__name__)


class ServiceState(Enum):
    """Service health states."""

    HEALTHY = "healthy"
    DEGRADED = "degraded"
    FAILED = "failed"
    CIRCUIT_OPEN = "circuit_open"


@dataclass
class CircuitBreakerConfig:
    """Configuration for circuit breaker."""

    failure_threshold: int = 5
    recovery_timeout: int = 60
    half_open_max_calls: int = 3


@dataclass
class ServiceMetrics:
    """Metrics for a service."""

    total_calls: int = 0
    successful_calls: int = 0
    failed_calls: int = 0
    last_failure_time: Optional[float] = None
    consecutive_failures: int = 0
    average_response_time: float = 0.0

    def success_rate(self) -> float:
        """Calculate success rate."""
        if self.total_calls == 0:
            return 1.0
        return self.successful_calls / self.total_calls


class CircuitBreaker:
    """Circuit breaker implementation for service reliability."""

    def __init__(self, service_name: str, config: CircuitBreakerConfig = None):
        self.service_name = service_name
        self.config = config or CircuitBreakerConfig()
        self.state = ServiceState.HEALTHY
        self.metrics = ServiceMetrics()
        self.last_failure_time = 0
        self.half_open_calls = 0
        self._lock = threading.Lock()

    async def call(self, func: Callable, *args, **kwargs) -> Any:
        """
        Execute function with circuit breaker protection.

        Args:
            func: Function to execute
            *args: Function arguments
            **kwargs: Function keyword arguments

        Returns:
            Function result

        Raises:
            CircuitOpenError: When circuit is open
            Exception: Original function exceptions when circuit is closed
        """
        with self._lock:
            if self.state == ServiceState.CIRCUIT_OPEN:
                if time.time() - self.last_failure_time < self.config.recovery_timeout:
                    raise CircuitOpenError(f"Circuit breaker open for {self.service_name}")
                else:
                    # Try to transition to half-open
                    self.state = ServiceState.DEGRADED
                    self.half_open_calls = 0
                    logger.info(f"Circuit breaker for {self.service_name} transitioning to half-open")

            elif self.state == ServiceState.DEGRADED:
                if self.half_open_calls >= self.config.half_open_max_calls:
                    raise CircuitOpenError(f"Circuit breaker half-open limit reached for {self.service_name}")

        # Execute the function
        start_time = time.time()
        try:
            if asyncio.iscoroutinefunction(func):
                result = await func(*args, **kwargs)
            else:
                result = func(*args, **kwargs)

            # Record success
            self._record_success(time.time() - start_time)
            return result

        except Exception as e:
            # Record failure
            logging.info(f"Failed to execute code with circuit breaker: {e}")
            self._record_failure()
            raise

    def _record_success(self, response_time: float):
        """Record successful call."""
        with self._lock:
            self.metrics.total_calls += 1
            self.metrics.successful_calls += 1
            self.metrics.consecutive_failures = 0

            # Update average response time
            if self.metrics.total_calls == 1:
                self.metrics.average_response_time = response_time
            else:
                self.metrics.average_response_time = (
                    self.metrics.average_response_time * (self.metrics.total_calls - 1) + response_time
                ) / self.metrics.total_calls

            # Transition to healthy if in degraded state
            if self.state == ServiceState.DEGRADED:
                self.state = ServiceState.HEALTHY
                logger.info(f"Circuit breaker for {self.service_name} recovered to healthy state")

    def _record_failure(self):
        """Record failed call."""
        with self._lock:
            self.metrics.total_calls += 1
            self.metrics.failed_calls += 1
            self.metrics.consecutive_failures += 1
            self.metrics.last_failure_time = time.time()
            self.last_failure_time = time.time()

            if self.state == ServiceState.DEGRADED:
                self.half_open_calls += 1

            # Check if we should open the circuit
            if self.metrics.consecutive_failures >= self.config.failure_threshold:
                self.state = ServiceState.CIRCUIT_OPEN
                logger.warning(
                    f"Circuit breaker opened for {self.service_name} after {self.metrics.consecutive_failures} failures"
                )


class CircuitOpenError(Exception):
    """Exception raised when circuit breaker is open."""

    pass


class ReliabilityManager:
    """
    Manages reliability features across the FORGE system.
    """

    def __init__(self):
        self.circuit_breakers: Dict[str, CircuitBreaker] = {}
        self.resource_locks: Dict[str, asyncio.Lock] = {}
        self.cleanup_tasks: List[asyncio.Task] = []
        self.service_health: Dict[str, ServiceState] = {}

    def get_circuit_breaker(self, service_name: str) -> CircuitBreaker:
        """Get or create circuit breaker for service."""
        if service_name not in self.circuit_breakers:
            self.circuit_breakers[service_name] = CircuitBreaker(service_name)
        return self.circuit_breakers[service_name]

    def get_resource_lock(self, resource_name: str) -> asyncio.Lock:
        """Get or create lock for resource."""
        if resource_name not in self.resource_locks:
            self.resource_locks[resource_name] = asyncio.Lock()
        return self.resource_locks[resource_name]

    @asynccontextmanager
    async def atomic_operation(self, operation_name: str):
        """
        Context manager for atomic operations.

        Args:
            operation_name: Name of the operation for logging
        """
        lock = self.get_resource_lock(operation_name)
        cleanup_functions = []

        try:
            async with lock:
                logger.debug(f"Starting atomic operation: {operation_name}")
                yield cleanup_functions
                logger.debug(f"Completed atomic operation: {operation_name}")
        except Exception as e:
            logger.error(f"Error in atomic operation {operation_name}: {e}")
            # Execute cleanup functions in reverse order
            for cleanup_func in reversed(cleanup_functions):
                try:
                    if asyncio.iscoroutinefunction(cleanup_func):
                        await cleanup_func()
                    else:
                        cleanup_func()
                except Exception as cleanup_error:
                    logger.error(f"Error in cleanup for {operation_name}: {cleanup_error}")
            raise

    def schedule_cleanup(self, cleanup_func: Callable):
        """Schedule a cleanup function to run on shutdown."""
        try:
            # Only create tasks if we have a running event loop
            _ = asyncio.get_running_loop()
            if asyncio.iscoroutinefunction(cleanup_func):
                task = asyncio.create_task(cleanup_func())
            else:
                task = asyncio.create_task(asyncio.to_thread(cleanup_func))

            self.cleanup_tasks.append(task)

            # Keep weak reference to avoid circular references
            weak_task = weakref.ref(task)
            task.add_done_callback(lambda t: self.cleanup_tasks.remove(t) if weak_task() in self.cleanup_tasks else None)
        except RuntimeError:
            # No event loop running, store the function for later scheduling
            logger.debug("No event loop running, deferring cleanup function scheduling")
            if not hasattr(self, '_deferred_cleanup_funcs'):
                self._deferred_cleanup_funcs = []
            self._deferred_cleanup_funcs.append(cleanup_func)

    def _schedule_deferred_cleanup_funcs(self):
        """Schedule any deferred cleanup functions given we have an event loop."""
        if hasattr(self, '_deferred_cleanup_funcs'):
            for cleanup_func in self._deferred_cleanup_funcs:
                try:
                    if asyncio.iscoroutinefunction(cleanup_func):
                        task = asyncio.create_task(cleanup_func())
                    else:
                        task = asyncio.create_task(asyncio.to_thread(cleanup_func))
                    
                    self.cleanup_tasks.append(task)
                    
                    # Keep weak reference to avoid circular references
                    weak_task = weakref.ref(task)
                    task.add_done_callback(lambda t=weak_task(): self.cleanup_tasks.remove(t) if t() in self.cleanup_tasks else None)
                except Exception as e:
                    logger.error(f"Error scheduling deferred cleanup function: {e}")
            
            # Clear the deferred list
            self._deferred_cleanup_funcs.clear()

    async def shutdown(self):
        """Graceful shutdown with cleanup."""
        logger.info("Starting reliability manager shutdown")
        
        # Schedule any deferred cleanup functions
        self._schedule_deferred_cleanup_funcs()

        # Cancel and wait for cleanup tasks
        for task in self.cleanup_tasks:
            if not task.done():
                task.cancel()

        if self.cleanup_tasks:
            await asyncio.gather(*self.cleanup_tasks, return_exceptions=True)

        logger.info("Reliability manager shutdown completed")

    def get_system_health(self) -> Dict[str, Any]:
        """Get overall system health status."""
        health_summary = {"overall_status": "healthy", "services": {}, "circuit_breakers": {}}

        # Check circuit breakers
        failed_services = 0
        for name, cb in self.circuit_breakers.items():
            health_summary["circuit_breakers"][name] = {
                "state": cb.state.value,
                "success_rate": cb.metrics.success_rate(),
                "total_calls": cb.metrics.total_calls,
                "consecutive_failures": cb.metrics.consecutive_failures,
                "average_response_time": cb.metrics.average_response_time,
            }

            if cb.state in [ServiceState.FAILED, ServiceState.CIRCUIT_OPEN]:
                failed_services += 1

        # Determine overall status
        if failed_services == 0:
            health_summary["overall_status"] = "healthy"
        elif failed_services < len(self.circuit_breakers) / 2:
            health_summary["overall_status"] = "degraded"
        else:
            health_summary["overall_status"] = "failed"

        return health_summary

    def cleanup_redundant_files(self, project_root: Path = None) -> Dict[str, Any]:
        """
        Remove redundant files and consolidate duplicate templates.
        
        Args:
            project_root: Project root directory (defaults to shared constants)
            
        Returns:
            Dictionary with cleanup results
        """
        if project_root is None:
            project_root = PROJECT_ROOT
            
        templates_dir = project_root / "src" / "templates"
        
        results = {
            "files_removed": [],
            "directories_removed": [],
            "duplicates_consolidated": [],
            "errors": [],
            "total_space_freed": 0,
        }
        
        logger.info("Starting redundant files cleanup")
        
        try:
            # Remove redundant template files
            redundant_files = [
                templates_dir / "core" / "standalone_jar.xml",
            ]
            
            for file_path in redundant_files:
                if file_path.exists():
                    try:
                        file_size = file_path.stat().st_size
                        file_path.unlink()
                        results["files_removed"].append(str(file_path))
                        results["total_space_freed"] += file_size
                        logger.info(f"Removed redundant file: {file_path} ({file_size} bytes)")
                    except Exception as e:
                        results["errors"].append(f"Failed to remove {file_path}: {e}")
            
            # Remove empty directories
            empty_dirs = [
                templates_dir / "container" / "python",
            ]
            
            for dir_path in empty_dirs:
                if dir_path.exists() and dir_path.is_dir():
                    try:
                        if not any(dir_path.iterdir()):  # Directory is empty
                            dir_path.rmdir()
                            results["directories_removed"].append(str(dir_path))
                            logger.info(f"Removed empty directory: {dir_path}")
                    except Exception as e:
                        results["errors"].append(f"Failed to remove directory {dir_path}: {e}")
            
            # Clean up temporary files
            temp_patterns = ["*.tmp", "*.bak", "*~", ".DS_Store"]
            for pattern in temp_patterns:
                temp_files = list(project_root.rglob(pattern))
                for temp_file in temp_files:
                    try:
                        file_size = temp_file.stat().st_size
                        temp_file.unlink()
                        results["files_removed"].append(str(temp_file))
                        results["total_space_freed"] += file_size
                    except Exception as e:
                        results["errors"].append(f"Failed to remove {temp_file}: {e}")
            
            logger.info(f"Redundant files cleanup completed: {len(results['files_removed'])} files, "
                       f"{len(results['directories_removed'])} directories, "
                       f"{results['total_space_freed']} bytes freed")
            
        except Exception as e:
            error_msg = f"Error during redundant files cleanup: {e}"
            logger.error(error_msg)
            results["errors"].append(error_msg)
        
        return results

    def cleanup_old_data(self, data_dir: Path = None, retention_policies: Dict[str, int] = None) -> Dict[str, Any]:
        """
        Clean up old monitoring data based on retention policies.
        
        Args:
            data_dir: Data directory (defaults to shared constants)
            retention_policies: Custom retention policies in days
            
        Returns:
            Dictionary with cleanup results
        """
        if data_dir is None:
            data_dir = DEFAULT_DATA_DIR
            
        if retention_policies is None:
            retention_policies = {
                "validation_results": 7,
                "container_logs": 7,
                "exploit_reports": 14,
                "poc_cache": 30,
                "error_patterns": 30,
                "ioc_collection": 14,
            }
        
        results = {
            "data_types_cleaned": [],
            "files_removed": [],
            "total_space_freed": 0,
            "errors": [],
        }
        
        logger.info("Starting old data cleanup")
        
        try:
            monitoring_dir = data_dir / "monitoring"
            if monitoring_dir.exists():
                # Clean up each data type based on retention policy
                for data_type, retention_days in retention_policies.items():
                    data_type_dir = monitoring_dir / data_type
                    if data_type_dir.exists():
                        cutoff_date = datetime.now() - timedelta(days=retention_days)
                        
                        for file_path in data_type_dir.rglob("*"):
                            if file_path.is_file():
                                try:
                                    file_mtime = datetime.fromtimestamp(file_path.stat().st_mtime)
                                    if file_mtime < cutoff_date:
                                        file_size = file_path.stat().st_size
                                        file_path.unlink()
                                        results["files_removed"].append(str(file_path))
                                        results["total_space_freed"] += file_size
                                except Exception as e:
                                    results["errors"].append(f"Failed to process {file_path}: {e}")
                        
                        results["data_types_cleaned"].append(data_type)
            
            logger.info(f"Old data cleanup completed: {len(results['files_removed'])} files, "
                       f"{results['total_space_freed']} bytes freed")
                       
        except Exception as e:
            error_msg = f"Error during old data cleanup: {e}"
            logger.error(error_msg)
            results["errors"].append(error_msg)
        
        return results

    def perform_system_maintenance(self) -> Dict[str, Any]:
        """
        Perform comprehensive system maintenance including cleanup and health checks.
        
        Returns:
            Dictionary with maintenance results
        """
        logger.info("Starting system maintenance")
        
        maintenance_results = {
            "timestamp": datetime.now().isoformat(),
            "redundant_files_cleanup": {},
            "old_data_cleanup": {},
            "system_health": {},
            "overall_success": True,
        }
        
        try:
            # Clean redundant files
            maintenance_results["redundant_files_cleanup"] = self.cleanup_redundant_files()
            
            # Clean old data
            maintenance_results["old_data_cleanup"] = self.cleanup_old_data()
            
            # Check system health
            maintenance_results["system_health"] = self.get_system_health()
            
            # Determine overall success
            has_errors = (
                maintenance_results["redundant_files_cleanup"].get("errors", []) or
                maintenance_results["old_data_cleanup"].get("errors", [])
            )
            maintenance_results["overall_success"] = not has_errors
            
            logger.info(f"System maintenance completed successfully: {maintenance_results['overall_success']}")
            
        except Exception as e:
            error_msg = f"Error during system maintenance: {e}"
            logger.error(error_msg)
            maintenance_results["overall_success"] = False
            maintenance_results["error"] = error_msg
        
        return maintenance_results


# Global reliability manager instance
reliability_manager = ReliabilityManager()
