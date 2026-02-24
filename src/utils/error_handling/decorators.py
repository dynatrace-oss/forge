import asyncio
import functools
import logging
import time
from typing import Any, Callable, Optional, TypeVar, Union

logger = logging.getLogger(__name__)

# Type variable for generic return types
T = TypeVar('T')


def with_error_recovery(
    default_return: Any = None,
    log_level: str = "error",
    reraise: bool = False,
    context: str = None
):
    """
    Decorator for consistent error handling with recovery.
    
    Args:
        default_return: Value to return on error (None by default)
        log_level: Logging level for errors ("error", "warning", "info")
        reraise: Whether to re-raise the exception after logging
        context: Context string for error messages
        
    Example:
        @with_error_recovery(default_return={}, context="blueprint_creation")
        def create_blueprint(self, data):
            # code here
            pass
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        async def async_wrapper(*args, **kwargs):
            func_context = context or f"{func.__module__}.{func.__name__}"
            try:
                return await func(*args, **kwargs)
            except Exception as e:
                log_func = getattr(logger, log_level, logger.error)
                log_func(
                    f"Error in {func_context}: {type(e).__name__}: {e}",
                    exc_info=log_level == "error"
                )
                if reraise:
                    raise
                return default_return
        
        @functools.wraps(func)
        def sync_wrapper(*args, **kwargs):
            func_context = context or f"{func.__module__}.{func.__name__}"
            try:
                return func(*args, **kwargs)
            except Exception as e:
                log_func = getattr(logger, log_level, logger.error)
                log_func(
                    f"Error in {func_context}: {type(e).__name__}: {e}",
                    exc_info=log_level == "error"
                )
                if reraise:
                    raise
                return default_return
        
        # Return appropriate wrapper based on function type
        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        else:
            return sync_wrapper
    
    return decorator


def with_retry(
    max_attempts: int = 3,
    delay: float = 1.0,
    backoff: float = 2.0,
    exceptions: tuple = (Exception,),
    context: str = None
):
    """
    Decorator for automatic retry with exponential backoff.
    
    Args:
        max_attempts: Maximum number of retry attempts
        delay: Initial delay between retries (seconds)
        backoff: Backoff multiplier for each retry
        exceptions: Tuple of exception types to catch and retry
        context: Context string for error messages
        
    Example:
        @with_retry(max_attempts=3, delay=2.0, context="llm_call")
        async def call_llm(self, prompt):
            # code here
            pass
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        async def async_wrapper(*args, **kwargs):
            func_context = context or f"{func.__module__}.{func.__name__}"
            last_exception = None
            current_delay = delay
            
            for attempt in range(1, max_attempts + 1):
                try:
                    return await func(*args, **kwargs)
                except exceptions as e:
                    last_exception = e
                    if attempt < max_attempts:
                        logger.warning(
                            f"Attempt {attempt}/{max_attempts} failed for {func_context}: {e}. "
                            f"Retrying in {current_delay}s..."
                        )
                        await asyncio.sleep(current_delay)
                        current_delay *= backoff
                    else:
                        logger.error(
                            f"All {max_attempts} attempts failed for {func_context}: {e}"
                        )
            
            # All attempts failed
            raise last_exception
        
        @functools.wraps(func)
        def sync_wrapper(*args, **kwargs):
            func_context = context or f"{func.__module__}.{func.__name__}"
            last_exception = None
            current_delay = delay
            
            for attempt in range(1, max_attempts + 1):
                try:
                    return func(*args, **kwargs)
                except exceptions as e:
                    last_exception = e
                    if attempt < max_attempts:
                        logger.warning(
                            f"Attempt {attempt}/{max_attempts} failed for {func_context}: {e}. "
                            f"Retrying in {current_delay}s..."
                        )
                        time.sleep(current_delay)
                        current_delay *= backoff
                    else:
                        logger.error(
                            f"All {max_attempts} attempts failed for {func_context}: {e}"
                        )
            
            # All attempts failed
            raise last_exception
        
        # Return appropriate wrapper based on function type
        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        else:
            return sync_wrapper
    
    return decorator


def with_circuit_breaker(
    failure_threshold: int = 5,
    recovery_timeout: float = 60.0,
    expected_exception: type = Exception,
    context: str = None
):
    """
    Decorator implementing circuit breaker pattern.
    Prevents cascading failures by stopping calls after threshold.
    
    Args:
        failure_threshold: Number of failures before opening circuit
        recovery_timeout: Seconds to wait before attempting recovery
        expected_exception: Exception type to count as failure
        context: Context string for error messages
        
    Example:
        @with_circuit_breaker(failure_threshold=5, context="external_api")
        async def call_external_api(self, data):
            # code here
            pass
    """
    def decorator(func: Callable) -> Callable:
        # Circuit breaker state
        state = {
            'failures': 0,
            'last_failure_time': None,
            'is_open': False
        }
        
        @functools.wraps(func)
        async def async_wrapper(*args, **kwargs):
            func_context = context or f"{func.__module__}.{func.__name__}"
            
            # Check if circuit is open
            if state['is_open']:
                # Check if recovery timeout has passed
                if time.time() - state['last_failure_time'] > recovery_timeout:
                    logger.info(f"Circuit breaker for {func_context}: Attempting recovery")
                    state['is_open'] = False
                    state['failures'] = 0
                else:
                    raise RuntimeError(
                        f"Circuit breaker open for {func_context}. "
                        f"Too many failures ({state['failures']}). "
                        f"Retry after {recovery_timeout}s."
                    )
            
            try:
                result = await func(*args, **kwargs)
                # Success - reset failure count
                if state['failures'] > 0:
                    logger.info(f"Circuit breaker for {func_context}: Recovered after failures")
                    state['failures'] = 0
                return result
                
            except expected_exception:
                state['failures'] += 1
                state['last_failure_time'] = time.time()
                
                if state['failures'] >= failure_threshold:
                    state['is_open'] = True
                    logger.error(
                        f"Circuit breaker OPENED for {func_context} "
                        f"after {failure_threshold} failures"
                    )
                
                raise
        
        @functools.wraps(func)
        def sync_wrapper(*args, **kwargs):
            func_context = context or f"{func.__module__}.{func.__name__}"
            
            # Check if circuit is open
            if state['is_open']:
                # Check if recovery timeout has passed
                if time.time() - state['last_failure_time'] > recovery_timeout:
                    logger.info(f"Circuit breaker for {func_context}: Attempting recovery")
                    state['is_open'] = False
                    state['failures'] = 0
                else:
                    raise RuntimeError(
                        f"Circuit breaker open for {func_context}. "
                        f"Too many failures ({state['failures']}). "
                        f"Retry after {recovery_timeout}s."
                    )
            
            try:
                result = func(*args, **kwargs)
                # Success - reset failure count
                if state['failures'] > 0:
                    logger.info(f"Circuit breaker for {func_context}: Recovered after failures")
                    state['failures'] = 0
                return result
                
            except expected_exception:
                state['failures'] += 1
                state['last_failure_time'] = time.time()
                
                if state['failures'] >= failure_threshold:
                    state['is_open'] = True
                    logger.error(
                        f"Circuit breaker OPENED for {func_context} "
                        f"after {failure_threshold} failures"
                    )
                
                raise
        
        # Return appropriate wrapper based on function type
        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        else:
            return sync_wrapper
    
    return decorator


def with_timeout(
    timeout_seconds: float,
    default_return: Any = None,
    context: str = None
):
    """
    Decorator to enforce timeout on async operations.
    
    Args:
        timeout_seconds: Maximum execution time in seconds
        default_return: Value to return on timeout (None by default)
        context: Context string for error messages
        
    Example:
        @with_timeout(timeout_seconds=30.0, context="llm_generation")
        async def generate_code(self, prompt):
            # code here
            pass
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        async def async_wrapper(*args, **kwargs):
            func_context = context or f"{func.__module__}.{func.__name__}"
            
            try:
                return await asyncio.wait_for(
                    func(*args, **kwargs),
                    timeout=timeout_seconds
                )
            except asyncio.TimeoutError:
                logger.error(
                    f"Timeout after {timeout_seconds}s in {func_context}"
                )
                if default_return is not None:
                    return default_return
                raise
        
        # Note: Timeout only makes sense for async functions
        if not asyncio.iscoroutinefunction(func):
            logger.warning(
                f"with_timeout decorator used on non-async function {func.__name__}. "
                "This will have no effect."
            )
            return func
        
        return async_wrapper
    
    return decorator


def with_validation(
    validate_args: Optional[Callable] = None,
    validate_result: Optional[Callable] = None,
    context: str = None
):
    """
    Decorator to validate function arguments and/or results.
    
    Args:
        validate_args: Function to validate arguments (should raise ValueError if invalid)
        validate_result: Function to validate result (should raise ValueError if invalid)
        context: Context string for error messages
        
    Example:
        def validate_blueprint_args(blueprint_id, **kwargs):
            if not blueprint_id:
                raise ValueError("blueprint_id is required")
        
        @with_validation(validate_args=validate_blueprint_args)
        async def process_blueprint(self, blueprint_id, data):
            # code here
            pass
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        async def async_wrapper(*args, **kwargs):
            func_context = context or f"{func.__module__}.{func.__name__}"
            
            # Validate arguments
            if validate_args:
                try:
                    validate_args(*args, **kwargs)
                except ValueError as e:
                    logger.error(f"Argument validation failed for {func_context}: {e}")
                    raise
            
            # Execute function
            result = await func(*args, **kwargs)
            
            # Validate result
            if validate_result:
                try:
                    validate_result(result)
                except ValueError as e:
                    logger.error(f"Result validation failed for {func_context}: {e}")
                    raise
            
            return result
        
        @functools.wraps(func)
        def sync_wrapper(*args, **kwargs):
            func_context = context or f"{func.__module__}.{func.__name__}"
            
            # Validate arguments
            if validate_args:
                try:
                    validate_args(*args, **kwargs)
                except ValueError as e:
                    logger.error(f"Argument validation failed for {func_context}: {e}")
                    raise
            
            # Execute function
            result = func(*args, **kwargs)
            
            # Validate result
            if validate_result:
                try:
                    validate_result(result)
                except ValueError as e:
                    logger.error(f"Result validation failed for {func_context}: {e}")
                    raise
            
            return result
        
        # Return appropriate wrapper based on function type
        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        else:
            return sync_wrapper
    
    return decorator
