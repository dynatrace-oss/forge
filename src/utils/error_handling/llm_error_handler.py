import logging

import openai
import yaml

from shared.constants import PROJECT_ROOT

logger = logging.getLogger(__name__)


class LLMErrorHandler:
    """Handles Azure OpenAI API errors with proper status code logging."""

    def __init__(self):
        self.config = self._load_config()

    def _load_config(self) -> dict:
        """Load error handling config from service_config.yaml."""
        config_path = PROJECT_ROOT / "src" / "config" / "service_config.yaml"
        try:
            with open(config_path, "r") as f:
                service_config = yaml.safe_load(f)
                return service_config.get("llm_service", {}).get("error_handling", {})
        except Exception as e:
            logger.warning(f"Failed to load error config: {e}")
            return {}

    def get_status_code(self, exc: Exception) -> int:
        """Extract HTTP status code from exception."""
        if hasattr(exc, "status_code"):
            return exc.status_code

        # Map known exception types
        if isinstance(exc, openai.RateLimitError):
            return 429
        elif isinstance(exc, openai.AuthenticationError):
            return 401
        elif isinstance(exc, openai.PermissionDeniedError):
            return 403
        elif isinstance(exc, openai.NotFoundError):
            return 404
        elif isinstance(exc, openai.BadRequestError):
            return 400
        elif isinstance(exc, openai.UnprocessableEntityError):
            return 422
        elif isinstance(exc, openai.InternalServerError):
            return 500
        elif isinstance(exc, openai.APIConnectionError):
            return 0  # No HTTP response
        elif isinstance(exc, openai.APITimeoutError):
            return 408
        return -1

    def get_error_message(self, exc: Exception) -> str:
        """Extract the actual error message from Azure OpenAI response."""
        # Try to get structured error info from OpenAI exceptions
        if hasattr(exc, "body") and exc.body:
            body = exc.body
            if isinstance(body, dict):
                # Azure OpenAI error format
                if "error" in body:
                    error_obj = body["error"]
                    code = error_obj.get("code", "")
                    message = error_obj.get("message", "")
                    inner_error = error_obj.get("innererror", {})
                    inner_code = inner_error.get("code", "") if inner_error else ""

                    parts = []
                    if code:
                        parts.append(f"Code: {code}")
                    if inner_code:
                        parts.append(f"InnerCode: {inner_code}")
                    if message:
                        parts.append(f"Message: {message}")

                    if parts:
                        return " | ".join(parts)

                # Direct message in body
                if "message" in body:
                    return body["message"]

        # Try message attribute
        if hasattr(exc, "message") and exc.message:
            return exc.message

        # Fallback to string representation
        return str(exc)

    def is_content_filter_error(self, exc: Exception) -> bool:
        """Check if error is a content filter/safety violation."""
        error_msg = self.get_error_message(exc).lower()
        return any(pattern in error_msg for pattern in [
            "content filter", "content_filter",
            "content policy", "content_policy",
            "responsible ai", "responsible_ai",
            "filtered"
        ])

    @staticmethod
    def extract_finish_reason(response) -> str:
        """Extract finish_reason from a llama_index CompletionResponse.

        Azure content filters return HTTP 200 with finish_reason='content_filter'
        and an empty text body. This inspects the raw response to detect that case.
        """
        if response is None:
            return "no_response"
        # Check raw OpenAI response object
        raw = getattr(response, "raw", None)
        if raw:
            choices = None
            if isinstance(raw, dict):
                choices = raw.get("choices", [])
            elif hasattr(raw, "choices"):
                choices = raw.choices
            if choices:
                first = choices[0] if isinstance(choices, list) else choices
                if isinstance(first, dict):
                    return first.get("finish_reason", "unknown")
                elif hasattr(first, "finish_reason"):
                    return first.finish_reason or "unknown"
        # Check additional_kwargs fallback
        additional = getattr(response, "additional_kwargs", {})
        if isinstance(additional, dict):
            return additional.get("finish_reason", "unknown")
        return "unknown"

    def is_retryable(self, exc: Exception) -> bool:
        """Check if error is retryable based on config."""
        if self.is_content_filter_error(exc):
            return False

        status_code = self.get_status_code(exc)
        http_codes = self.config.get("http_status_codes", {})

        # Try both int and string keys
        code_info = http_codes.get(status_code) or http_codes.get(str(status_code))
        if code_info:
            return code_info.get("retryable", False)

        # Default: 429 and 5xx are retryable
        return status_code == 429 or status_code >= 500 or status_code == 0

    def get_backoff_delay(self, attempt: int, exc: Exception) -> float:
        """Calculate backoff delay based on error type."""
        retry_config = self.config.get("retry_config", {})

        # Determine error type for config lookup
        if isinstance(exc, openai.RateLimitError):
            cfg = retry_config.get("rate_limit", {})
        elif isinstance(exc, (openai.APIConnectionError, openai.APITimeoutError)):
            cfg = retry_config.get("connection_error", {})
        elif isinstance(exc, openai.InternalServerError):
            cfg = retry_config.get("server_error", {})
        else:
            cfg = retry_config.get("server_error", {})

        base = cfg.get("base_delay_seconds", 2)
        max_delay = cfg.get("max_delay_seconds", 60)
        backoff_type = cfg.get("backoff_type", "exponential")

        if backoff_type == "exponential":
            delay = base * (2 ** (attempt - 1))
        else:
            delay = base * attempt

        return min(delay, max_delay)

    def log_error(self, exc: Exception, context: str = "") -> None:
        """Log error with status code, description, and Azure OpenAI message."""
        status_code = self.get_status_code(exc)
        error_message = self.get_error_message(exc)
        is_retryable = self.is_retryable(exc)

        # Get status code info from config
        http_codes = self.config.get("http_status_codes", {})
        code_info = http_codes.get(status_code) or http_codes.get(str(status_code), {})
        code_name = code_info.get("name", "Unknown")
        code_desc = code_info.get("description", "")

        # Handle special cases
        if status_code == 0:
            code_name = "Connection Error"
            code_desc = "Failed to connect to Azure OpenAI API"

        # Check for content filter
        if self.is_content_filter_error(exc):
            content_codes = self.config.get("content_safety_codes", {}).get("content_filter", {})
            logger.error(
                f"Azure OpenAI Content Filter Error | "
                f"Type: {content_codes.get('name', 'Content Filter')} | "
                f"Recommendation: {content_codes.get('recommendation', 'Modify prompt')} | "
                f"Azure Message: {error_message}"
                + (f" | Context: {context}" if context else "")
            )
            return

        # Standard error logging
        log_msg = (
            f"Azure OpenAI API Error | "
            f"Status: {status_code} ({code_name}) | "
            f"Description: {code_desc} | "
            f"Retryable: {is_retryable} | "
            f"Azure Message: {error_message}"
        )
        if context:
            log_msg += f" | Context: {context}"

        if is_retryable:
            logger.warning(log_msg)
        else:
            logger.error(log_msg)


# Singleton instance
llm_error_handler = LLMErrorHandler()
