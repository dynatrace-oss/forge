import asyncio
import logging
from datetime import datetime
from pathlib import Path
import json

from shared.constants import DEFAULT_DATA_DIR
from utils.error_handling.decorators import with_error_recovery

logger = logging.getLogger(__name__)


class ContainerLogService:
    """
    Centralized service for all container log operations.
    """
    
    def __init__(self, data_dir: str = DEFAULT_DATA_DIR, container_runtime: str = "podman"):
        """
        Initialize the container log service.
        
        Args:
            data_dir: Base directory for persistent storage
            container_runtime: Container runtime to use (podman/docker)
        """
        self.data_dir = Path(data_dir)
        self.container_runtime = container_runtime
        self.logs_dir = self.data_dir / "monitoring" / "container_logs"
        self.logs_dir.mkdir(parents=True, exist_ok=True)
        self.logger = logger
    
    @with_error_recovery(default_return="", log_level="warning", context="get_logs")
    async def get_logs(
        self,
        container_id: str,
        tail: int | None = None,
        since: int | None = None,
        timestamps: bool = False
    ) -> str:
        """
        Retrieve container logs (unified method).

        Args:
            container_id: Container name or ID
            tail: Number of recent lines to retrieve
            since: Only return logs since N seconds ago
            timestamps: Include timestamps in output

        Returns:
            Container logs as string
        """
        cmd = [self.container_runtime, "logs"]

        if tail is not None:
            cmd.extend(["--tail", str(tail)])

        if since is not None:
            cmd.extend(["--since", f"{since}s"])

        if timestamps:
            cmd.append("--timestamps")

        cmd.append(container_id)

        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        stdout, stderr = await process.communicate()

        if process.returncode == 0:
            # Combine stdout and stderr — many runtimes (e.g. Tomcat) write logs to stderr
            stdout_text = stdout.decode('utf-8', errors='replace')
            stderr_text = stderr.decode('utf-8', errors='replace')
            logs = (stdout_text + stderr_text).strip()
            self.logger.debug(f"Retrieved {len(logs)} chars of logs from {container_id}")
            return logs
        else:
            error_msg = stderr.decode('utf-8', errors='replace')
            self.logger.warning(f"Failed to get logs for {container_id}: {error_msg}")
            return ""
    
    async def save_logs_persistent(
        self,
        blueprint_id: str,
        container_id: str,
        container_name: str,
        logs: str | None = None,
        metadata: dict[str, any] | None = None
    ) -> Path:
        """
        Save container logs to persistent storage with rotation.
        
        Args:
            blueprint_id: Blueprint ID for organization
            container_id: Container ID
            container_name: Human-readable container name
            logs: Log content (if None, will fetch from container)
            metadata: Additional metadata to save
            
        Returns:
            Path to saved log file
        """
        try:
            # Fetch logs if not provided
            if logs is None:
                logs = await self.get_logs(container_id)
            
            # Create filename with timestamp
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"{blueprint_id}_{container_name}_{timestamp}.log"
            log_file = self.logs_dir / filename
            
            # Prepare log content with metadata header
            header_lines = [
                "# Container Log Export",
                f"# Blueprint ID: {blueprint_id}",
                f"# Container ID: {container_id}",
                f"# Container Name: {container_name}",
                f"# Timestamp: {timestamp}",
                f"# Log Length: {len(logs)} characters",
            ]
            
            if metadata:
                header_lines.append(f"# Metadata: {json.dumps(metadata)}")
            
            header_lines.append("#" + "=" * 80)
            header_lines.append("")
            
            header = "\n".join(header_lines)
            
            # Write to file
            log_file.write_text(header + logs, encoding='utf-8')
            
            self.logger.info(
                f"Saved container logs to {log_file} "
                f"({len(logs)} chars, {logs.count(chr(10))} lines)"
            )
            
            # Perform log rotation if needed
            self._rotate_logs_if_needed()
            
            return log_file
        
        except Exception as e:
            self.logger.error(
                f"Failed to save logs for {container_id} to persistent storage: {e}"
            )
            raise
    
    @with_error_recovery(default_return=None, log_level="warning", context="_rotate_logs_if_needed")
    def _rotate_logs_if_needed(self, max_files: int = 100, max_age_days: int = 7):
        """
        Rotate old log files to prevent disk bloat.

        Args:
            max_files: Maximum number of log files to keep
            max_age_days: Maximum age of log files in days
        """
        log_files = sorted(
            self.logs_dir.glob("*.log"),
            key=lambda p: p.stat().st_mtime,
            reverse=True
        )

        # Delete old files beyond max_files limit
        if len(log_files) > max_files:
            for old_file in log_files[max_files:]:
                try:
                    old_file.unlink()
                    self.logger.debug(f"Deleted old log file: {old_file.name}")
                except Exception as e:
                    self.logger.warning(f"Failed to delete {old_file}: {e}")

        # Delete files older than max_age_days
        import time
        max_age_seconds = max_age_days * 24 * 60 * 60
        current_time = time.time()

        for log_file in log_files:
            file_age = current_time - log_file.stat().st_mtime
            if file_age > max_age_seconds:
                try:
                    log_file.unlink()
                    self.logger.debug(f"Deleted expired log file: {log_file.name}")
                except Exception as e:
                    self.logger.warning(f"Failed to delete {log_file}: {e}")
    
    @with_error_recovery(default_return=[], log_level="warning", context="get_stored_logs")
    def get_stored_logs(self, blueprint_id: str | None = None) -> list[dict[str, any]]:
        """
        Retrieve stored container logs from persistent storage.

        Args:
            blueprint_id: Optional blueprint ID to filter by

        Returns:
            List of dictionaries with log metadata and content
        """
        logs = []

        pattern = f"{blueprint_id}_*.log" if blueprint_id else "*.log"

        for log_file in self.logs_dir.glob(pattern):
            try:
                content = log_file.read_text(encoding='utf-8')

                # Parse metadata from header
                metadata = self._parse_log_metadata(content)

                logs.append({
                    "filename": log_file.name,
                    "filepath": str(log_file),
                    "size": log_file.stat().st_size,
                    "modified": datetime.fromtimestamp(log_file.stat().st_mtime).isoformat(),
                    "metadata": metadata,
                    "content": content
                })

            except Exception as e:
                self.logger.warning(f"Failed to read log file {log_file}: {e}")

        return logs
    
    def _parse_log_metadata(self, content: str) -> dict[str, str]:
        """
        Parse metadata from log file header.
        
        Args:
            content: Log file content
            
        Returns:
            Dictionary of metadata fields
        """
        metadata = {}
        
        for line in content.split('\n'):
            if not line.startswith('#'):
                break
            
            if ':' in line:
                key_part = line[1:].split(':', 1)[0].strip()
                value_part = line[1:].split(':', 1)[1].strip() if len(line[1:].split(':', 1)) > 1 else ''
                metadata[key_part] = value_part
        
        return metadata
    
    async def get_logs_safely(self, container_id: str, default: str = "") -> str:
        """
        Get logs with exception handling (safe wrapper).
        
        Args:
            container_id: Container name or ID
            default: Default value to return on error
            
        Returns:
            Container logs or default value
        """
        try:
            return await self.get_logs(container_id)
        except Exception as e:
            self.logger.warning(f"Failed to get logs safely for {container_id}: {e}")
            return default
