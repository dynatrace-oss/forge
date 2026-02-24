import asyncio
import json
import logging
import os
import re
import subprocess
import time
from datetime import datetime
from pathlib import Path

import aiofiles

from services.monitoring.container_log_service import ContainerLogService
from services.system.reliability_service import reliability_manager
from shared.constants import DEFAULT_CONTAINER_DIR
from utils.error_handling.decorators import with_error_recovery, with_retry, with_timeout
from utils.core.common import (
    cleanup_build_resources,
    ensure_dir_exists,
    generate_safe_id,
    parse_port_mapping,
    validate_container_name,
)
from utils.container.container_utils import (
    check_container_health,
    check_container_status,
    check_disk_space,
    cleanup_failed_build,
    get_image_size,
)
from utils.container.diagnostics import run_pre_build_diagnostics
from utils.maintenance.log_processor import LogProcessor

logger = logging.getLogger(__name__)


class ContainerService:
    """
    Service for container operations like building, running, and managing containers.
    Acts as a capability-providing service without decision-making capabilities.
    """

    def __init__(self, containers_dir: Path | str | None = None):
        """
        Initialize the container service.

        Args:
            containers_dir: Directory to store container files
        """
        self.containers_dir = DEFAULT_CONTAINER_DIR
        ensure_dir_exists(self.containers_dir)
        self.reliability_manager = reliability_manager
        self.container_log_service = ContainerLogService()
        self.active_containers: dict[str, dict[str, any]] = {}
        
        # Initialize log processor for build output filtering
        try:
            self.log_processor = LogProcessor()
            logger.info("Log processor initialized for container build filtering")
        except Exception as e:
            logger.warning(f"Failed to initialize log processor: {e}, using fallback")
            self.log_processor = None

        # Register cleanup on shutdown
        self.reliability_manager.schedule_cleanup(self.cleanup_all_containers)

    @with_error_recovery(context="create_container_dir")
    def create_container_dir(self, name_prefix: str) -> dict[str, str]:
        """
        Create a directory for container files.

        Args:
            name_prefix: Prefix for the container directory name

        Returns:
            dictionary with directory information
        """
        # Generate a unique ID
        container_id = generate_safe_id()[:8]

        # Create a sanitized prefix
        safe_prefix = name_prefix.replace(":", "-").replace(".", "-").lower()

        # Generate the container name
        container_name = f"vulnapp-{safe_prefix}-{container_id}"

        # Create the directory
        container_dir = os.path.join(self.containers_dir, container_name)
        os.makedirs(container_dir, exist_ok=True)

        return {
            "container_name": container_name,
            "container_dir": container_dir,
            "container_id": container_id,
        }


    @with_error_recovery(context="write_container_files")
    async def write_container_files(self, container_dir: str, files: dict[str, str]) -> list[str]:
        """
        Write files to a container directory with content cleaning.

        Args:
            container_dir: Path to the container directory
            files: dictionary mapping file paths to content

        Returns:
            list of written file paths
        """
        written_files = []

        # Spring Boot Maven Plugin requires this directory for repackaging to work
        resources_dir = os.path.join(container_dir, "src", "main", "resources")
        os.makedirs(resources_dir, exist_ok=True)

        # Create a .gitkeep file to ensure directory is tracked and exists
        gitkeep_path = os.path.join(resources_dir, ".gitkeep")
        if not os.path.exists(gitkeep_path):
            async with aiofiles.open(gitkeep_path, "w", encoding="utf-8") as f:
                await f.write("# This file ensures src/main/resources/ exists for Spring Boot Maven Plugin\n")
            logger.debug(f"Created resources directory with .gitkeep: {resources_dir}")

        for file_path, content in files.items():
            # Common cleaning: remove markdown code blocks
            content = re.sub(r"^```\w*\n", "", content)
            content = re.sub(r"\n```$", "", content)
            # Handle cases with no newlines around code blocks
            content = re.sub(r"^```\w*", "", content)
            content = re.sub(r"```$", "", content)

            # Type-specific cleaning based on file extension
            if file_path.endswith((".yaml", ".yml")):
                # For YAML files, stop at any explanations
                # Split at common markers that indicate the start of explanations
                for marker in [
                    "Explanation:",
                    "\n\nExplanation",
                    "Notes:",
                    "Example:",
                    "---",
                ]:
                    if marker in content:
                        content = content.split(marker)[0].strip()

                # Keep only lines that look like YAML content or YAML comments
                yaml_lines = []
                for line in content.split("\n"):
                    line = line.strip()
                    # Keep YAML comments and content, exclude explanations
                    if (
                        line.startswith("#")
                        or ":" in line
                        or line.startswith("!")
                        or line.startswith("-")
                        or not line
                    ):  # Include empty lines too
                        yaml_lines.append(line)
                content = "\n".join(yaml_lines)

            # Create full path and ensure parent directory exists
            full_path = os.path.join(container_dir, file_path)
            logger.info(f"Creating following directory path: {full_path}")
            os.makedirs(os.path.dirname(full_path), exist_ok=True)

            async with aiofiles.open(full_path, "w", encoding="utf-8") as f:
                await f.write(content)

            written_files.append(full_path)
            logger.debug(f"Wrote file: {full_path}")

        return written_files


    @with_timeout(timeout_seconds=10)
    @with_retry(max_attempts=2, delay=1)
    async def check_podman_available(self) -> dict:
        """
        Check if Podman is available and get version info.

        Returns:
            dictionary with availability information
        """
        # Try the podman version command
        process = await asyncio.create_subprocess_exec(
            "podman",
            "--version",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        stdout, stderr = await process.communicate()

        if process.returncode == 0:
            return {
                "available": True,
                "version": stdout.decode().strip(),
                "error": None,
            }
        else:
            return {
                "available": False,
                "version": None,
                "error": stderr.decode().strip(),
            }


    @with_error_recovery(context="validate_container_dir")
    def validate_container_dir(self, container_dir: str) -> dict:
        """
        Validate container directory structure.

        Args:
            container_dir: Path to the container directory

        Returns:
            dictionary with validation result
        """
        # Check if the directory exists
        if not os.path.exists(container_dir):
            return {
                "valid": False,
                "error": f"Container directory {container_dir} does not exist",
            }

        # Check for Containerfile or Dockerfile
        containerfile_path = os.path.join(container_dir, "Containerfile")
        dockerfile_path = os.path.join(container_dir, "Dockerfile")

        if not os.path.exists(containerfile_path) and not os.path.exists(dockerfile_path):
            return {
                "valid": False,
                "error": f"No Containerfile or Dockerfile found in {container_dir}",
            }

        # For Java containers, check for pom.xml
        pom_path = os.path.join(container_dir, "pom.xml")
        if os.path.exists(pom_path):
            # Check for Java source files
            java_files = list(Path(container_dir).glob("**/*.java"))
            if not java_files:
                return {
                    "valid": False,
                    "error": f"No Java source files found in {container_dir}",
                }

        return {
            "valid": True,
            "containerfile": containerfile_path if os.path.exists(containerfile_path) else dockerfile_path,
        }


    @with_timeout(timeout_seconds=900)  # 15 minutes for build
    @with_error_recovery(context="build_container")
    async def build_container(self, container_dir: str, container_name: str | None = None) -> dict:
        """
        Build a container with enhanced resource management.

        Args:
            container_dir: Path to the container directory
            container_name: Optional name for the container

        Returns:
            Dictionary with build result
        """
        # Use atomic operation for build process
        async with self.reliability_manager.atomic_operation(f"build_container_{container_name}"):
            # Existing validation logic...
            validation = self.validate_container_dir(container_dir)
            if not validation["valid"]:
                return {
                    "status": "error",
                    "container_dir": container_dir,
                    "error": validation["error"],
                }

            if not container_name:
                container_name = os.path.basename(container_dir)

            container_name = validate_container_name(container_name)

            # Check resources before starting build
            available_space = check_disk_space(container_dir)
            if available_space < 1024 * 1024 * 100:  # 100MB minimum
                return {
                    "status": "error",
                    "container_dir": container_dir,
                    "error": "Insufficient disk space for container build",
                }

            # Get the Containerfile path
            containerfile_path = validation["containerfile"]

            # Check if Podman is available
            podman_check = await self.check_podman_available()
            if not podman_check["available"]:
                return {
                    "status": "error",
                    "container_dir": container_dir,
                    "error": f"Podman not available: {podman_check['error']}",
                }

            # Pre-build diagnostics
            run_pre_build_diagnostics(container_dir, container_name)
            
            # Build the container with timeout
            logger.info(f"Building container {container_name} from {container_dir}")

            try:
                build_process = await asyncio.wait_for(
                    asyncio.create_subprocess_exec(
                        "podman",
                        "build",
                        "-t",
                        container_name,
                        "-f",
                        os.path.basename(containerfile_path),
                        ".",
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                        cwd=container_dir,
                    ),
                    timeout=300.0,  # 5 minute timeout
                )

                stdout, stderr = await build_process.communicate()

            except asyncio.TimeoutError:
                return {
                    "status": "error",
                    "container_name": container_name,
                    "container_dir": container_dir,
                    "error": "Build process timed out after 5 minutes",
                }

            if build_process.returncode != 0:
                # Build failed - analyze error with enhanced logging
                raw_stderr = stderr.decode()
                raw_stdout = stdout.decode()
                
                logger.warning(f"CONTAINER BUILD FAILED for {container_name}")
                logger.warning(f"Exit Code: {build_process.returncode}")
                logger.warning(f"Container Dir: {container_dir}")
                logger.warning(f"STDOUT Length: {len(raw_stdout)} characters")
                logger.warning(f"STDERR Length: {len(raw_stderr)} characters")

                # Filter out noisy Maven download messages before logging
                if raw_stdout:
                    filtered_lines = []
                    for line in raw_stdout.split('\n'):
                        # Skip Maven download/downloading messages (case-insensitive)
                        line_lower = line.lower()
                        if '[info] download' in line_lower or '[info] downloaded' in line_lower:
                            continue
                        filtered_lines.append(line)
                    filtered_stdout_str = '\n'.join(filtered_lines)
                    stdout_preview = filtered_stdout_str if len(filtered_stdout_str) <= 50000 else filtered_stdout_str[:50000] + "...[TRUNCATED]"
                    logger.warning(f"COMPLETE BUILD STDOUT:\n{stdout_preview}")

                if raw_stderr:
                    stderr_preview = raw_stderr if len(raw_stderr) <= 50000 else raw_stderr[:50000] + "...[TRUNCATED]"
                    logger.warning(f"COMPLETE BUILD STDERR:\n{stderr_preview}")
                
                # Use log processor to filter and extract relevant error information
                if self.log_processor:
                    try:
                        error_summary = self.log_processor.extract_error_summary(raw_stderr, 'container')
                        error_detail = self.log_processor.analyze_error_summary(error_summary)

                        # Filter stdout for cleaner output
                        stdout_filter_result = self.log_processor.filter_build_output(raw_stdout, 'container')
                        filtered_stdout = stdout_filter_result.filtered_output
                    except Exception as e:
                        logger.warning(f"Log filtering failed, using raw output: {e}")
                        error_detail = self.log_processor.analyze_build_error(raw_stderr)
                        filtered_stdout = raw_stdout
                else:
                    error_detail = self.log_processor.analyze_build_error(raw_stderr)
                    filtered_stdout = raw_stdout

                # Cleanup any partial build artifacts
                await cleanup_failed_build(container_name)

                return {
                    "status": "error",
                    "container_name": container_name,
                    "container_dir": container_dir,
                    "error": error_detail,
                    "output": filtered_stdout,
                    "error_output": raw_stderr if not self.log_processor else error_summary.get('filtered_log', raw_stderr),
                }

            # Verify the image exists
            image_check = await asyncio.create_subprocess_exec(
                "podman",
                "image",
                "exists",
                container_name,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            await image_check.communicate()

            if image_check.returncode != 0:
                return {
                    "status": "error",
                    "container_name": container_name,
                    "container_dir": container_dir,
                    "error": "Container build appeared to succeed but the image was not found",
                    "output": stdout.decode(),
                    "error_output": stderr.decode(),
                }

            # Track successful build
            self.active_containers[container_name] = {
                "status": "built",
                "container_dir": container_dir,
                "build_time": time.time(),
                "image_size": await get_image_size(container_name),
            }

            # Get image details
            image_details_process = await asyncio.create_subprocess_exec(
                "podman",
                "image",
                "inspect",
                container_name,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            image_stdout, _ = await image_details_process.communicate()

            # Filter successful build output for cleaner logging
            raw_stdout = stdout.decode()
            if self.log_processor:
                try:
                    stdout_filter_result = self.log_processor.filter_build_output(raw_stdout, 'container')
                    filtered_stdout = stdout_filter_result.filtered_output
                    logger.info(f"Build output filtered: {stdout_filter_result.statistics}")
                except Exception as e:
                    logger.warning(f"Log filtering failed for successful build: {e}")
                    filtered_stdout = raw_stdout
            else:
                filtered_stdout = raw_stdout

        return {
                "status": "success",
                "container_name": container_name,
                "container_dir": container_dir,
                "output": filtered_stdout,
                "image_details": image_stdout.decode() if image_details_process.returncode == 0 else None,
                "command": f"podman run --rm -it {container_name}",
                "timestamp": datetime.now().isoformat(),
            }

    @with_timeout(timeout_seconds=120)  # 2 minutes for container startup
    @with_error_recovery(context="run_container")
    async def run_container(self, container_name: str, ports: list[str] | None = None, labels: dict[str, str] | None = None, memory_limit: str | None = None) -> dict:
        """
        Run a container.

        Args:
            container_name: Name of the container
            ports: Optional list of port mappings (e.g., ["8080:8080"])
            labels: Optional dictionary of labels to apply to the container
            memory_limit: Optional memory limit (e.g., "512m", "1g") for DoS vulnerability testing

        Returns:
            Dictionary with run result
        """
        # Check if Podman is available
        podman_check = await self.check_podman_available()
        if not podman_check["available"]:
            return {
                "status": "error",
                "container_name": container_name,
                "error": f"Podman not available: {podman_check['error']}",
            }

        # Build the command
        command = ["podman", "run", "--rm", "-d"]
        
        # Add memory limit if specified (for DoS vulnerability testing)
        try:
            if memory_limit:
                command.extend(["-m", memory_limit])
                logger.info(f"Setting memory limit for container {container_name}: {memory_limit}")
            else:
                # Default memory limit for vulnerability testing (aligned with JVM settings)
                default_memory_limit = "1g"
                command.extend(["-m", default_memory_limit])
                logger.info(f"Using default memory limit for container {container_name}: {default_memory_limit}")
        except Exception as e:
            logger.warning(f"Failed to set container memory limit for {container_name}: {e}, continuing without memory limit")

        # Add port mappings if specified
        if ports:
            for port_mapping in ports:
                try:
                    # Use parse_port_mapping to validate and normalize port mappings
                    host_port, container_port = parse_port_mapping(port_mapping)
                    command.extend(["-p", f"{host_port}:{container_port}"])
                except ValueError as e:
                    logger.warning(f"Invalid port mapping {port_mapping}: {e}")
                    # Continue with other ports instead of failing entirely
                    continue

        # Add labels if specified
        if labels:
            for key, value in labels.items():
                command.extend(["--label", f"{key}={value}"])

        # Add container name
        command.append(container_name)

        # Run the container
        logger.info(f"Running container {container_name} with command: {' '.join(command)}")

        run_process = await asyncio.create_subprocess_exec(
            *command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )

        stdout, stderr = await run_process.communicate()

        if run_process.returncode != 0:
            # Run failed
            return {
                "status": "error",
                "container_name": container_name,
                "error": stderr.decode().strip(),
                "output": stdout.decode().strip(),
                "error_output": stderr.decode().strip(),
            }
        if run_process.returncode == 0:
            container_id = stdout.decode().strip()

            # Wait a moment for container to fully start
            await asyncio.sleep(2)

            # Verify container is still running (catch immediate exits)
            is_running_check1 = await self.is_container_running(container_id)
            if not is_running_check1:
                # Container exited immediately, get logs to understand why
                logs = await self.get_container_logs(container_id, tail=50)
                logger.error(f"Container {container_name} ({container_id}) exited immediately after start")
                logger.error(f"Container logs: {logs}")
                return {
                    "status": "error",
                    "container_name": container_name,
                    "container_id": container_id,
                    "error": "Container exited immediately after start",
                    "container_logs": logs,
                    "exit_reason": "Premature container exit - check logs for startup errors"
                }

            # Wait additional time and check again to catch early exits
            await asyncio.sleep(3)
            is_running_check2 = await self.is_container_running(container_id)
            if not is_running_check2:
                # Container exited within 5 seconds, get logs
                logs = await self.get_container_logs(container_id, tail=50)
                logger.error(f"Container {container_name} ({container_id}) exited within 5 seconds of start")
                logger.error(f"Container logs: {logs}")
                return {
                    "status": "error",
                    "container_name": container_name,
                    "container_id": container_id,
                    "error": "Container exited within 5 seconds of start",
                    "container_logs": logs,
                    "exit_reason": "Early container exit - application may have startup errors"
                }

            # Get detailed container information immediately after starting
            container_info = await self.get_container_info(container_id)
                
            if container_info.get("found", False):
                # Extract port mappings from container info
                exposed_ports = container_info.get("exposed_ports", {})
                    
                # Update active containers tracking with comprehensive info
                self.active_containers[container_name] = {
                    "status": "running",
                    "container_id": container_id,
                    "container_name": container_name,
                    "start_time": time.time(),
                    "ports": ports or [],
                    "exposed_ports": exposed_ports,
                    "network_settings": container_info.get("network_settings", {}),
                    "running": container_info.get("running", False),
                    "container_status": container_info.get("status", "unknown"),
                    "blueprint_id": labels.get("blueprint_id", "") if labels else "",
                    "labels": labels or {}
                }

                # Schedule periodic health check
                asyncio.create_task(self._monitor_container_health(container_name, container_id))

                # Extract host port for validation targeting
                host_port = None
                if exposed_ports:
                    # Get the first available port mapping
                    for container_port, host_bindings in exposed_ports.items():
                        if host_bindings:
                            host_port = host_bindings[0].get("HostPort")
                            break
                    
                # If no port found from inspect, try to extract from ports parameter
                if not host_port and ports:
                    try:
                        host_port = ports[0].split(':')[0]
                    except (IndexError, AttributeError):
                        host_port = "8080"  # Default fallback

                # Return comprehensive success result with all needed info for validation
                return {
                    "status": "success",
                    "container_name": container_name,
                    "container_id": container_id,
                    "output": stdout.decode().strip(),
                    "container_details": json.dumps(container_info["raw_info"], indent=2) if container_info.get("raw_info") else "",
                    "command": f"podman logs -f {container_id}",
                    "stop_command": f"podman stop {container_id}",
                    "timestamp": datetime.now().isoformat(),
                    # Additional fields for validation targeting
                    "host": "localhost",
                    "port": host_port or "8080",
                    "exposed_ports": exposed_ports,
                    "network_settings": container_info.get("network_settings", {}),
                    "running": container_info.get("running", False),
                    "container_status": container_info.get("status", "unknown")
                }
            else:
                logger.warning(f"Container {container_id} started but could not retrieve detailed info")
                # Fallback result with basic info
                return {
                    "status": "warning",
                    "container_name": container_name,
                    "container_id": container_id,
                    "error": "Container started but detailed info retrieval failed",
                    "output": stdout.decode().strip(),
                    "host": "localhost",
                    "port": "8080",  # Default fallback
                    "timestamp": datetime.now().isoformat(),
                }
            
        # This code should not be reached since we handle success above
        container_id = stdout.decode().strip()

        # Return basic success result as final fallback
        return {
        "status": "success",
        "container_name": container_name,
        "container_id": container_id,
        "output": stdout.decode().strip(),
        "timestamp": datetime.now().isoformat(),
        "host": "localhost",
        "port": "8080"
        }

    @with_error_recovery(context="monitor_container", default_return=None)
    async def monitor_container(self, container_info: dict, health_check_interval: int = 30) -> None:
        """
        Monitor a running container with health checks.

        Args:
        container_info: Container information dictionary
        health_check_interval: Interval between health checks in seconds
        """
        container_name = container_info["name"]
        container_id = container_info["id"]
        port = container_info.get("port")
        container_type = container_info.get("type", "standalone")

        logger.info(f"Starting monitoring for {container_name} (type: {container_type})")

        health_check_failures = 0
        max_failures = 3

        while container_name in self.active_containers:
            try:
                await asyncio.sleep(health_check_interval)

                # Check if container is still running
                logs_result = await self.get_container_logs(container_id)

                if logs_result["status"] != "success":
                    logger.warning(f"Container {container_name} may have stopped")
                    break

                # Perform health check if port is available
                if port:
                    health_ok = await check_container_health(port)

                    if health_ok:
                        health_check_failures = 0
                        logger.debug(f"Health check passed for {container_name}")
                    else:
                        health_check_failures += 1
                        logger.warning(
                            f"Health check failed for {container_name} ({health_check_failures}/{max_failures})"
                        )

                        if health_check_failures >= max_failures:
                            logger.error(f"Container {container_name} failed health checks, may need restart")
                            break

            except asyncio.CancelledError:
                logger.info(f"Monitoring cancelled for {container_name}")
                break
            except Exception as e:
                logger.error(f"Error monitoring {container_name}: {e}")
                break

    def start_container_monitoring(self, container_info: dict) -> asyncio.Task:
        """
        Start monitoring task for a container.

        Args:
            container_info: Container information dictionary

        Returns:
            Monitoring task
        """
        task = asyncio.create_task(self.monitor_container(container_info))
        return task

    async def _monitor_container_health(self, container_name: str, container_id: str):
        """Monitor container health and restart if needed."""
        while container_name in self.active_containers:
            try:
                await asyncio.sleep(30)  # Check every 30 seconds

                # Check if container is still running
                check_process = await asyncio.create_subprocess_exec(
                    "podman",
                    "ps",
                    "-q",
                    "--filter",
                    f"id={container_id}",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )

                stdout, _ = await check_process.communicate()

                if not stdout.decode().strip():
                    logger.warning(f"Container {container_name} stopped unexpectedly")
                    if container_name in self.active_containers:
                        self.active_containers[container_name]["status"] = "stopped"
                    break

            except Exception as e:
                logger.error(f"Error monitoring container {container_name}: {e}")
                break

    @with_error_recovery(context="list_running_containers", default_return=[])
    def list_running_containers(self) -> list[dict]:
        """
        List all currently running containers.
        
        Returns:
            List of dictionaries with container information
        """
        # Use podman ps to get running containers
        result = subprocess.run(
            ["podman", "ps", "--format", "json"],
            capture_output=True,
            text=True,
            check=True
        )
        
        containers = json.loads(result.stdout) if result.stdout.strip() else []
        
        # Format containers to match expected structure
        formatted_containers = []
        for container in containers:
            # Handle null labels from podman (returns null instead of empty dict)
            labels = container.get('Labels') or {}

            formatted_containers.append({
                'name': container.get('Names', [''])[0] if container.get('Names') else '',
                'id': container.get('Id', ''),
                'labels': labels,  # Ensure labels is always a dict, never None
                'ports': container.get('Ports', []),
                'status': container.get('State', 'unknown')
            })
        
        logger.debug(f"Found {len(formatted_containers)} running containers")
        return formatted_containers

    @with_timeout(timeout_seconds=10)
    @with_retry(max_attempts=2, delay=1)
    async def is_container_running(self, container_id_or_name: str) -> bool:
        """
        Check if a container is currently running.
        
        Args:
            container_id_or_name: Container ID or name to check
            
        Returns:
            True if container is running, False otherwise
        """
        check_process = await asyncio.create_subprocess_exec(
            "podman",
            "ps",
            "-q",
            "--filter",
            f"id={container_id_or_name}",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        
        stdout, _ = await check_process.communicate()
        is_running = bool(stdout.decode().strip())
        
        logger.debug(f"Container {container_id_or_name} running status: {is_running}")
        return is_running

    @with_error_recovery(context="cleanup_all_containers", default_return=None)
    async def cleanup_all_containers(self):
        """Cleanup all active containers on shutdown."""
        logger.info("Cleaning up all active containers")

        cleanup_tasks = []
        for container_name, info in self.active_containers.items():
            if info["status"] == "running" and "container_id" in info:
                cleanup_tasks.append(self.stop_container(info["container_id"]))

        if cleanup_tasks:
            await asyncio.gather(*cleanup_tasks, return_exceptions=True)

        self.active_containers.clear()


    @with_timeout(timeout_seconds=60)
    @with_retry(max_attempts=2, delay=2)
    async def stop_container(self, container_id: str) -> dict:
        """
        Stop a running container.

        Args:
            container_id: ID of the container to stop

        Returns:
            dictionary with stop result
        """
        # Check if Podman is available
        podman_check = await self.check_podman_available()
        if not podman_check["available"]:
            return {
                "status": "error",
                "container_id": container_id,
                "error": f"Podman not available: {podman_check['error']}",
            }

        # Stop the container
        logger.info(f"Stopping container {container_id}")

        stop_process = await asyncio.create_subprocess_exec(
            "podman",
            "stop",
            container_id,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        stdout, stderr = await stop_process.communicate()

        if stop_process.returncode != 0:
            # Stop failed
            return {
                "status": "error",
                "container_id": container_id,
                "error": stderr.decode(),
                "output": stdout.decode(),
                "error_output": stderr.decode(),
            }

        # Remove from active containers if stopped successfully
        container_name = None
        for name, info in self.active_containers.items():
            if info.get("id") == container_id:
                container_name = name
                break
        
        if container_name:
            del self.active_containers[container_name]
            logger.info(f"Removed {container_name} from active containers")

        # Return success result
        return {
            "status": "success",
            "container_id": container_id,
            "output": stdout.decode(),
            "timestamp": datetime.now().isoformat(),
        }

    @with_timeout(timeout_seconds=30)
    @with_retry(max_attempts=3, delay=2)
    async def check_http_health(self, container_id: str, port: int = 8080) -> dict:
        """
        Check HTTP health of a web application container.
        
        Args:
            container_id: Container ID to check
            port: Port to check (default 8080)
            
        Returns:
            Dictionary with health check results
        """
        # Check if container is running first
        is_running = await self.is_container_running(container_id)
        if not is_running:
            return {
                "status": "unhealthy",
                "container_id": container_id,
                "port": port,
                "error": "Container not running"
            }
        
        # Perform HTTP health check
        health_ok = await check_container_health(port)
        
        return {
            "status": "healthy" if health_ok else "unhealthy",
            "container_id": container_id,
            "port": port,
            "http_accessible": health_ok,
            "timestamp": datetime.now().isoformat()
        }

    @with_error_recovery(context="get_container_files", default_return={})
    def get_container_files(self, container_dir: str) -> dict[str, str]:
        """
        Get all files from a container directory.

        Args:
            container_dir: Path to container directory

        Returns:
            Dictionary mapping file paths to content
        """
        files = {}
        container_path = Path(container_dir)

        if not container_path.exists():
            logger.warning(f"Container directory does not exist: {container_dir}")
            return files

        # Recursively read all files
        for file_path in container_path.rglob("*"):
            if file_path.is_file():
                try:
                    # Get relative path from container directory
                    relative_path = file_path.relative_to(container_path)

                    # Read file content
                    with open(file_path, "r", encoding="utf-8") as f:
                        content = f.read()

                    files[str(relative_path)] = content
                    logger.debug(f"Read container file: {relative_path}")

                except UnicodeDecodeError:
                    # Skip binary files
                    logger.debug(f"Skipping binary file: {file_path}")
                    continue
                except Exception as e:
                    logger.warning(f"Error reading file {file_path}: {e}")
                    continue

        return files

    @with_error_recovery(context="get_container_logs_detailed")
    async def get_container_logs_detailed(self, container_id: str) -> dict:
        """
        Get logs from a container with metadata.

        Args:
            container_id: ID of the container

        Returns:
            dictionary with log result
        """
        # Use unified log service
        logs = await self.container_log_service.get_logs(container_id)
        
        if logs:
            return {
                "status": "success",
                "container_id": container_id,
                "logs": logs,
                "timestamp": datetime.now().isoformat(),
            }
        else:
            return {
                "status": "error",
                "container_id": container_id,
                "error": "Failed to retrieve logs",
            }


    async def get_container_logs_with_filter(self, container_id: str, since: int = None) -> str:
        """
        Get container logs for analysis.

        Args:
            container_id: Container ID
            since: Number of seconds to get logs since (optional)

        Returns:
            Container logs as string
        """
        return await self.container_log_service.get_logs(container_id, since=since)

    @with_timeout(timeout_seconds=15)
    @with_error_recovery(context="get_container_info")
    async def get_container_info(self, container_name: str) -> dict:
        """
        Get detailed container information.

        Args:
            container_name: Name of the container

        Returns:
            Dictionary with container information including 'found' flag
        """
        process = await asyncio.create_subprocess_exec(
            "podman", "inspect", container_name, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )

        stdout, stderr = await process.communicate()

        if process.returncode == 0:
            try:
                container_info = json.loads(stdout.decode())
            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse container info JSON for {container_name}: {e}")
                return {"found": False, "error": f"JSON parse error: {e}"}
                
            if container_info:
                # Extract key information and add found flag
                info = container_info[0]
                result = {
                    "found": True,
                    "id": info.get("Id", ""),
                    "name": info.get("Name", container_name),
                    "state": info.get("State", {}),
                    "config": info.get("Config", {}),
                    "network_settings": info.get("NetworkSettings", {}),
                    "host_config": info.get("HostConfig", {}),
                    "raw_info": info
                }
                
                # Extract port mappings
                host_config = info.get("HostConfig", {})
                port_bindings = host_config.get("PortBindings", {})
                result["exposed_ports"] = port_bindings
                
                # Extract container state
                state = info.get("State", {})
                result["running"] = state.get("Running", False)
                result["status"] = state.get("Status", "unknown")
                
                logger.debug(f"Container {container_name} found - ID: {result['id'][:12]}, Running: {result['running']}")
                return result
            else:
                logger.warning(f"Container {container_name} inspect returned empty result")
                return {"found": False, "error": "Empty inspect result"}
        else:
            error_msg = stderr.decode().strip()
            logger.debug(f"Container {container_name} not found or not accessible: {error_msg}")
            return {"found": False, "error": error_msg}

    @with_timeout(timeout_seconds=15)
    @with_retry(max_attempts=2, delay=1)
    @with_error_recovery(context="get_container_status")
    async def get_container_status(self, container_name: str) -> dict:
        """
        Get the current status of a container by name.
        
        Args:
            container_name: Name of the container to check
            
        Returns:
            Dictionary with container status information
        """
        # First try to get container info by name
        container_info = await self.get_container_info(container_name)
        if container_info.get("found", False):
            container_id = container_info.get("id", "")
            if container_id:
                return await check_container_status(container_id)
        
        # If not found by name, return not found status
        return {"running": False, "status": "not_found"}

    async def get_container_logs(self, container_name_or_id: str, tail: int = None) -> str:
        """
        Get logs from a container by name or ID with optional tail limit.
        
        Args:
            container_name_or_id: Name or ID of the container
            tail: Number of recent lines to retrieve (optional)
            
        Returns:
            String containing the container logs
        """
        return await self.container_log_service.get_logs(container_name_or_id, tail=tail)
