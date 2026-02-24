import asyncio
import json
import logging
import shutil
import socket
from typing import Optional

import aiohttp

logger = logging.getLogger(__name__)


class PortAllocator:
    """
    Manages port allocation to avoid conflicts.
    """

    def __init__(self, port_range: str = "8080-8090"):
        """
        Initialize port allocator.

        Args:
            port_range: Port range in format "start-end" (e.g., "8080-8090")
                       or single port with Docker mapping (e.g., "8080:8080")
        """
        try:
            # Handle Docker port mapping format (8080:8080) - extract host port and create single port range
            if ":" in port_range:
                host_port = port_range.split(":")[0]
                start = end = int(host_port)
                logger.info(f"Port allocator initialized with single port {start} (from Docker format)")
            # Handle range format (8080-8090)
            elif "-" in port_range:
                start, end = map(int, port_range.split("-"))
                logger.info(f"Port allocator initialized with range {start}-{end}")
            # Handle single port number
            else:
                start = end = int(port_range)
                logger.info(f"Port allocator initialized with single port {start}")

            self.available_ports = set(range(start, end + 1))
            self.allocated_ports = set()

        except (ValueError, IndexError) as e:
            logger.error(f"Invalid port range format: {port_range}. Error: {e}")
            logger.info("Using default fallback port range 8080-8090")
            self.available_ports = set(range(8080, 8091))  # Default fallback
            self.allocated_ports = set()

    def allocate_port(self) -> Optional[int]:
        """
        Allocate an available port.

        Returns:
            Allocated port number or None if no ports available
        """
        # Check for ports actually in use
        available = self.available_ports - self.allocated_ports
        for port in sorted(available):
            if not self._is_port_in_use(port):
                self.allocated_ports.add(port)
                logger.debug(f"Allocated port {port}")
                return port

        logger.warning("No available ports in range")
        return None

    def release_port(self, port: int) -> None:
        """
        Release an allocated port.

        Args:
            port: Port number to release
        """
        self.allocated_ports.discard(port)
        logger.debug(f"Released port {port}")

    def _is_port_in_use(self, port: int) -> bool:
        """
        Check if a port is currently in use.

        Args:
            port: Port number to check

        Returns:
            True if port is in use
        """
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                result = sock.connect_ex(("localhost", port))
                return result == 0  # Port is in use if connection succeeds
        except Exception:
            return False


async def check_container_health(port: int, retries: int = 3) -> bool:
    """
    Perform health check appropriate for container type with retry logic.

    Args:
        port: Port to check
        container_type: Type of container (web-app, standalone, etc.)
        retries: Number of retry attempts

    Returns:
        True if container appears healthy
    """
    for attempt in range(retries):
        try:
            # First, check if port is in use
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex(("localhost", port))
            sock.close()

            if result != 0:
                # Port not bound, container might not be running
                if attempt < retries - 1:
                    await asyncio.sleep(2)  # Wait before retry
                    continue
                return False

            # All containers are now web applications - try HTTP endpoints
            timeout = aiohttp.ClientTimeout(total=5)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                # Try common health and vulnerability endpoints
                health_endpoints = [
                    f"http://localhost:{port}/actuator/health",  # Spring Boot
                    f"http://localhost:{port}/health",  # Generic health
                    f"http://localhost:{port}/",  # Root endpoint
                    f"http://localhost:{port}/api/vulnerable",  # Vulnerability endpoints
                    f"http://localhost:{port}/api/test",  # Test endpoints
                ]

                for endpoint in health_endpoints:
                    try:
                        async with session.get(endpoint) as response:
                            if response.status < 500:  # any non-server-error response
                                logger.debug(f"HTTP health check passed for {endpoint} (status: {response.status})")
                                return True
                    except Exception as e:
                        logger.debug(f"HTTP endpoint {endpoint} not accessible: {e}")
                        continue

            # If no HTTP endpoints respond, container is not healthy
            logger.warning(f"No HTTP endpoints responding on port {port}")
            return False

        except Exception as e:
            logger.debug(f"Health check error for port {port} (attempt {attempt + 1}/{retries}): {e}")
            if attempt < retries - 1:
                await asyncio.sleep(2)  # Wait before retry
            continue

    return False


def check_disk_space(path: str) -> int:
    """
    Check available disk space at path.

    Args:
        path: Path to check disk space for

    Returns:
        Free disk space in bytes, or 0 if unable to determine
    """
    try:
        _, _, free = shutil.disk_usage(path)
        return free
    except Exception:
        return 0


async def get_image_size(container_name: str) -> int:
    """
    Get container image size via podman inspect.

    Args:
        container_name: Name of the container image

    Returns:
        Image size in bytes, or 0 if unable to determine
    """
    try:
        process = await asyncio.create_subprocess_exec(
            "podman",
            "image",
            "inspect",
            container_name,
            "--format",
            "{{.Size}}",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await process.communicate()
        return int(stdout.decode().strip()) if process.returncode == 0 else 0
    except Exception:
        return 0


async def cleanup_failed_build(container_name: str) -> None:
    """
    Remove partial container images after failed builds.

    Args:
        container_name: Name of the container image to remove
    """
    try:
        await asyncio.create_subprocess_exec(
            "podman",
            "rmi",
            "-f",
            container_name,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
    except Exception:
        pass


async def check_container_status(container_id: str) -> dict:
    """
    Check container status via podman ps.

    Args:
        container_id: Container ID to check

    Returns:
        Dictionary with container status information
    """
    try:
        process = await asyncio.create_subprocess_exec(
            "podman",
            "ps",
            "--format",
            "json",
            "--filter",
            f"id={container_id}",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        stdout, _ = await process.communicate()

        if process.returncode == 0:
            containers = json.loads(stdout.decode()) if stdout.decode().strip() else []
            if containers:
                container = containers[0]
                return {
                    "running": True,
                    "status": container.get("State", "unknown"),
                    "created": container.get("Created", ""),
                    "names": container.get("Names", []),
                }

        return {"running": False, "status": "not_found"}

    except Exception as e:
        logger.error(f"Error checking container status: {e}")
        return {"running": False, "status": "error", "error": str(e)}
