import json
import logging
from datetime import datetime
from pathlib import Path
import re

import aiofiles

from agents.blueprint_management_agent import BlueprintManagementAgent
from agents.deployment_agent import DeploymentAgent
from agents.exploit_validation_agent import ExploitValidationAgent
from services.blueprint_management.blueprint_repository_service import BlueprintRepositoryService
from services.deployment.container_service import ContainerService
from services.monitoring.container_log_service import ContainerLogService
from services.system.llm_service import LLMService
from services.system.reliability_service import reliability_manager
from shared.constants import DEFAULT_DATA_DIR
from templates.manager import TemplateManager
from utils.container.container_utils import PortAllocator
from utils.core.common import cleanup_containers
from utils.error_handling.decorators import with_error_recovery
from utils.support.osv_client import extract_vulnerable_version, get_vulnerabilities_for_selected_packages

logger = logging.getLogger(__name__)


class CVEEmulatorSystem:
    """
    System integration service that coordinates agents and services.
    Provides a unified interface for the entire FORGE system.
    """

    def __init__(self, config_path: Path = None, container_dir: Path = None, use_llm: bool = True):
        """Initialize with proper dependency order."""
        # Initialize core services (no dependencies)
        self.llm_service = LLMService(config_path) if use_llm else None
        self.blueprint_service = BlueprintRepositoryService()
        self.container_service = ContainerService(container_dir)
        self.container_log_service = ContainerLogService()

        # Initialize logger and data directory for persistent storage
        self.logger = logger

        self.data_dir = DEFAULT_DATA_DIR
        
        # Ensure data directory structure exists
        self._initialize_data_directories()

        # Initialize exploit validation agent with dependencies
        self.exploit_validation_service = ExploitValidationAgent(
            system_integration=self, 
            blueprint_service=self.blueprint_service,
            container_service=self.container_service,
            llm_service=self.llm_service
        )

        # Initialize template manager with LLM service
        self.template_manager = TemplateManager(llm_service=self.llm_service)

        # Initialize agents with all dependencies
        self.blueprint_agent = BlueprintManagementAgent(
            blueprint_service=self.blueprint_service,
            llm_service=self.llm_service,
            template_manager=self.template_manager,
        )

        self.deployment_agent = DeploymentAgent(
            blueprint_service=self.blueprint_service,
            container_service=self.container_service,
            llm_service=self.llm_service,
            template_manager=self.template_manager,
            use_llm=use_llm,
        )

    @staticmethod
    def _prepare_vuln_data(vuln: dict, package_name: str) -> dict:
        """Extract standard vulnerability data dict from an OSV record."""
        return {
            "cve_id": next(
                (alias for alias in vuln.get("aliases", []) if alias.startswith("CVE-")),
                "",
            ),
            "package_name": package_name,
            "package_version": extract_vulnerable_version(vuln, package_name),
            "description": vuln.get("summary", ""),
            "summary": vuln.get("summary", ""),
            "references": vuln.get("references", []),
            "osv_data": vuln,
        }

    async def _fetch_vulnerabilities(
        self, package_name: str, limit: int = 1, cve_id: str | None = None
    ) -> list[dict]:
        """Fetch vulnerabilities for a package from OSV, returning empty list if none found."""
        if cve_id:
            vulnerabilities = await get_vulnerabilities_for_selected_packages(
                [package_name], vuln_limit=1, cve_ids={package_name: cve_id}
            )
        else:
            vulnerabilities = await get_vulnerabilities_for_selected_packages([package_name], limit)

        if not vulnerabilities or package_name not in vulnerabilities:
            logger.warning(f"No vulnerabilities found for package {package_name}")
            return []
        return vulnerabilities[package_name]

    @with_error_recovery(default_return={})
    async def process_package_with_guidance(
        self, package_name: str, limit: int = 1, cve_id: str | None = None
    ) -> dict[str, list]:
        """
        Process a package with guidance from similar blueprints.

        Args:
            package_name: Package to process
            limit: Maximum number of vulnerabilities to process
            cve_id: Optional specific CVE ID to process

        Returns:
            dictionary mapping package name to list of blueprints
        """
        logger.info(f"Processing package with guidance: {package_name}")
        vuln_list = await self._fetch_vulnerabilities(package_name, limit, cve_id)

        blueprints = []
        for vuln in vuln_list:
            try:
                vuln_data = self._prepare_vuln_data(vuln, package_name)
                blueprint = await self.blueprint_agent.create_blueprint_with_guidance(vuln_data)
                blueprints.append(blueprint)
            except Exception as e:
                logger.error(f"Error creating blueprint for {package_name}: {e}")

        return {package_name: blueprints}

    @with_error_recovery(default_return={})
    async def process_packages(
        self,
        packages: list[str],
        limit: int = 2,
        cve_ids: dict[str, str] | None = None,
        additional_dependencies: list[dict[str, str]] | None = None,
    ) -> dict[str, list | str]:
        """
        Process packages to generate blueprints.

        Args:
            packages: list of packages to process
            limit: Maximum number of vulnerabilities per package
            cve_ids: Optional dictionary mapping package names to specific CVE IDs
            additional_dependencies: Optional list of additional dependencies

        Returns:
            dictionary mapping package names to lists of blueprints
        """
        logger.info(f"Processing packages: {packages}")
        vulnerabilities = await get_vulnerabilities_for_selected_packages(packages, limit, cve_ids=cve_ids)

        results = {}
        for package_name, vuln_list in vulnerabilities.items():
            results[package_name] = []
            for vuln in vuln_list:
                try:
                    vuln_data = self._prepare_vuln_data(vuln, package_name)
                    blueprint = await self.blueprint_agent.create_blueprint(vuln_data, additional_dependencies)
                    results[package_name].append(blueprint)
                except Exception as e:
                    logger.error(f"Error creating blueprint for {package_name}: {e}")

        return results

    @with_error_recovery(default_return={})
    async def process_packages_guided(
        self,
        packages: list[str],
        limit: int = 2,
        cve_ids: dict[str, str] | None = None,
        additional_dependencies: list[dict[str, str]] | None = None,
        framework_type: str | None = None,
    ) -> dict[str, list]:
        """
        Process packages using guided process with enhanced features.

        Args:
            packages: List of packages to process
            limit: Maximum number of vulnerabilities per package
            cve_ids: Optional dictionary mapping package names to specific CVE IDs
            additional_dependencies: Additional Maven dependencies
            framework_type: Force specific framework type

        Returns:
            Dictionary mapping package names to lists of blueprints
        """
        logger.info(f"Processing packages with guided process: {packages}")

        results = {}
        for package_name in packages:
            cve_id = cve_ids.get(package_name) if cve_ids else None

            # Pass additional_dependencies and CVE ID to the guided process
            package_result = await self.process_package_with_enhanced_guidance(
                package_name, limit, cve_id, additional_dependencies
            )
            results.update(package_result)

        if framework_type:
            self._apply_framework_type_to_blueprints(results, framework_type)

        return results

    @with_error_recovery(default_return={})
    async def process_package_with_enhanced_guidance(
        self,
        package_name: str,
        limit: int = 1,
        cve_id: str | None = None,
        additional_dependencies: list[dict[str, str]] | None = None,
    ) -> dict[str, list]:
        """
        Process a package with guidance from similar blueprints and dependencies.

        Args:
            package_name: Package to process
            limit: Maximum number of vulnerabilities to process
            cve_id: Optional specific CVE ID to process
            additional_dependencies: Additional Maven dependencies

        Returns:
            dictionary mapping package name to list of blueprints
        """
        logger.info(f"Processing package with enhanced guidance: {package_name}")
        vuln_list = await self._fetch_vulnerabilities(package_name, limit, cve_id)

        blueprints = []
        for vuln in vuln_list:
            try:
                vuln_data = self._prepare_vuln_data(vuln, package_name)
                blueprint = await self.blueprint_agent.create_blueprint_with_guidance(
                    vuln_data, additional_dependencies
                )
                blueprints.append(blueprint)
            except Exception as e:
                logger.error(f"Error creating blueprint for {package_name}: {e}")

        return {package_name: blueprints}

    def _apply_framework_type_to_blueprints(self, results: dict[str, list], framework_type: str) -> None:
        """Apply framework type to all blueprints in results."""
        for package_blueprints in results.values():
            for blueprint in package_blueprints:
                if hasattr(blueprint, "metadata"):
                    blueprint.metadata.setdefault("framework_info", {})
                    blueprint.metadata["framework_info"]["forced_type"] = framework_type

    async def get_system_health(self) -> dict[str, any]:
        """Get comprehensive system health status."""
        health_status = reliability_manager.get_system_health()

        # Add service-specific health checks
        health_status["services"] = {
            "llm_service": await self._check_llm_service(),
            "blueprint_service": await self._check_blueprint_service(),
            "container_service": await self._check_container_service(),
        }

        return health_status

    @with_error_recovery(default_return={"status": "failed", "error": "Health check failed"})
    async def _check_llm_service(self) -> dict[str, any]:
        """Check LLM service health."""
        # Simple health check prompt
        test_response = await self.llm_service.generate("Health check test", retries=1)
        return {
            "status": "healthy" if test_response else "degraded",
            "response_length": len(test_response) if test_response else 0,
        }

    @with_error_recovery(default_return={"status": "failed", "error": "Health check failed"})
    def _check_blueprint_service(self) -> dict[str, any]:
        """Check blueprint service health."""
        blueprints = self.blueprint_service.list_blueprints()
        return {"status": "healthy", "blueprint_count": len(blueprints)}

    @with_error_recovery(default_return={"status": "failed", "error": "Health check failed"})
    async def _check_container_service(self) -> dict[str, any]:
        """Check container service health."""
        podman_check = await self.container_service.check_podman_available()
        return {
            "status": "healthy" if podman_check["available"] else "failed",
            "podman_version": podman_check.get("version", "unknown"),
        }

    @with_error_recovery(default_return={"status": "error", "error": "Build failed"})
    async def build_container(self, blueprint_id: str) -> dict:
        """
        Build a container for a blueprint.

        Args:
            blueprint_id: ID of the blueprint

        Returns:
            dictionary with build result
        """
        logger.info(f"CONTAINER BUILD REQUEST: blueprint_id={blueprint_id}")
            
        # Check if container already exists before building
        running_containers = self.get_running_containers()
        logger.info(f"PRE-BUILD CHECK: Found {len(running_containers)} running containers")
        
        for container_name, info in running_containers.items():
            container_blueprint_id = info.get("blueprint_id")
            logger.info(f"- Container {container_name}: blueprint_id={container_blueprint_id}")
            if container_blueprint_id == blueprint_id:
                logger.warning(f"DUPLICATE BUILD ATTEMPT: Container for blueprint {blueprint_id} already exists: {container_name}")
                # Return existing container with complete structure expected by validation services
                container_id = info.get("container_id", info.get("id", ""))
                return {
                    "status": "success",
                    "container_name": container_name,
                    "container_id": container_id,
                    "blueprint_id": blueprint_id,
                    "duplicate_prevention": True,
                    "existing_container": info,
                    "output": f"Reusing existing container {container_name}",
                    "command": f"podman logs -f {container_id}",
                    "stop_command": f"podman stop {container_id}",
                    "timestamp": datetime.now().isoformat(),
                    "ports": info.get("ports", [])
                }
        
        logger.info(f"BUILD AUTHORIZED: No existing container found for blueprint {blueprint_id}, proceeding with build")

        # Deploy the blueprint
        result = await self.deployment_agent.deploy_blueprint(blueprint_id)
        
        if result.get("status") == "success":
            container_name = result.get("container_name")
            logger.info(f"CONTAINER BUILD COMPLETED: {container_name} for blueprint {blueprint_id}")
            logger.info(f"Build result: {result}")
        else:
            logger.error(f"CONTAINER BUILD FAILED: blueprint {blueprint_id}, error: {result.get('error')}")

        return result

    @with_error_recovery(default_return=[{"status": "error", "error": "Build failed"}])
    async def build_containers_for_package(self, package_name: str) -> list[dict]:
        """
        Build containers for all blueprints matching a package name.

        Args:
            package_name: Package name filter

        Returns:
            list of build results
        """
        logger.info(f"Building containers for package {package_name}")

        # Deploy blueprints for the package
        results = await self.deployment_agent.deploy_multiple_blueprints(package_name)

        return results

    def list_blueprints(self, package_name: str | None = None) -> list[dict]:
        """
        list blueprints, optionally filtered by package name.

        Args:
            package_name: Optional package name filter

        Returns:
            list of blueprint metadata dictionaries
        """
        return self.blueprint_service.list_blueprints(package_name)

    async def get_blueprint_details(self, blueprint_id: str) -> dict:
        """
        Get detailed information about a blueprint.

        Args:
            blueprint_id: ID of the blueprint

        Returns:
            dictionary with blueprint details
        """
        logger.info("⌛Getting blueprint details")
        return await self.blueprint_service.get_blueprint_details(blueprint_id)

    async def debug_blueprint_system(self, blueprint_id: str | None = None) -> dict:
        """
        Provide diagnostic information about the blueprint system.

        Args:
            blueprint_id: Optional blueprint ID to check specifically

        Returns:
            dictionary with diagnostic information
        """
        diagnostics = {
            "blueprint_storage_dir": str(self.blueprint_service.storage_dir),
            "blueprint_count": len(self.blueprint_service.blueprint_index),
            "available_blueprints": self.blueprint_service.list_all_available_blueprints(),
        }

        if blueprint_id:
            try:
                file_path = Path(self.blueprint_service.storage_dir) / f"{blueprint_id}.json"
                diagnostics["blueprint_check"] = {
                    "id": blueprint_id,
                    "file_exists": file_path.exists(),
                    "file_path": str(file_path),
                    "in_index": blueprint_id in self.blueprint_service.blueprint_index,
                }

                if file_path.exists():
                    async with aiofiles.open(file_path, "r", encoding="utf-8") as f:
                        blueprint_data = json.load(f)
                    diagnostics["blueprint_check"]["content_preview"] = {
                        "name": blueprint_data.get("name", "Unknown"),
                        "package_name": blueprint_data.get("package_name", "Unknown"),
                        "cve_ids": blueprint_data.get("cve_ids", []),
                    }
            except Exception as e:
                diagnostics["blueprint_check_error"] = str(e)

        return diagnostics

    async def regenerate_code(self, blueprint_id: str) -> dict:
        """
        Regenerate code for a blueprint.

        Args:
            blueprint_id: ID of the blueprint

        Returns:
            dictionary with regeneration result
        """
        return await self.blueprint_agent.regenerate_code(blueprint_id)

    @with_error_recovery(default_return={"status": "error", "error": "Run failed"})
    async def run_container(self, container_name: str, ports: list[str], blueprint_id: str = None) -> dict[str, any]:
        """
        Container running with better error handling.

        Args:
            container_name: Name of the container
            ports: list of port mappings
            blueprint_id: Optional blueprint ID for container labeling

        Returns:
            dictionary with run result
        """
        result = await self.deployment_agent.run_container(container_name, ports, blueprint_id)

        if result["status"] == "success":
            logger.info(f"Container {container_name} started successfully on ports {ports}")

            # Add convenience information
            if ports:
                host_port = ports[0].split(":")[0]
                result["access_url"] = f"http://localhost:{host_port}"
                result["port"] = int(host_port)  # Add port for exploit executor

        return result

    @with_error_recovery(default_return={})
    async def process_packages_with_dependencies(
        self,
        packages: list[str],
        limit: int = 2,
        cve_ids: dict[str, str] | None = None,
        additional_dependencies: list[dict[str, str]] | None = None,
    ) -> dict[str, list]:
        """
        Process packages with additional dependency support.

        Args:
            packages: list of packages to process
            limit: Maximum number of vulnerabilities per package
            cve_ids: Optional dictionary mapping package names to specific CVE IDs
            additional_dependencies: Additional Maven dependencies

        Returns:
            dictionary mapping package names to lists of blueprints
        """
        logger.info(f"Processing packages with {len(additional_dependencies or [])} additional dependencies")
        vulnerabilities = await get_vulnerabilities_for_selected_packages(packages, limit, cve_ids=cve_ids)

        results = {}
        for package_name, vuln_list in vulnerabilities.items():
            results[package_name] = []
            for vuln in vuln_list:
                try:
                    vuln_data = self._prepare_vuln_data(vuln, package_name)
                    blueprint = await self.blueprint_agent.create_blueprint(vuln_data, additional_dependencies)
                    results[package_name].append(blueprint)
                except Exception as e:
                    logger.error(f"Error creating blueprint for {package_name}: {e}")

        return results

    @staticmethod
    def _extract_blueprint_id(container_labels: dict, container_name: str) -> str:
        """Extract blueprint_id from container labels or name pattern."""
        for key in ('blueprint_id', 'gyros.blueprint_id', 'gyros_blueprint_id'):
            if container_labels.get(key):
                return container_labels[key]
        # Try to extract from container name pattern
        match = re.search(r'vulnapp-(.+)-[a-f0-9]{8}$', container_name)
        return match.group(1).replace('-', ':').replace('-', '.') if match else ''

    @with_error_recovery(default_return={}, log_level="warning", context="get_running_containers")
    def get_running_containers(self) -> dict[str, dict]:
        """
        Get information about currently running containers.
        Merges active tracking (complete info) with podman discovery (live state).

        Returns:
            Dictionary mapping container names to container information
        """
        running_containers_list = self.container_service.list_running_containers()
        active_containers = getattr(self.container_service, 'active_containers', {})

        result = {}

        # Active tracking has more complete info (blueprint_id, ports, etc.)
        for name, info in active_containers.items():
            result[name] = {
                'id': info.get('container_id', ''),
                'name': name,
                'container_id': info.get('container_id', ''),
                'image': info.get('image', ''),
                'status': info.get('status', 'running'),
                'ports': info.get('ports', []),
                'exposed_ports': info.get('exposed_ports', {}),
                'network_settings': info.get('network_settings', {}),
                'blueprint_id': info.get('blueprint_id', ''),
                'running': info.get('running', True),
                'container_status': info.get('container_status', 'running'),
                'labels': {},
                'source': 'active_tracking'
            }

        # Add discovered containers not already tracked
        for container in running_containers_list:
            if container is None:
                continue
            name = container.get('name', '')
            if name and name not in result:
                labels = container.get('labels', {})
                result[name] = {
                    'id': container.get('id', ''),
                    'name': name,
                    'container_id': container.get('id', ''),
                    'image': container.get('image', ''),
                    'status': container.get('status', ''),
                    'ports': container.get('ports', []),
                    'created': container.get('created', ''),
                    'blueprint_id': self._extract_blueprint_id(labels, name),
                    'labels': labels,
                    'source': 'discovery'
                }

        logger.info(f"Container mapping: {len(result)} total ({len(active_containers)} active, {len(running_containers_list)} discovered)")
        return result

    @with_error_recovery(default_return={"status": "error", "error": "Stop failed"})
    async def stop_all_containers(self) -> dict[str, any]:
        """
        Stop all running containers managed by the system.

        Returns:
            dictionary with cleanup results
        """
        # Import here to avoid circular dependency
        from shared.container_state import container_state_manager
        running_containers = container_state_manager.get_running_containers()

        # Pass the container list explicitly
        await cleanup_containers(running_containers)
        return {"status": "success", "message": "All containers stopped"}

    async def stop_container(self, container_id: str) -> dict:
        """
        Stop a container.

        Args:
            container_id: ID of the container

        Returns:
            dictionary with stop result
        """
        return await self.deployment_agent.stop_container(container_id)

    async def create_blueprint_from_template(
        self, template_name: str, cve_id: str, package_name: str, package_version: str
    ) -> dict:
        """
        Create a blueprint from a template.

        Args:
            template_name: Name of the template
            cve_id: CVE ID
            package_name: Package name
            package_version: Package version

        Returns:
            dictionary with creation result
        """
        return await self.blueprint_agent.create_blueprint_from_template(
            template_name, cve_id, package_name, package_version
        )

    @with_error_recovery(default_return={"errors": ["Workflow failed"]})
    async def run_complete_workflow(
        self,
        packages: list[str],
        limit: int = 2,
        cve_ids: dict[str, str] | list = None,
        auto_run: bool = False,
        port_range: str = "8080-8090",
        monitor: bool = False,
        background: bool = False,
    ) -> dict[str, any]:
        """
        Execute complete workflow from blueprint creation to container execution.

        Args:
            packages: List of packages to process
            limit: Limit per package
            cve_ids: Optional dictionary mapping package names to specific CVE IDs
            auto_run: Whether to automatically run containers
            port_range: Port range for container allocation
            monitor: Whether to monitor running containers
            background: Whether to run containers in background

        Returns:
            Dictionary with workflow results
        """
        workflow_results = {
            "blueprints_created": 0,
            "containers_built": 0,
            "containers_running": 0,
            "port_allocations": {},
            "errors": [],
            "monitoring_tasks": [],
        }

        # Process packages with CVE IDs
        results = await self.process_packages(packages, limit, cve_ids=cve_ids)

        all_blueprints = []
        for package, blueprints in results.items():
            workflow_results["blueprints_created"] += len(blueprints)
            all_blueprints.extend(blueprints)

        if not all_blueprints:
            return workflow_results

        # Build containers
        port_allocator = PortAllocator(port_range)
        container_results = []

        for bp in all_blueprints:
            result = await self.build_container(bp.blueprint_id)
            if result["status"] == "success":
                workflow_results["containers_built"] += 1
                container_results.append(result)
            else:
                workflow_results["errors"].append(f"Build failed for {bp.name}: {result.get('error')}")

        # Run containers if requested
        if auto_run and container_results:
            execution_results = await self._execute_containers_with_monitoring(
                container_results, port_allocator, monitor, background
            )
            workflow_results.update(execution_results)

        return workflow_results

    async def _execute_containers_with_monitoring(
        self, container_results: list[dict], port_allocator, monitor: bool, background: bool
    ) -> dict[str, any]:
        """Execute containers with monitoring setup and proper background handling."""
        from shared.container_state import container_state_manager
        running_containers = container_state_manager.get_running_containers()

        execution_results = {"containers_running": 0, "port_allocations": {}, "errors": [], "monitoring_tasks": []}

        for result in container_results:
            container_name = result["container_name"]
            allocated_port = port_allocator.allocate_port()

            if not allocated_port:
                execution_results["errors"].append(f"No available ports for {container_name}")
                continue

            ports = [f"{allocated_port}:8080"]
            run_result = await self.run_container(container_name, ports)

            if run_result["status"] == "success":
                execution_results["containers_running"] += 1
                execution_results["port_allocations"][container_name] = allocated_port

                container_info = {
                    "name": container_name,
                    "id": run_result["container_id"],
                    "port": allocated_port,
                    "stop_command": run_result["stop_command"],
                    "type": "standalone",  # Default
                }
                running_containers.append(container_info)

                # Handle background vs foreground execution properly
                if background:
                    logger.info(f"Container {container_name} started in background mode")
                    # For background mode, start monitoring but don't block
                    if monitor:
                        monitoring_task = await self.container_service.start_container_monitoring(container_info)
                        execution_results["monitoring_tasks"].append(monitoring_task)
                        logger.info(f"Background monitoring started for {container_name}")
                else:
                    # Foreground mode - setup monitoring as before
                    if monitor:
                        monitoring_task = await self.container_service.start_container_monitoring(container_info)
                        execution_results["monitoring_tasks"].append(monitoring_task)
                        logger.info(f"Foreground monitoring started for {container_name}")
            else:
                port_allocator.release_port(allocated_port)
                execution_results["errors"].append(f"Failed to start {container_name}")

        return execution_results

    async def validate_vulnerability_demo(self, blueprint_id: str) -> dict:
        """
        Validate a vulnerability demonstration for a specific blueprint.

        Args:
            blueprint_id: ID of the blueprint

        Returns:
            Dictionary with validation results
        """
        logger.info(f"VALIDATION REQUEST: blueprint_id={blueprint_id}")
        
        # Check if there's already a running container for this blueprint to avoid port conflicts
        running_containers = self.get_running_containers()
        logger.info(f"VALIDATION PRE-CHECK: Found {len(running_containers)} running containers")
        
        container_info = None
        for container_name, info in running_containers.items():
            container_blueprint_id = info.get("blueprint_id")
            logger.info(f"   - Container {container_name}: blueprint_id={container_blueprint_id}, status={info.get('status')}")
            
            if container_blueprint_id == blueprint_id:
                container_info = {
                    "container_name": container_name,
                    "blueprint_id": blueprint_id,
                    "container_id": info.get("container_id"),
                    "ports": info.get("ports", [])
                }
                logger.info(f"CONTAINER REUSE: Found existing container {container_name} for blueprint {blueprint_id}")
                logger.info(f"   Container details: {container_info}")
                break
        
        if container_info is None:
            logger.warning(f"NO CONTAINER FOUND: No running container found for blueprint {blueprint_id}")
            logger.warning("   This may trigger a new container build during validation")
        
        logger.info(f"STARTING VALIDATION: Calling exploit_validation_service for blueprint {blueprint_id}")
        result = await self.exploit_validation_service.validate_vulnerability_demo(blueprint_id, container_info)
        
        logger.info(f"VALIDATION COMPLETED: blueprint {blueprint_id}, success={result.success if hasattr(result, 'success') else 'unknown'}")
        return result

    async def test_exploit_payload(self, blueprint_id: str, payload_data: dict) -> dict:
        """
        Test an exploit payload against a blueprint.

        Args:
            blueprint_id: ID of the blueprint
            payload_data: Payload data to test

        Returns:
            Dictionary with test results
        """
        return await self.exploit_validation_service.test_exploit_payload(blueprint_id, payload_data)

    async def monitor_container_for_exploitation(
        self, container_id: str, monitoring_duration: int = 300, blueprint_id: str = None
    ) -> dict:
        """
        Monitor a container for signs of exploitation with persistent logging.

        Args:
            container_id: ID of the container to monitor
            monitoring_duration: Duration to monitor in seconds
            blueprint_id: Blueprint ID for persistent storage

        Returns:
            Dictionary with monitoring results
        """
        return await self.exploit_validation_service.monitor_container_for_exploitation(
            container_id, monitoring_duration, blueprint_id, save_persistent=True
        )

    @with_error_recovery(default_return=[], context="get_stored_validation_results")
    def get_stored_validation_results(self, blueprint_id: str = None) -> list[dict]:
        """
        Retrieve stored validation results from persistent storage.

        Args:
            blueprint_id: Optional blueprint ID to filter results

        Returns:
            List of validation result dictionaries
        """
        validation_results_dir = Path(self.data_dir) / "monitoring" / "validation_results"
        if not validation_results_dir.exists():
            return []

        results = []
        for json_file in validation_results_dir.glob("*.json"):
            if blueprint_id and not json_file.name.startswith(blueprint_id):
                continue
            try:
                with open(json_file, "r", encoding="utf-8") as f:
                    results.append(json.load(f))
            except Exception as e:
                logger.warning(f"Error reading validation file {json_file}: {e}")

        results.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
        return results

    @with_error_recovery(default_return=[])
    async def get_stored_container_logs(self, blueprint_id: str = None) -> list[dict]:
        """
        Retrieve stored container logs from persistent storage using unified service.

        Args:
            blueprint_id: Optional blueprint ID to filter logs

        Returns:
            List of log file information dictionaries
        """
        return await self.container_log_service.get_stored_logs(blueprint_id=blueprint_id)

    @with_error_recovery(default_return=[])
    def get_stored_exploit_reports(self, blueprint_id: str = None) -> list[dict]:
        """
        Retrieve stored exploit reports from persistent storage.

        Args:
            blueprint_id: Optional blueprint ID to filter reports

        Returns:
            List of report file information dictionaries
        """
        exploit_reports_dir = Path(self.data_dir) / "monitoring" / "exploit_reports"
        reports_info = []

        if not exploit_reports_dir.exists():
            return reports_info

        for report_file in exploit_reports_dir.glob("*.md"):
            if blueprint_id and not report_file.name.startswith(blueprint_id):
                continue

            try:
                stat_info = report_file.stat()
                reports_info.append(
                    {
                        "file_path": str(report_file),
                        "file_name": report_file.name,
                        "size_bytes": stat_info.st_size,
                        "modified_time": stat_info.st_mtime,
                        "blueprint_id_prefix": report_file.name.split("_")[0] if "_" in report_file.name else None,
                    }
                )
            except Exception as e:
                self.logger.warning(f"Error reading report file {report_file}: {e}")

        # Sort by modification time (newest first)
        reports_info.sort(key=lambda x: x.get("modified_time", 0), reverse=True)
        return reports_info

    async def validate_exploit(self, blueprint_id: str, container_info: dict = None):
        """
        Validate exploit for a given blueprint.

        Args:
            blueprint_id: ID of the blueprint to validate
            container_info: Optional pre-built container info to reuse

        Returns:
            ExploitTestResult with validation details
        """
        return await self.exploit_validation_service.validate_vulnerability_demo(blueprint_id, container_info)

    @with_error_recovery()
    def _initialize_data_directories(self):
        """Initialize required data directory structure."""
        # Core data directories
        directories_to_create = [
            self.data_dir,
            self.data_dir / "blueprints",
            self.data_dir / "containers", 
            self.data_dir / "monitoring",
            self.data_dir / "monitoring" / "validation_results",
            self.data_dir / "monitoring" / "container_logs",
            self.data_dir / "monitoring" / "exploit_reports",
            self.data_dir / "monitoring" / "ioc_collection",
            self.data_dir / "monitoring" / "ioc_collection" / "network",
            self.data_dir / "monitoring" / "ioc_collection" / "filesystem", 
            self.data_dir / "monitoring" / "ioc_collection" / "process",
            self.data_dir / "monitoring" / "ioc_collection" / "application",
            self.data_dir / "monitoring" / "ioc_collection" / "timing",
            self.data_dir / "monitoring" / "ioc_collection" / "behavioral",
            self.data_dir / "poc_cache",
            self.data_dir / "exploit_scripts",
        ]
        
        for directory in directories_to_create:
            directory.mkdir(parents=True, exist_ok=True)
            
        logger.info(f"Data directory structure initialized at {self.data_dir}")
        
        # Create .gitkeep files to preserve empty directories in git
        for directory in directories_to_create[1:]:  # Skip root data dir
            gitkeep_file = directory / ".gitkeep"
            if not gitkeep_file.exists():
                gitkeep_file.touch()
